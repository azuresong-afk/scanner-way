"""Загрузка справочника NVD (CVE) в reference_nvd_cve / reference_nvd_cpe_match.

Источники (формат один и тот же — CVE JSON 2.0):
  * NVD API 2.0 ``/rest/json/cves/2.0`` (постранично, ключ в ``NVD_API_KEY``,
    инкрементально по ``lastModStartDate``/``lastModEndDate``);
  * офлайн-фиды ``nvdcve-2.0-<год>.json[.gz]`` — для закрытых контуров без
    доступа в интернет.

NVD — внешний сервис, а не цель сканирования: allowlist к нему не применяется,
но лимиты NVD соблюдаются (5 запросов / 30 с без ключа, 50 / 30 с с ключом),
а каждый запрос пишется в журнал аудита.
"""
from __future__ import annotations

import gzip
import json
import time
from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

from scanner.core.audit import AuditSink
from scanner.feeds.cpe import parse_cpe

if TYPE_CHECKING:
    import httpx

    from scanner.feeds.store import ReferenceStore

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
PAGE_SIZE = 2000  # максимум, который разрешает API 2.0


@dataclass(slots=True)
class CpeMatch:
    """Критерий уязвимой конфигурации из NVD (cpeMatch с vulnerable=true)."""
    cve_id: str
    criteria: str
    vendor: str
    product: str
    version: str = "*"
    update: str = "*"
    version_start_incl: str | None = None
    version_start_excl: str | None = None
    version_end_incl: str | None = None
    version_end_excl: str | None = None


@dataclass(slots=True)
class NvdRecord:
    cve_id: str
    cvss_v3: float | None = None
    cvss_vector: str | None = None
    severity: str | None = None          # baseSeverity из NVD (CRITICAL/HIGH/…)
    summary: str | None = None
    refs: list[str] = field(default_factory=list)
    cpe: list[str] = field(default_factory=list)          # критерии (строки CPE 2.3)
    cpe_matches: list[CpeMatch] = field(default_factory=list)
    updated_at: datetime | None = None


def _parse_dt(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(value)
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=UTC)  # NVD отдаёт время в UTC


def _pick_cvss(metrics: dict[str, Any]) -> tuple[float | None, str | None, str | None]:
    """CVSS: предпочитаем v3.1 > v3.0 > v4.0 > v2, и Primary-оценку (NVD) над вторичной."""
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV40", "cvssMetricV2"):
        items = metrics.get(key) or []
        if not items:
            continue
        items = sorted(items, key=lambda m: m.get("type") != "Primary")
        data = items[0].get("cvssData", {})
        severity = data.get("baseSeverity") or items[0].get("baseSeverity")
        return data.get("baseScore"), data.get("vectorString"), severity
    return None, None, None


def _iter_cpe_matches(cve_id: str, configurations: list[dict]) -> Iterator[CpeMatch]:
    """Все уязвимые cpeMatch из configurations[].nodes[] (AND/OR упрощаем до OR:
    уязвимым считается сам продукт с vulnerable=true, платформа — нет)."""
    stack: list[dict] = []
    for conf in configurations or []:
        stack.extend(conf.get("nodes") or [])
    while stack:
        node = stack.pop()
        stack.extend(node.get("children") or [])
        for m in node.get("cpeMatch") or []:
            if not m.get("vulnerable", False):
                continue
            criteria = m.get("criteria") or m.get("cpe23Uri")
            cpe = parse_cpe(criteria)
            if cpe is None:
                continue
            yield CpeMatch(
                cve_id=cve_id, criteria=criteria, vendor=cpe.vendor,
                product=cpe.product, version=cpe.version, update=cpe.update,
                version_start_incl=m.get("versionStartIncluding"),
                version_start_excl=m.get("versionStartExcluding"),
                version_end_incl=m.get("versionEndIncluding"),
                version_end_excl=m.get("versionEndExcluding"),
            )


def parse_cve_item(item: dict[str, Any]) -> NvdRecord | None:
    """Разбирает элемент ``vulnerabilities[]`` (CVE JSON 2.0) в NvdRecord."""
    cve = item.get("cve", item)
    cve_id = (cve.get("id") or "").upper()
    if not cve_id.startswith("CVE-"):
        return None
    if cve.get("vulnStatus") == "Rejected":
        return None
    score, vector, severity = _pick_cvss(cve.get("metrics") or {})
    summary = next((d.get("value") for d in cve.get("descriptions") or []
                    if d.get("lang") == "en"), None)
    refs = [r["url"] for r in cve.get("references") or [] if r.get("url")]
    matches = list(_iter_cpe_matches(cve_id, cve.get("configurations") or []))
    return NvdRecord(
        cve_id=cve_id, cvss_v3=score, cvss_vector=vector,
        severity=severity.upper() if severity else None, summary=summary,
        refs=refs, cpe=sorted({m.criteria for m in matches}), cpe_matches=matches,
        updated_at=_parse_dt(cve.get("lastModified")),
    )


def parse_feed(data: dict[str, Any]) -> Iterator[NvdRecord]:
    for item in data.get("vulnerabilities") or []:
        rec = parse_cve_item(item)
        if rec:
            yield rec


class NvdFeed:
    def __init__(self, api_key: str = "", *, client: httpx.Client | None = None,
                 audit: AuditSink | None = None, base_url: str = NVD_API_URL,
                 sleep: Callable[[float], None] = time.sleep):
        self.api_key = api_key
        self.base_url = base_url
        self.audit = audit
        self._client = client
        self._sleep = sleep
        # Лимит NVD: 5 запросов за 30 с без ключа, 50 за 30 с с ключом.
        self.min_interval = 0.6 if api_key else 6.0
        self._last_request = 0.0

    # ---------- источники ----------

    def iter_files(self, paths: Iterable[str | Path]) -> Iterator[NvdRecord]:
        """Офлайн-фиды NVD 2.0 (``.json`` или ``.json.gz``)."""
        for path in paths:
            path = Path(path)
            opener = gzip.open if path.suffix == ".gz" else open
            with opener(path, "rt", encoding="utf-8") as fh:
                yield from parse_feed(json.load(fh))

    def iter_api(self, *, last_mod_start: datetime | None = None,
                 last_mod_end: datetime | None = None,
                 cve_id: str | None = None) -> Iterator[NvdRecord]:
        """Постраничная выгрузка из NVD API 2.0 (полная, по CVE или за период).

        NVD ограничивает период lastMod 120 днями — длинные периоды делит вызывающий.
        """
        import httpx

        client = self._client or httpx.Client(timeout=60)
        params: dict[str, Any] = {"resultsPerPage": PAGE_SIZE, "startIndex": 0}
        if cve_id:
            params["cveId"] = cve_id
        if last_mod_start and last_mod_end:
            params["lastModStartDate"] = last_mod_start.isoformat()
            params["lastModEndDate"] = last_mod_end.isoformat()
        headers = {"apiKey": self.api_key} if self.api_key else {}
        try:
            while True:
                data = self._get(client, params, headers)
                yield from parse_feed(data)
                total = int(data.get("totalResults", 0))
                got = int(data.get("resultsPerPage", 0))
                params["startIndex"] += got
                if got == 0 or params["startIndex"] >= total:
                    break
        finally:
            if self._client is None:
                client.close()

    def _get(self, client: httpx.Client, params: dict[str, Any],
             headers: dict[str, str]) -> dict[str, Any]:
        wait = self.min_interval - (time.monotonic() - self._last_request)
        if wait > 0:
            self._sleep(wait)
        self._last_request = time.monotonic()
        resp = client.get(self.base_url, params=params, headers=headers)
        if self.audit:
            self.audit.record(subject="scanner", action="feed_fetch", target="nvd",
                              result=str(resp.status_code),
                              details=f"startIndex={params.get('startIndex')}")
        resp.raise_for_status()
        return resp.json()

    # ---------- загрузка в справочник ----------

    def sync(self, store: ReferenceStore, *, records: Iterable[NvdRecord] | None = None,
             batch_size: int = 1000) -> int:
        """Upsert CVE в справочник. По умолчанию — полная выгрузка через API;
        можно передать ``records`` (например, ``iter_files(...)``)."""
        source = records if records is not None else self.iter_api()
        total, batch = 0, []
        for rec in source:
            batch.append(rec)
            if len(batch) >= batch_size:
                total += store.upsert_nvd(batch)
                batch = []
        if batch:
            total += store.upsert_nvd(batch)
        return total
