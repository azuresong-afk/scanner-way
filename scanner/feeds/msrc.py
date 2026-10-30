"""Обновления Microsoft (MSRC): какая KB закрывает какую CVE, с учётом замещения.

Источник — бюллетени MSRC в формате CVRF (API v3.0, по документу на месяц:
``/cvrf/v3.0/cvrf/2024-Jan``). Из каждой уязвимости берутся исправления типа
Vendor Fix: номер KB, продукт, KB, которую это обновление замещает
(``Supercedence``), и сборка ОС, начиная с которой уязвимость закрыта
(``FixedBuild``). Хранятся только продукты Windows — сопоставление идёт с ОС
хоста; ПО из реестра сопоставляется с БДУ/NVD обычным `VulnMatcher`.

Сопоставление с хостом (`assess`) — CVE продукта хоста считается закрытой, если:

1. установлена KB-исправление или любая KB, которая её замещает — напрямую или
   по цепочке (накопительное обновление декабря замещает ноябрьское, то —
   октябрьское…): в списке установленных обычно остаётся только последнее
   накопительное, и без замещения все старые CVE выглядели бы открытыми;
2. или сборка ОС хоста (``10.0.17763.<UBR>``) не ниже ``FixedBuild`` той же
   ветки — так закрываются CVE и при KB новее справочника.

Если данных MSRC по продукту хоста нет (справочник не загружен, продукт не
распознан) — сопоставление не выполняется, модуль пишет «нет данных MSRC», а
не «уязвимостей нет».

Загрузка — по расписанию (источник ``msrc`` в `feeds.sources`) или
`scanner feeds sync-msrc`; для закрытого контура — из файлов CVRF JSON
(`SCANNER_MSRC_FEED_PATH`: файл или каталог с ``*.json``).
"""
from __future__ import annotations

import json
import re
from collections.abc import Iterable, Iterator, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

from pydantic_settings import BaseSettings, SettingsConfigDict
from sqlalchemy import (
    BigInteger,
    Column,
    Integer,
    Numeric,
    Table,
    Text,
    UniqueConstraint,
    delete,
    func,
    select,
)
from sqlalchemy.engine import Engine

from scanner.feeds.store import StrArray, metadata

API_URL = "https://api.msrc.microsoft.com/cvrf/v3.0"
GUIDE_URL = "https://msrc.microsoft.com/update-guide/vulnerability/{cve}"
CATALOG_URL = "https://catalog.update.microsoft.com/v7/site/Search.aspx?q=KB{kb}"
VENDOR_FIX = 2              # CVRF: Remediation.Type = Vendor Fix
THREAT_SEVERITY = 3         # CVRF: Threat.Type = Severity

_MONTHS = {m: i for i, m in enumerate(
    ("jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec"),
    start=1)}
_RELEASE_RE = re.compile(r"^(\d{4})-([A-Za-z]{3})")
_KB_RE = re.compile(r"\d{6,8}")
_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")
_BUILD_RE = re.compile(r"^\d+\.\d+\.\d+\.\d+$")

msrc_fix = Table(
    "reference_msrc_fix", metadata,
    Column("id", BigInteger().with_variant(Integer, "sqlite"), primary_key=True),
    Column("release", Text, nullable=False),
    Column("cve_id", Text, nullable=False, index=True),
    Column("product_id", Text, nullable=False),
    Column("product", Text, nullable=False, index=True),
    Column("kb", Text, nullable=False),
    Column("supersedes", StrArray, nullable=False, default=list),
    Column("fixed_build", Text),
    Column("url", Text),
    Column("severity", Text),
    Column("cvss", Numeric(4, 1)),
    Column("title", Text),
    UniqueConstraint("release", "cve_id", "product_id", "kb"),
)


class MsrcError(RuntimeError):
    """Справочник MSRC недоступен или документ не разобран."""


@dataclass(frozen=True, slots=True)
class MsrcFix:
    """Одно исправление: KB закрывает CVE для продукта Windows."""
    release: str                    # 2024-Jan
    cve_id: str
    product_id: str
    product: str                    # Windows Server 2019 (Server Core installation)
    kb: str                         # только цифры: 5034127
    supersedes: tuple[str, ...] = ()
    fixed_build: str | None = None  # 10.0.17763.5329
    url: str | None = None
    severity: str | None = None     # Critical | Important | Moderate | Low
    cvss: float | None = None
    title: str | None = None


def release_key(release: str) -> tuple[int, int, str]:
    """2024-Jan -> (2024, 1, ''): сортировка бюллетеней по времени."""
    m = _RELEASE_RE.match(release or "")
    if not m:
        return (0, 0, release or "")
    return (int(m[1]), _MONTHS.get(m[2].lower(), 0), release[m.end():])


def _value(node: Any) -> str:
    if isinstance(node, dict):
        return str(node.get("Value") or "").strip()
    return str(node or "").strip()


def _products(tree: dict[str, Any]) -> dict[str, str]:
    """ProductTree -> {ProductID: название}, включая вложенные ветки."""
    out: dict[str, str] = {}

    def walk(node: Any) -> None:
        if isinstance(node, list):
            for x in node:
                walk(x)
        elif isinstance(node, dict):
            pid, name = node.get("ProductID"), node.get("Value")
            if isinstance(pid, str) and isinstance(name, str):
                out.setdefault(pid, name.strip())
            for key in ("FullProductName", "Branch", "Items"):
                if key in node:
                    walk(node[key])

    walk(tree or {})
    return out


def is_windows_product(name: str) -> bool:
    return name.lower().startswith("windows ")


def parse_cvrf(doc: dict[str, Any], release: str | None = None) -> list[MsrcFix]:
    """Документ CVRF (JSON) -> исправления для продуктов Windows."""
    if release is None:
        ident = (doc.get("DocumentTracking") or {}).get("Identification") or {}
        release = _value(ident.get("ID")) or "unknown"
    products = _products(doc.get("ProductTree") or {})
    out: dict[tuple[str, str, str], MsrcFix] = {}
    for vuln in doc.get("Vulnerability") or []:
        cve = str(vuln.get("CVE") or "").strip().upper()
        if not _CVE_RE.match(cve):
            continue
        title = _value(vuln.get("Title"))[:500] or None
        severity: dict[str, str] = {}
        for t in vuln.get("Threats") or []:
            if t.get("Type") == THREAT_SEVERITY:
                for pid in t.get("ProductID") or []:
                    severity[str(pid)] = _value(t.get("Description"))[:32]
        cvss: dict[str, float] = {}
        for s in vuln.get("CVSSScoreSets") or []:
            try:
                score = float(s.get("BaseScore"))
            except (TypeError, ValueError):
                continue
            for pid in s.get("ProductID") or []:
                cvss[str(pid)] = score
        for r in vuln.get("Remediations") or []:
            if r.get("Type") != VENDOR_FIX:
                continue
            kb_m = _KB_RE.fullmatch(_value(r.get("Description")))
            if not kb_m:
                continue                    # «Release Notes», «Security Update» без номера
            kb = kb_m.group(0)
            sup = tuple(dict.fromkeys(x for x in _KB_RE.findall(str(r.get("Supercedence")
                                                                     or "")) if x != kb))
            fixed = str(r.get("FixedBuild") or "").strip()
            url = str(r.get("URL") or "").strip() or None
            for pid in r.get("ProductID") or []:
                pid = str(pid)
                name = products.get(pid)
                if not name or not is_windows_product(name):
                    continue
                out[(cve, pid, kb)] = MsrcFix(
                    release=release, cve_id=cve, product_id=pid, product=name[:200], kb=kb,
                    supersedes=sup, fixed_build=fixed if _BUILD_RE.match(fixed) else None,
                    url=url if url and url.startswith("https://") else None,
                    severity=severity.get(pid) or None, cvss=cvss.get(pid), title=title)
    return list(out.values())


# ---------- хранилище ----------

class MsrcStore:
    """Таблица reference_msrc_fix (миграция 0014; SQLite в тестах — create_schema)."""

    def __init__(self, engine: Engine):
        self.engine = engine

    def create_schema(self) -> None:
        metadata.create_all(self.engine, tables=[msrc_fix])

    def replace_release(self, release: str, fixes: Iterable[MsrcFix]) -> int:
        """Заменяет исправления бюллетеня целиком: MSRC переиздаёт документы."""
        rows = [{"release": f.release, "cve_id": f.cve_id, "product_id": f.product_id,
                 "product": f.product, "kb": f.kb, "supersedes": list(f.supersedes),
                 "fixed_build": f.fixed_build, "url": f.url, "severity": f.severity,
                 "cvss": f.cvss, "title": f.title} for f in fixes]
        with self.engine.begin() as conn:
            conn.execute(delete(msrc_fix).where(msrc_fix.c.release == release))
            for i in range(0, len(rows), 1000):
                conn.execute(msrc_fix.insert(), rows[i:i + 1000])
        return len(rows)

    def count(self) -> int:
        with self.engine.connect() as conn:
            return int(conn.execute(select(func.count()).select_from(msrc_fix)).scalar())

    def products(self) -> set[str]:
        with self.engine.connect() as conn:
            return {r[0] for r in conn.execute(select(msrc_fix.c.product).distinct())}

    def fixes_for(self, product: str) -> list[MsrcFix]:
        with self.engine.connect() as conn:
            rows = conn.execute(select(msrc_fix).where(
                func.lower(msrc_fix.c.product) == product.lower()))
            return [MsrcFix(release=r.release, cve_id=r.cve_id, product_id=r.product_id,
                            product=r.product, kb=r.kb,
                            supersedes=tuple(r.supersedes or ()),
                            fixed_build=r.fixed_build, url=r.url, severity=r.severity,
                            cvss=float(r.cvss) if r.cvss is not None else None,
                            title=r.title) for r in rows]


class InMemoryMsrcStore:
    def __init__(self, fixes: Iterable[MsrcFix] = ()):
        self._fixes = list(fixes)

    def count(self) -> int:
        return len(self._fixes)

    def products(self) -> set[str]:
        return {f.product for f in self._fixes}

    def fixes_for(self, product: str) -> list[MsrcFix]:
        return [f for f in self._fixes if f.product.lower() == product.lower()]


# ---------- продукт хоста ----------

@dataclass(slots=True)
class WindowsOs:
    """ОС хоста по реестру (HKLM\\...\\Windows NT\\CurrentVersion)."""
    product_name: str | None = None      # «Windows Server 2019 Standard» (у 11 — «Windows 10 …»)
    edition: str | None = None           # ServerStandard, Professional…
    display_version: str | None = None   # 22H2 (ReleaseId у старых сборок)
    build: int | None = None             # CurrentBuildNumber
    ubr: int | None = None               # Update Build Revision
    installation_type: str | None = None  # Client | Server | Server Core
    arch: str | None = None              # AMD64 | x86 | ARM64

    @property
    def is_server(self) -> bool:
        return (self.installation_type or "").lower().startswith("server") or \
            "server" in (self.product_name or "").lower()

    @property
    def is_core(self) -> bool:
        return (self.installation_type or "").lower() == "server core"

    @property
    def version(self) -> str | None:
        """Версия в формате FixedBuild MSRC: 10.0.17763.5329, 6.3.9600.21620."""
        if self.build is None:
            return None
        major = "10.0" if self.build >= 10240 else _NT6.get(self.build)
        if major is None:
            return None
        return f"{major}.{self.build}" + (f".{self.ubr}" if self.ubr is not None else "")

    @property
    def label(self) -> str:
        name = self.product_name or "Windows"
        if self.build is not None and self.build >= 22000 and name.startswith("Windows 10"):
            name = "Windows 11" + name[len("Windows 10"):]   # ProductName у 11 не обновлён
        extra = [x for x in (self.display_version,) if x]
        if self.build is not None:
            extra.append(f"сборка {self.build}" + (f".{self.ubr}" if self.ubr is not None
                                                     else ""))
        return f"{name} ({', '.join(extra)})" if extra else name


_NT6 = {7601: "6.1", 9200: "6.2", 9600: "6.3"}
_SERVER_BY_BUILD = {7601: "Windows Server 2008 R2", 9200: "Windows Server 2012",
                    9600: "Windows Server 2012 R2", 14393: "Windows Server 2016",
                    17763: "Windows Server 2019", 20348: "Windows Server 2022",
                    25398: "Windows Server 2022, 23H2 Edition",
                    26100: "Windows Server 2025"}
_WIN10_BY_BUILD = {10240: None, 10586: "1511", 14393: "1607", 15063: "1703",
                   16299: "1709", 17134: "1803", 17763: "1809", 18362: "1903",
                   18363: "1909", 19041: "2004", 19042: "20H2", 19043: "21H1",
                   19044: "21H2", 19045: "22H2"}
_WIN11_BY_BUILD = {22000: "21H2", 22621: "22H2", 22631: "23H2", 26100: "24H2",
                   26200: "25H2"}
_ARCH = {"amd64": "x64-based Systems", "x86": "32-bit Systems",
         "arm64": "ARM64-based Systems"}


def msrc_products(os: WindowsOs) -> list[str]:
    """Названия продукта в MSRC для ОС хоста — от точного к запасному."""
    if os.build is None:
        return []
    arch = _ARCH.get((os.arch or "amd64").lower(), "x64-based Systems")
    if os.is_server:
        base = _SERVER_BY_BUILD.get(os.build)
        if base is None:
            return []
        if os.build == 7601:
            base = f"{base} for x64-based Systems Service Pack 1"
        core = f"{base} (Server Core installation)"
        return [core, base] if os.is_core else [base, core]
    if os.build in _WIN11_BY_BUILD:
        return [f"Windows 11 Version {_WIN11_BY_BUILD[os.build]} for {arch}"]
    if os.build in _WIN10_BY_BUILD:
        ver = _WIN10_BY_BUILD[os.build]
        return [f"Windows 10 Version {ver} for {arch}" if ver else f"Windows 10 for {arch}"]
    if os.build == 9600:
        return [f"Windows 8.1 for {arch}"]
    if os.build == 7601:
        return [f"Windows 7 for {arch} Service Pack 1"]
    return []


# ---------- сопоставление ----------

def _build_tuple(build: str | None) -> tuple[int, ...] | None:
    if not build or not _BUILD_RE.match(build):
        return None
    return tuple(int(x) for x in build.split("."))


def build_fixed(host_version: str | None, fixed_build: str | None) -> bool:
    """Сборка хоста не ниже FixedBuild той же ветки (major.minor.build совпадают)."""
    h, f = _build_tuple(host_version), _build_tuple(fixed_build)
    if h is None or f is None or h[:3] != f[:3]:
        return False
    return h[3] >= f[3]


def covered_kbs(installed: Iterable[str], fixes: Sequence[MsrcFix]) -> set[str]:
    """Установленные KB и все, что они замещают (транзитивно)."""
    supersedes: dict[str, set[str]] = {}
    for f in fixes:
        supersedes.setdefault(f.kb, set()).update(f.supersedes)
    seen: set[str] = set()
    stack = [kb for kb in installed]
    while stack:
        kb = stack.pop()
        if kb in seen:
            continue
        seen.add(kb)
        stack.extend(supersedes.get(kb, ()))
    return seen


@dataclass(slots=True)
class KbGap:
    """CVE продукта хоста, не закрытая установленными обновлениями."""
    cve_id: str
    fix_kbs: list[str]
    recommended_kb: str | None
    fixed_build: str | None
    severity: str | None
    cvss: float | None
    title: str | None
    release: str


@dataclass(slots=True)
class Assessment:
    product: str | None                 # продукт MSRC, по которому сопоставлено
    gaps: list[KbGap] = field(default_factory=list)
    fixed: int = 0                      # CVE продукта, закрытые обновлениями
    no_data: bool = False               # справочник пуст или продукт не распознан
    reason: str | None = None


def _norm_kb(kb: str) -> str | None:
    m = _KB_RE.search(kb or "")
    return m.group(0) if m else None


def assess(os: WindowsOs, installed_kbs: Iterable[str], store) -> Assessment:
    """Какие CVE продукта хоста не закрыты установленными KB (с замещением)."""
    candidates = msrc_products(os)
    if not candidates:
        return Assessment(None, no_data=True,
                          reason=f"продукт MSRC для «{os.label}» не распознан")
    product, fixes = None, []
    for name in candidates:
        fixes = store.fixes_for(name)
        if fixes:
            product = name
            break
    if not fixes:
        return Assessment(candidates[0], no_data=True,
                          reason=f"в справочнике MSRC нет данных по «{candidates[0]}» — "
                                 "загрузите справочник обновлений Microsoft")
    installed = {k for k in (_norm_kb(x) for x in installed_kbs) if k}
    covered = covered_kbs(installed, fixes)
    host_version = os.version

    # последняя KB каждой цепочки замещения — её и рекомендовать
    superseded = {s for f in fixes for s in f.supersedes}
    kb_release = {}
    for f in fixes:
        if release_key(f.release) > release_key(kb_release.get(f.kb, "")):
            kb_release[f.kb] = f.release
    heads = sorted((kb for kb in kb_release if kb not in superseded),
                   key=lambda kb: release_key(kb_release[kb]), reverse=True)
    head_closure = {kb: covered_kbs([kb], fixes) for kb in heads}

    by_cve: dict[str, list[MsrcFix]] = {}
    for f in fixes:
        by_cve.setdefault(f.cve_id, []).append(f)
    out = Assessment(product)
    for cve, items in sorted(by_cve.items()):
        kbs = list(dict.fromkeys(f.kb for f in items))
        if covered & set(kbs) or any(build_fixed(host_version, f.fixed_build)
                                     for f in items):
            out.fixed += 1
            continue
        rec = next((h for h in heads if head_closure[h] & set(kbs)), None)
        latest = max(items, key=lambda f: release_key(f.release))
        builds = sorted({f.fixed_build for f in items if f.fixed_build},
                        key=lambda b: _build_tuple(b) or ())
        scores = [f.cvss for f in items if f.cvss is not None]
        out.gaps.append(KbGap(
            cve_id=cve, fix_kbs=kbs, recommended_kb=rec, fixed_build=builds[0] if builds
            else None, severity=next((f.severity for f in items if f.severity), None),
            cvss=max(scores) if scores else None, title=latest.title,
            release=latest.release))
    return out


# ---------- загрузка ----------

class _MsrcSettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="SCANNER_MSRC_", env_file=".env",
                                      extra="ignore")

    api_url: str = API_URL
    # Файл или каталог с документами CVRF (*.json) — для закрытого контура.
    feed_path: str = ""
    # С какого бюллетеня грузить при первой загрузке: накопительные обновления
    # замещают старые, глубже история нужна только для давно не обновлявшихся ОС.
    since: str = "2019-Jan"


def msrc_settings() -> _MsrcSettings:
    return _MsrcSettings()


class MsrcFeed:
    def __init__(self, api_url: str = API_URL, *, timeout: float = 120.0, client=None):
        self.api_url = api_url.rstrip("/")
        self.timeout = timeout
        self._client = client

    def _get(self, url: str) -> dict[str, Any]:
        import httpx
        client = self._client or httpx
        try:
            resp = client.get(url, headers={"Accept": "application/json"},
                              timeout=self.timeout, follow_redirects=True)
            resp.raise_for_status()
            return resp.json()
        except (httpx.HTTPError, ValueError) as e:
            raise MsrcError(f"MSRC: {type(e).__name__}: {e}"[:500]) from e

    def releases(self) -> list[dict[str, Any]]:
        """Список бюллетеней: [{ID, CurrentReleaseDate, CvrfUrl}, ...]."""
        data = self._get(f"{self.api_url}/updates")
        return [u for u in data.get("value") or [] if u.get("ID")]

    def iter_api(self, *, since: str = "2019-Jan",
                 modified_after: datetime | None = None
                 ) -> Iterator[tuple[str, list[MsrcFix]]]:
        """(бюллетень, исправления) — с `since`; при `modified_after` — только
        переизданные после этой даты."""
        floor = release_key(since)
        for u in sorted(self.releases(), key=lambda x: release_key(x["ID"])):
            rid = str(u["ID"])
            if release_key(rid)[:2] < floor[:2]:
                continue
            if modified_after is not None:
                changed = _parse_dt(u.get("CurrentReleaseDate"))
                if changed is not None and changed <= modified_after:
                    continue
            url = u.get("CvrfUrl") or f"{self.api_url}/cvrf/{rid}"
            yield rid, parse_cvrf(self._get(url), rid)

    @staticmethod
    def iter_files(paths: Iterable[Path]) -> Iterator[tuple[str, list[MsrcFix]]]:
        files: list[Path] = []
        for p in paths:
            files.extend(sorted(p.glob("*.json")) if p.is_dir() else [p])
        for f in files:
            try:
                doc = json.loads(f.read_text(encoding="utf-8-sig"))
            except (OSError, ValueError) as e:
                raise MsrcError(f"{f.name}: не удалось прочитать CVRF JSON: {e}") from e
            fixes = parse_cvrf(doc)
            yield (fixes[0].release if fixes else f.stem), fixes

    @staticmethod
    def sync(store: MsrcStore, documents: Iterable[tuple[str, list[MsrcFix]]]
             ) -> tuple[int, int]:
        """Загружает документы; возвращает (бюллетеней, исправлений)."""
        docs = fixes = 0
        for release, items in documents:
            fixes += store.replace_release(release, items)
            docs += 1
        return docs, fixes


def _parse_dt(value: Any) -> datetime | None:
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None
