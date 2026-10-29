"""Слой сопоставления находок с базами уязвимостей (NVD + БДУ ФСТЭК).

Цепочки сопоставления (каждая находка на выходе несёт и CVE, и ``BDU:…``):
  1. есть CVE (``finding.vuln_id`` / ``finding.cve_ids``) -> запись NVD +
     все записи БДУ, где этот CVE указан в «Идентификаторах других систем»;
  2. есть только ``BDU:…`` -> запись БДУ -> её CVE -> NVD (+ прочие записи БДУ
     по тем же CVE);
  3. нет идентификаторов, но есть сервис+версия (``ServiceInfo``) ->
     CPE -> уязвимые конфигурации NVD (с диапазонами версий) -> CVE -> БДУ;
  4. плюс прямой поиск в БДУ по названию ПО и версии (поле «Версия ПО») —
     ловит записи БДУ без CVE (отечественное ПО) и работает без загруженного NVD.

Сопоставление по баннеру (3, 4) не учитывает бэкпорты патчей в дистрибутивах,
поэтому такие совпадения помечаются в ``MatchEvidence.source`` и в evidence находки.
"""
from __future__ import annotations

import re
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field

from scanner.core.models import Finding, FindingType, ServiceInfo, Severity
from scanner.feeds.bdu_fstec import BduRecord, BduVersionSpec, parse_bdu_versions
from scanner.feeds.cpe import (
    VENDOR_SYNONYMS,
    Cpe,
    clean_version,
    compare_versions,
    normalize_name,
    service_cpe,
    version_in_range,
)
from scanner.feeds.nvd import CpeMatch, NvdRecord
from scanner.feeds.severity import (
    bdu_best_score,
    max_severity,
    severity_from_bdu_text,
    severity_from_cvss,
)
from scanner.feeds.store import ReferenceStore

# Источник совпадения (от более к менее достоверному)
SRC_CVE = "cve"                  # CVE пришёл от проверки (Nuclei/OpenVAS)
SRC_BDU_ID = "bdu_id"            # BDU пришёл от проверки
SRC_CVE_LINK = "cve_link"        # связь CVE <-> БДУ из выгрузки БДУ
SRC_CPE = "cpe"                  # версия сервиса попала в уязвимую конфигурацию NVD
SRC_BDU_PRODUCT = "bdu_product"  # версия сервиса попала в «Версия ПО» записи БДУ

# Продукт CPE -> (названия ПО в БДУ, обязательное слово в «Вендор ПО» или None).
# Без подсказки ищем по продукту CPE («openssh», «tomcat») без проверки вендора;
# вендор проверяем только для общих названий, которые есть у разных вендоров
# («HTTP Server» бывает у Apache, Oracle и IBM).
BDU_SOFTWARE_HINTS: dict[str, tuple[list[str], str | None]] = {
    "http_server": (["HTTP Server", "Apache HTTP Server"], "apache"),
    "internet_information_services": (["Internet Information Services", "IIS"], "microsoft"),
    "sql_server": (["SQL Server", "Microsoft SQL Server"], "microsoft"),
    "dropbear_ssh": (["Dropbear SSH", "Dropbear"], None),
    "bind": (["BIND", "BIND 9"], None),
    "jetty": (["Jetty"], None),
}


@dataclass(slots=True)
class MatchEvidence:
    source: str
    identifier: str
    detail: str = ""


@dataclass(slots=True)
class MatchResult:
    cve_ids: list[str] = field(default_factory=list)
    bdu_ids: list[str] = field(default_factory=list)
    nvd: dict[str, NvdRecord] = field(default_factory=dict)
    bdu: dict[str, BduRecord] = field(default_factory=dict)
    evidence: list[MatchEvidence] = field(default_factory=list)
    cvss: float | None = None
    severity: Severity | None = None

    @property
    def matched(self) -> bool:
        return bool(self.cve_ids or self.bdu_ids)

    @property
    def remediation(self) -> list[str]:
        """Меры по устранению из БДУ (для отчёта с рекомендациями)."""
        seen: list[str] = []
        for rec in self.bdu.values():
            if rec.remediation and rec.remediation not in seen:
                seen.append(rec.remediation)
        return seen


def _norm_id(value: str) -> str:
    return value.strip().upper()


def _bdu_spec_matches(spec: BduVersionSpec, version: str) -> bool:
    if spec.unknown:
        return False
    if spec.exact is not None:
        return compare_versions(version, spec.exact) == 0
    if spec.start and compare_versions(version, spec.start) < 0:
        return False
    if spec.end:
        c = compare_versions(version, spec.end)
        return c <= 0 if spec.end_inclusive else c < 0
    return True


# Граница в формате пакета дистрибутива: ``2.19-18+deb8u4``, ``1.2-3ubuntu1``,
# ``8.0p1-24.el9``, ``0.105-16.1``. Не путать с версиями апстрима через дефис
# (ImageMagick ``7.0.10-62``).
_DISTRO_REVISION = re.compile(
    r"[~+]|-\d+\.\d|-[^-]*(deb\d|ubuntu|astra|\.el\d|\.fc\d|alt\d|\.red\d|\.mos)",
    re.IGNORECASE)


def _spec_version(spec: BduVersionSpec, upstream: str, distro: str | None) -> str:
    """Какой версией проверять запись БДУ: границы в формате дистрибутива
    (``2.19-18+deb8u4``, ``0.105-16.1``) — версией пакета, иначе — апстрима."""
    if distro and any(b and _DISTRO_REVISION.search(b)
                      for b in (spec.exact, spec.start, spec.end)):
        return distro
    return upstream


class VulnMatcher:
    def __init__(self, store: ReferenceStore, *, bdu_product_match: bool = True,
                 bdu_software_aliases: dict[str, list[str]] | None = None):
        """
        :param bdu_product_match: искать в БДУ напрямую по ПО+версии (цепочка 4).
        :param bdu_software_aliases: доп. названия ПО в БДУ для продукта CPE,
            напр. ``{"http_server": ["HTTP Server", "Apache HTTP Server"]}``.
        """
        self.store = store
        self.bdu_product_match = bdu_product_match
        self.bdu_software_aliases = {k.lower(): v for k, v in (bdu_software_aliases or {}).items()}

    # ---------- публичный API ----------

    def enrich(self, finding: Finding, service: ServiceInfo | None = None) -> Finding:
        """Дополняет находку CVE, BDU, CVSS и severity (изменяет и возвращает её).

        Если у находки нет идентификаторов, нужен ``service`` (сервис+версия).
        """
        res = self.match(finding, service)
        self._apply(finding, res)
        return finding

    def match(self, finding: Finding, service: ServiceInfo | None = None) -> MatchResult:
        res = MatchResult()
        cves = [_norm_id(c) for c in finding.cve_ids]
        bdus = [_norm_id(b) for b in finding.bdu_ids]
        if finding.vuln_id:
            vid = _norm_id(finding.vuln_id)
            if vid.startswith("CVE-"):
                cves.insert(0, vid)
            elif vid.startswith("BDU:"):
                bdus.insert(0, vid)
        for cve in dict.fromkeys(cves):
            self._add_cve(res, cve, MatchEvidence(SRC_CVE, cve, "идентификатор от проверки"))
        for bdu_id in dict.fromkeys(bdus):
            self._add_bdu_id(res, bdu_id)
        if not res.matched and service is not None:
            for cve, ev in self._cves_by_cpe(service):
                self._add_cve(res, cve, ev)
            if self.bdu_product_match:
                for rec, ev in self._bdu_by_product(service):
                    self._add_bdu(res, rec, ev)
        self._score(res)
        return res

    def findings_for_service(self, service: ServiceInfo, *, module: str = "vuln") -> list[Finding]:
        """Находки по баннеру сервиса: по одной на каждый CVE (или BDU без CVE),
        чтобы ключ сравнения прогонов (host+port+vuln_id+module) был стабильным."""
        res = MatchResult()
        for cve, ev in self._cves_by_cpe(service):
            self._add_cve(res, cve, ev)
        if self.bdu_product_match:
            for rec, ev in self._bdu_by_product(service):
                self._add_bdu(res, rec, ev)
        label = " ".join(x for x in (service.product, service.version) if x) or service.service
        return self._version_findings(
            res, host=service.host, port=service.port, module=module, label=label,
            evidence=lambda ids: self._evidence_text(res, ids, service))

    def findings_for_package(self, host: str, *, product: str, version: str,
                             cpe: str | None = None, bdu_names: Sequence[str] = (),
                             distro_version: str | None = None,
                             packages: Sequence[str] = (), use_nvd: bool = True,
                             module: str = "auth_inventory") -> list[Finding]:
        """Находки по установленному пакету (аутентифицированная инвентаризация).

        :param product: название ПО (главное имя в БДУ), напр. «OpenSSH».
        :param version: версия апстрима (``9.2p1``).
        :param cpe: ``cpe:/a:vendor:product`` — только для известных пакетов;
            без него NVD не используется (только БДУ по названию ПО).
        :param distro_version: версия пакета без эпохи (``9.2p1-2+deb12u3``) —
            для записей БДУ, где граница указана в формате дистрибутива.
        :param packages: пакеты хоста, давшие это ПО (для evidence).
        Находки без порта: уязвимость относится к хосту, а не к сервису.
        """
        cpe_value = f"{cpe}:{version}" if cpe else None
        service = ServiceInfo(host=host, port=0, protocol="pkg", product=product,
                              version=version, cpe=cpe_value)
        res = MatchResult()
        if use_nvd and cpe:
            for cve, ev in self._cves_by_cpe(service):
                self._add_cve(res, cve, ev)
        if self.bdu_product_match:
            for rec, ev in self._bdu_by_product(service, extra_names=bdu_names,
                                                distro_version=distro_version,
                                                hints=bool(cpe)):
                self._add_bdu(res, rec, ev)
        label = f"{product} {version}"
        pkgs = ", ".join(packages) or product

        def evidence(ids: set[str]) -> str:
            lines = [f"Пакет {pkgs} ({distro_version or version}) → {label}"
                     + (f", {cpe_value}" if cpe_value else "")]
            lines += [f"[{e.source}] {e.identifier}: {e.detail}"
                      for e in res.evidence
                      if e.identifier in ids and e.source in (SRC_CPE, SRC_BDU_PRODUCT)]
            lines.append("Совпадение по версии установленного пакета: дистрибутив мог "
                         "перенести исправление в свою ревизию пакета (бэкпорт) — "
                         "сверьтесь с бюллетенем безопасности дистрибутива.")
            return "\n".join(lines)

        return self._version_findings(res, host=host, port=None, module=module,
                                      label=label, evidence=evidence)

    def _version_findings(self, res: MatchResult, *, host: str, port: int | None,
                          module: str, label: str | None,
                          evidence: Callable[[set[str]], str]) -> list[Finding]:
        findings: list[Finding] = []
        for cve in res.cve_ids:
            f = Finding(module=module, host=host, port=port,
                        finding_type=FindingType.VULN, vuln_id=cve, cve_ids=[cve],
                        title=self._title(res, cve, label))
            findings.append(self.enrich(f))
            f.evidence = evidence({cve, *f.bdu_ids})
        linked = {b for f in findings for b in f.bdu_ids}
        for bdu_id in res.bdu_ids:
            if bdu_id in linked:
                continue
            rec = res.bdu[bdu_id]
            f = Finding(module=module, host=host, port=port,
                        finding_type=FindingType.VULN, vuln_id=bdu_id, bdu_ids=[bdu_id],
                        title=rec.title or f"{bdu_id} в {label}")
            findings.append(self.enrich(f))
            f.evidence = evidence({bdu_id})
        return findings

    # ---------- сборка результата ----------

    def _add_cve(self, res: MatchResult, cve: str, ev: MatchEvidence) -> None:
        if cve in res.cve_ids:
            return
        res.cve_ids.append(cve)
        res.evidence.append(ev)
        nvd = self.store.get_nvd(cve)
        if nvd:
            res.nvd[cve] = nvd
        for rec in self.store.bdu_by_cve(cve):
            self._add_bdu(res, rec, MatchEvidence(SRC_CVE_LINK, rec.bdu_id, f"связан с {cve}"),
                          follow_cves=False)

    def _add_bdu_id(self, res: MatchResult, bdu_id: str) -> None:
        rec = self.store.get_bdu(bdu_id)
        if rec is None:
            if bdu_id not in res.bdu_ids:
                res.bdu_ids.append(bdu_id)
                res.evidence.append(MatchEvidence(SRC_BDU_ID, bdu_id, "нет в справочнике БДУ"))
            return
        self._add_bdu(res, rec, MatchEvidence(SRC_BDU_ID, bdu_id, "идентификатор от проверки"))

    def _add_bdu(self, res: MatchResult, rec: BduRecord, ev: MatchEvidence,
                 *, follow_cves: bool = True) -> None:
        if rec.bdu_id in res.bdu_ids:
            return
        res.bdu_ids.append(rec.bdu_id)
        res.bdu[rec.bdu_id] = rec
        res.evidence.append(ev)
        if follow_cves:
            for cve in rec.cve_ids:
                self._add_cve(res, cve, MatchEvidence(SRC_CVE_LINK, cve, f"указан в {rec.bdu_id}"))

    def _score(self, res: MatchResult) -> None:
        nvd_scores = [r.cvss_v3 for r in res.nvd.values() if r.cvss_v3 is not None]
        bdu_scores = [s for s in (bdu_best_score(r.severity_text) or r.cvss_score
                                  for r in res.bdu.values()) if s is not None]
        # Оценка NVD приоритетнее; если её нет — базовая оценка из БДУ.
        res.cvss = max(nvd_scores) if nvd_scores else (max(bdu_scores) if bdu_scores else None)
        res.severity = max_severity(
            severity_from_cvss(res.cvss),
            *(severity_from_bdu_text(r.severity_text) for r in res.bdu.values()),
        ) if res.matched else None

    @staticmethod
    def _apply(finding: Finding, res: MatchResult) -> None:
        finding.cve_ids = list(dict.fromkeys([*map(_norm_id, finding.cve_ids), *res.cve_ids]))
        finding.bdu_ids = list(dict.fromkeys([*map(_norm_id, finding.bdu_ids), *res.bdu_ids]))
        if res.cvss is not None and (finding.cvss is None or res.cvss > finding.cvss):
            finding.cvss = res.cvss
        if res.severity is not None:
            finding.severity = max_severity(finding.severity, res.severity)

    # ---------- цепочка CPE -> CVE ----------

    def _cves_by_cpe(self, service: ServiceInfo) -> list[tuple[str, MatchEvidence]]:
        cpe = service_cpe(service.cpe, service.product, service.version)
        if cpe is None:
            return []
        version = clean_version(cpe.full_version) or clean_version(service.version)
        if not version:
            return []  # без версии сопоставление по CPE даёт слишком много ложных
        vendors = VENDOR_SYNONYMS.get(cpe.vendor, {cpe.vendor})
        out: list[tuple[str, MatchEvidence]] = []
        seen: set[str] = set()
        for m in self.store.cpe_matches(cpe.product):
            if m.cve_id in seen:
                continue
            if cpe.vendor != "*" and m.vendor not in vendors:
                continue
            if not self._cpe_match_hits(m, version):
                continue
            seen.add(m.cve_id)
            out.append((m.cve_id, MatchEvidence(
                SRC_CPE, m.cve_id, f"{cpe.vendor}:{cpe.product}:{version} ∈ {self._describe(m)}")))
        return sorted(out, key=lambda x: x[0])

    @staticmethod
    def _cpe_match_hits(m: CpeMatch, version: str) -> bool:
        exact = Cpe("a", m.vendor, m.product, m.version, m.update).full_version
        has_range = any((m.version_start_incl, m.version_start_excl,
                         m.version_end_incl, m.version_end_excl))
        return version_in_range(
            version, exact=None if has_range else exact,
            start_incl=m.version_start_incl, start_excl=m.version_start_excl,
            end_incl=m.version_end_incl, end_excl=m.version_end_excl)

    @staticmethod
    def _describe(m: CpeMatch) -> str:
        parts = []
        if m.version_start_incl:
            parts.append(f">={m.version_start_incl}")
        if m.version_start_excl:
            parts.append(f">{m.version_start_excl}")
        if m.version_end_incl:
            parts.append(f"<={m.version_end_incl}")
        if m.version_end_excl:
            parts.append(f"<{m.version_end_excl}")
        return f"{m.criteria} {' '.join(parts)}".strip()

    # ---------- прямой поиск в БДУ по ПО+версии ----------

    def _bdu_software_names(self, service: ServiceInfo, cpe: Cpe | None,
                            hints: bool = True) -> tuple[list[str], str | None]:
        names: list[str] = []
        vendor_word: str | None = None
        if cpe and hints:
            hint_names, vendor_word = BDU_SOFTWARE_HINTS.get(cpe.product, ([], None))
            names += self.bdu_software_aliases.get(cpe.product, [])
            names += hint_names
            names.append(cpe.product.replace("_", " "))
        if service.product and not (cpe and hints and cpe.product in BDU_SOFTWARE_HINTS):
            names.append(service.product)
        return list(dict.fromkeys(n for n in names if normalize_name(n))), vendor_word

    def _bdu_by_product(self, service: ServiceInfo, *, extra_names: Sequence[str] = (),
                        distro_version: str | None = None, hints: bool = True,
                        ) -> list[tuple[BduRecord, MatchEvidence]]:
        """Записи БДУ, где ПО сервиса/пакета и его версия попадают в «Версия ПО».

        distro_version — версия пакета дистрибутива (без эпохи): ей проверяются
        границы, записанные в формате дистрибутива (``до 2.19-18+deb8u4``),
        остальные — версией апстрима.
        """
        cpe = (service_cpe(service.cpe, service.product, service.version) if hints
               else None)
        version = clean_version(cpe.full_version if cpe else None) or clean_version(service.version)
        if not version:
            return []
        names, vendor_word = self._bdu_software_names(service, cpe, hints)
        names = list(dict.fromkeys([*names, *(n for n in extra_names if normalize_name(n))]))
        out: list[tuple[BduRecord, MatchEvidence]] = []
        seen: set[str] = set()
        for name in names:
            norm = normalize_name(name)
            for rec in self.store.bdu_by_software(name):
                if rec.bdu_id in seen:
                    continue
                if vendor_word and vendor_word not in normalize_name(rec.vendor):
                    continue
                hit = next((s for s in parse_bdu_versions(rec.versions)
                            if normalize_name(s.software) == norm
                            and _bdu_spec_matches(s, _spec_version(s, version,
                                                                   distro_version))),
                           None)
                if hit is None:
                    continue
                seen.add(rec.bdu_id)
                shown = _spec_version(hit, version, distro_version)
                out.append((rec, MatchEvidence(
                    SRC_BDU_PRODUCT, rec.bdu_id,
                    f"{hit.software} {shown} ∈ «{self._describe_spec(hit)}»")))
        return sorted(out, key=lambda x: x[0].bdu_id)

    @staticmethod
    def _describe_spec(s: BduVersionSpec) -> str:
        if s.exact:
            return s.exact
        parts = []
        if s.start:
            parts.append(f"от {s.start}")
        if s.end:
            parts.append(f"до {s.end}" + (" включительно" if s.end_inclusive else ""))
        return " ".join(parts)

    # ---------- оформление ----------

    @staticmethod
    def _title(res: MatchResult, cve: str, label: str | None) -> str:
        bdu = next((r for r in res.bdu.values() if cve in r.cve_ids and r.title), None)
        if bdu:
            return bdu.title  # type: ignore[return-value]
        return f"{cve} в {label}" if label else cve

    @staticmethod
    def _evidence_text(res: MatchResult, idents: set[str], service: ServiceInfo) -> str:
        banner = " ".join(x for x in (service.product, service.version) if x)
        lines = [f"Сервис {service.host}:{service.port}/{service.protocol} «{banner}»"
                 + (f", {service.cpe}" if service.cpe else "")]
        lines += [f"[{e.source}] {e.identifier}: {e.detail}"
                  for e in res.evidence
                  if e.identifier in idents and e.source in (SRC_CPE, SRC_BDU_PRODUCT)]
        lines.append("Совпадение по версии из баннера: возможен бэкпорт исправления "
                     "в дистрибутиве — подтвердите проверкой.")
        return "\n".join(lines)
