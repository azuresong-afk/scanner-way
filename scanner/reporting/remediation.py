"""Рекомендации по устранению для каждой находки.

Источники в порядке приоритета:
  1. рекомендация, уже записанная в саму находку (поле `remediation`, если его
     заполнил модуль/матчер — например, правило бенчмарка в config audit);
  2. БДУ ФСТЭК: «Возможные меры по устранению» + «Способ устранения»
     (по `bdu_ids` находки или через связь CVE -> БДУ);
  3. NVD / вендор: меры и ссылки на бюллетени по CVE;
  4. правила бенчмарка (CIS / ФСТЭК / ГОСТ) по идентификатору правила;
  5. типовая рекомендация по типу находки — чтобы в отчёте не было находок
     без указаний, что делать.

Ссылки на устранение собираются для каждой находки из нескольких источников:
«Ссылки на источники» записи БДУ (бюллетени производителей, исправления,
бюллетени отечественных ОС), ссылки NVD, страницы БДУ/NVD/CWE, контроль Lynis
и профильные руководства (NIST, OWASP, man sshd_config) по теме находки.
Ссылки без пользы для устранения (базы эксплойтов, новости, соцсети,
агрегаторы) отбрасываются; остальные упорядочиваются: бюллетень производителя
-> исправление -> бюллетени ОС -> БДУ/NVD -> справочные материалы.

Справочники передаются извне (из БД или фидов), поэтому модуль не зависит от
persistence и тестируется на фикстурах.
"""
from __future__ import annotations

import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from enum import IntEnum, StrEnum
from typing import Protocol
from urllib.parse import urlsplit

from scanner.core.models import Finding, FindingType, Severity


class RemediationSource(StrEnum):
    FINDING = "finding"
    BDU = "bdu_fstec"
    NVD = "nvd"
    BENCHMARK = "benchmark"
    GENERIC = "generic"


SOURCE_LABELS: dict[RemediationSource, str] = {
    RemediationSource.FINDING: "Модуль сканирования",
    RemediationSource.BDU: "БДУ ФСТЭК России",
    RemediationSource.NVD: "NVD / производитель",
    RemediationSource.BENCHMARK: "Правило бенчмарка",
    RemediationSource.GENERIC: "Типовая рекомендация",
}

# Рекомендуемые сроки устранения по уровню опасности (дни). Значения по
# умолчанию — типовая практика; переопределяются через RemediationResolver.
DEFAULT_DEADLINES: dict[Severity, int | None] = {
    Severity.CRITICAL: 3,
    Severity.HIGH: 14,
    Severity.MEDIUM: 30,
    Severity.LOW: 90,
    Severity.INFO: None,
}


class BduLike(Protocol):
    """Минимум полей записи БДУ (совместимо с feeds.bdu_fstec.BduRecord).

    Необязательные поля `refs` («Ссылки на источники», URL через перевод строки)
    и `cwe` («Тип ошибки CWE») читаются через getattr.
    """
    bdu_id: str
    remediation: str | None
    fix_method: str | None
    cve_ids: list[str]


@dataclass(slots=True)
class Remediation:
    text: str
    source: RemediationSource
    references: list[str] = field(default_factory=list)
    deadline_days: int | None = None
    fix_method: str | None = None

    @property
    def source_label(self) -> str:
        return SOURCE_LABELS[self.source]

    def to_dict(self) -> dict:
        return {
            "text": self.text,
            "source": str(self.source),
            "source_label": self.source_label,
            "fix_method": self.fix_method,
            "deadline_days": self.deadline_days,
            "references": list(self.references),
        }


def bdu_url(bdu_id: str) -> str:
    """BDU:2023-00001 -> https://bdu.fstec.ru/vul/2023-00001"""
    return f"https://bdu.fstec.ru/vul/{bdu_id.split(':', 1)[-1]}"


def nvd_url(cve_id: str) -> str:
    return f"https://nvd.nist.gov/vuln/detail/{cve_id}"


def cwe_url(cwe_id: str) -> str:
    return f"https://cwe.mitre.org/data/definitions/{cwe_id.split('-')[-1]}.html"


def lynis_url(control: str) -> str:
    return f"https://cisofy.com/lynis/controls/{control}/"


# --- ссылки на устранение ------------------------------------------------------

class RefKind(IntEnum):
    """Вид ссылки; значение — порядок в отчёте."""
    VENDOR = 0      # бюллетень производителя
    PATCH = 1       # исправление (коммит, релиз)
    OS = 2          # бюллетень дистрибутива ОС
    REGISTRY = 3    # БДУ ФСТЭК, NVD
    GUIDE = 4       # справочные материалы: CWE, руководства, контроль бенчмарка


@dataclass(frozen=True, slots=True)
class RefLink:
    url: str
    label: str
    kind: RefKind


# Домены, ссылки на которые не помогают устранению: эксплойты, новости, соцсети,
# агрегаторы, почтовые рассылки, баг-трекеры, мёртвые базы.
_SKIP_DOMAINS = (
    "exploit-db.com", "packetstormsecurity.com", "cxsecurity.com", "vuldb.com",
    "cybersecurity-help.cz", "securityfocus.com", "securitytracker.com", "securitylab.ru",
    "safe-surf.ru", "strelets.net", "lwn.net", "seclists.org", "openwall.com",
    "zerodayinitiative.com", "talosintelligence.com", "cve.mitre.org", "cve.org",
    "lore.kernel.org", "twitter.com", "x.com", "bsky.app", "t.me", "youtube.com",
    "habr.com", "medium.com", "reddit.com", "crbug.com", "issues.chromium.org",
    "hackerone.com",
)
_SKIP_PREFIXES = ("lists.", "bugzilla.", "bugs.", "blog.", "blogs.")

_OS = {
    "wiki.astralinux.ru": "Astra Linux", "astralinux.ru": "Astra Linux",
    "redos.red-soft.ru": "РЕД ОС", "repo.red-soft.ru": "РЕД ОС",
    "altsp.su": "Альт", "packages.altlinux.org": "Альт",
    "поддержка.нппкт.рф": "ОС «Основа» (НППКТ)",
    "abf.rosa.ru": "РОСА", "abf.rosalinux.ru": "РОСА",
    "ubuntu.com": "Ubuntu", "usn.ubuntu.com": "Ubuntu",
    "security-tracker.debian.org": "Debian", "debian.org": "Debian",
    "deb.freexian.com": "Debian LTS",
    "access.redhat.com": "Red Hat", "rhn.redhat.com": "Red Hat",
    "suse.com": "SUSE", "security.gentoo.org": "Gentoo",
}
_VENDORS = {
    "microsoft.com": "Microsoft", "oracle.com": "Oracle", "adobe.com": "Adobe",
    "apple.com": "Apple", "cisco.com": "Cisco", "mozilla.org": "Mozilla",
    "chromereleases.googleblog.com": "Google Chrome", "source.android.com": "Android",
    "siemens.com": "Siemens", "fortiguard.com": "Fortinet", "intel.com": "Intel",
    "ibm.com": "IBM", "dell.com": "Dell", "netapp.com": "NetApp", "se.com": "Schneider Electric",
    "schneider-electric.com": "Schneider Electric", "vmware.com": "VMware",
    "broadcom.com": "Broadcom", "paloaltonetworks.com": "Palo Alto Networks",
    "juniper.net": "Juniper", "f5.com": "F5", "sap.com": "SAP", "hp.com": "HP",
    "hpe.com": "HPE", "lenovo.com": "Lenovo", "huawei.com": "Huawei",
    "openssh.com": "OpenSSH", "openssl.org": "OpenSSL", "apache.org": "Apache",
    "nginx.org": "nginx", "php.net": "PHP", "python.org": "Python", "cisa.gov": "CISA",
    "kaspersky.ru": "Kaspersky", "1c.ru": "1С",
}
_GUIDES = {
    "cwe.mitre.org": "CWE", "cisofy.com": "Lynis", "man.openbsd.org": "OpenSSH, документация",
    "pages.nist.gov": "NIST SP 800-63B", "cheatsheetseries.owasp.org": "OWASP Cheat Sheet",
    "ssl-config.mozilla.org": "Mozilla SSL Configuration Generator",
}


def _host(url: str) -> str:
    try:
        host = (urlsplit(url).hostname or "").lower()
    except ValueError:
        return ""
    return host.removeprefix("www.")


def _match(host: str, table: Mapping[str, str]) -> str | None:
    for domain, label in table.items():
        if host == domain or host.endswith("." + domain):
            return label
    return None


def describe_ref(url: str) -> RefLink | None:
    """Подпись и вид ссылки; None — ссылка не помогает устранению."""
    url = url.strip().rstrip(".,;")
    if not url.lower().startswith(("http://", "https://")):
        return None
    host = _host(url)
    if not host:
        return None
    if any(host == d or host.endswith("." + d) for d in _SKIP_DOMAINS) \
            or host.startswith(_SKIP_PREFIXES):
        return None
    path = urlsplit(url).path
    if host == "bdu.fstec.ru":
        return RefLink(url, "БДУ ФСТЭК " + path.rstrip("/").rsplit("/", 1)[-1], RefKind.REGISTRY)
    if host == "nvd.nist.gov":
        return RefLink(url, "NVD " + path.rstrip("/").rsplit("/", 1)[-1], RefKind.REGISTRY)
    if host == "cwe.mitre.org":
        num = re.search(r"(\d+)\.html", path)
        return RefLink(url, f"CWE-{num.group(1)}" if num else "CWE", RefKind.GUIDE)
    if host in ("github.com", "gitlab.com"):
        if "/advisories" in path or "/security/" in path:
            return RefLink(url, "GitHub Security Advisory", RefKind.VENDOR)
        if re.search(r"/(commit|commits|pull|merge_requests|releases|tags|compare)(/|$)", path):
            return RefLink(url, "Исправление в репозитории", RefKind.PATCH)
        return None                       # корень репозитория, PoC и т.п.
    if host.endswith("kernel.org"):
        return RefLink(url, "Исправление ядра Linux", RefKind.PATCH)
    if label := _match(host, _OS):
        return RefLink(url, f"Бюллетень {label}", RefKind.OS)
    if label := _match(host, _GUIDES):
        return RefLink(url, label, RefKind.GUIDE)
    if label := _match(host, _VENDORS):
        return RefLink(url, f"Бюллетень {label}", RefKind.VENDOR)
    return RefLink(url, f"Бюллетень ({host})", RefKind.VENDOR)


MAX_REFERENCES = 10


def curate_refs(urls: Iterable[str], limit: int = MAX_REFERENCES) -> list[str]:
    """Убирает бесполезные и повторные ссылки, упорядочивает по пользе."""
    seen: set[str] = set()
    links: list[tuple[int, int, str]] = []
    for i, u in enumerate(urls):
        link = describe_ref(u)
        if link is None:
            continue
        key = link.url.rstrip("/").lower().replace("http://", "https://")
        if key in seen:
            continue
        seen.add(key)
        links.append((link.kind, i, link.url))
    links.sort()
    return [u for _, _, u in links[:limit]]


def _split_urls(text: str | None) -> list[str]:
    return re.findall(r"https?://\S+", text or "")


# Руководства по теме находки — когда у находки нет CVE (конфигурация,
# учётные данные, сервисы), это основной источник ссылок.
_NIST_PASSWORDS = "https://pages.nist.gov/800-63-3/sp800-63b.html"
_OWASP_AUTH = ("https://cheatsheetseries.owasp.org/cheatsheets/"
               "Authentication_Cheat_Sheet.html")
_TOPICS: list[tuple[re.Pattern, list[str]]] = [
    (re.compile(r"\bssh|sshd", re.IGNORECASE), ["https://man.openbsd.org/sshd_config"]),
    (re.compile(r"telnet|\bftp\b|svc:ftp|открытом виде|cleartext", re.IGNORECASE),
     [cwe_url("CWE-319")]),
    (re.compile(r"\btls\b|\bssl\b|шифр|cipher|certificate|сертификат", re.IGNORECASE),
     ["https://ssl-config.mozilla.org/"]),
    (re.compile(r"парол|password|AUTH-92", re.IGNORECASE), [_NIST_PASSWORDS]),
]


_GENERIC: dict[FindingType, str] = {
    FindingType.VULN: (
        "Установите обновление производителя, устраняющее уязвимость, или "
        "обновите ПО до поддерживаемой версии. Если обновление невозможно — "
        "ограничьте сетевой доступ к сервису (межсетевой экран, сегментация) "
        "и усильте мониторинг до устранения."
    ),
    FindingType.CONFIG: (
        "Приведите настройку в соответствие с требованием бенчмарка "
        "(CIS / ФСТЭК / ГОСТ), внесите изменение в эталонную конфигурацию и "
        "проверьте повторным сканированием."
    ),
    FindingType.CRED: (
        "Немедленно смените пароль учётной записи на стойкий (не менее 12 "
        "символов, не словарный), отключите учётные записи по умолчанию, "
        "включите блокировку после неудачных попыток и, где возможно, "
        "многофакторную аутентификацию."
    ),
    FindingType.INFO: (
        "Проверьте, что сервис необходим и доступен только из доверенных "
        "сегментов сети; отключите неиспользуемые сервисы."
    ),
}


def _clean(text: str | None) -> str | None:
    if text is None:
        return None
    text = text.strip()
    return text or None


class RemediationResolver:
    """Подбирает рекомендацию по устранению для находки."""

    def __init__(
        self,
        *,
        bdu: Mapping[str, BduLike] | None = None,
        nvd: Mapping[str, str] | None = None,
        benchmark: Mapping[str, str] | None = None,
        deadlines: Mapping[Severity, int | None] | None = None,
        nvd_refs: Mapping[str, Sequence[str]] | None = None,
        benchmark_refs: Mapping[str, Sequence[str]] | None = None,
    ):
        # bdu: bdu_id -> запись БДУ; nvd: cve_id -> текст мер;
        # benchmark: id правила -> текст исправления;
        # nvd_refs: cve_id -> ссылки NVD (feeds.nvd.NvdRecord.refs);
        # benchmark_refs: id правила -> ссылки на описание правила.
        self.bdu = {k.upper(): v for k, v in (bdu or {}).items()}
        self.nvd = {k.upper(): v for k, v in (nvd or {}).items()}
        self.benchmark = dict(benchmark or {})
        self.nvd_refs = {k.upper(): list(v) for k, v in (nvd_refs or {}).items()}
        self.benchmark_refs = {k: list(v) for k, v in (benchmark_refs or {}).items()}
        self.deadlines = dict(DEFAULT_DEADLINES if deadlines is None else deadlines)
        # обратный индекс CVE -> записи БДУ (одна CVE может быть в нескольких)
        self._bdu_by_cve: dict[str, list[BduLike]] = {}
        for rec in self.bdu.values():
            for cve in rec.cve_ids or []:
                self._bdu_by_cve.setdefault(cve.upper(), []).append(rec)

    def _cves(self, f: Finding) -> list[str]:
        ids = [c.upper() for c in f.cve_ids]
        if f.vuln_id and f.vuln_id.upper().startswith("CVE-") and f.vuln_id.upper() not in ids:
            ids.insert(0, f.vuln_id.upper())
        return ids

    def _bdus(self, f: Finding) -> list[str]:
        ids = [b.upper() for b in f.bdu_ids]
        if f.vuln_id and f.vuln_id.upper().startswith("BDU:") and f.vuln_id.upper() not in ids:
            ids.insert(0, f.vuln_id.upper())
        return ids

    def _bdu_records(self, f: Finding) -> list[BduLike]:
        recs = [self.bdu[b] for b in self._bdus(f) if b in self.bdu]
        if not recs:
            for cve in self._cves(f):
                recs.extend(self._bdu_by_cve.get(cve, []))
        return recs

    def references(self, f: Finding, bdu_records: Sequence[BduLike] | None = None
                   ) -> list[str]:
        """Ссылки на устранение для находки — отобранные и упорядоченные."""
        recs = self._bdu_records(f) if bdu_records is None else bdu_records
        cves = self._cves(f)
        urls: list[str] = []
        for rec in recs:
            urls.extend(_split_urls(getattr(rec, "refs", None)))
        for cve in cves:
            urls.extend(self.nvd_refs.get(cve, []))
        urls.extend(bdu_url(b) for b in self._bdus(f))
        urls.extend(bdu_url(r.bdu_id) for r in recs)
        urls.extend(nvd_url(c) for c in cves)
        for rec in recs:
            for cwe in re.findall(r"CWE-\d+", getattr(rec, "cwe", None) or ""):
                urls.append(cwe_url(cwe))
        vid = f.vuln_id or ""
        if vid:
            urls.extend(self.benchmark_refs.get(vid, []))
            if vid.lower().startswith("lynis:"):
                urls.append(lynis_url(vid.split(":", 1)[1]))
        if f.finding_type is FindingType.CRED:
            default = re.search(r"default|стандартн|по умолчанию|admin/admin", f.title, re.IGNORECASE)
            urls += [cwe_url("CWE-1392" if default else "CWE-521"), _NIST_PASSWORDS,
                     _OWASP_AUTH]
        if f.finding_type is not FindingType.VULN:
            topic = f"{vid} {f.title}"
            for rx, links in _TOPICS:
                if rx.search(topic):
                    urls.extend(links)
        return curate_refs(urls)

    def resolve(self, f: Finding) -> Remediation:
        deadline = self.deadlines.get(f.severity)
        if f.finding_type is FindingType.CRED:
            # подобранный пароль эксплуатируется сразу — срок как у критических
            deadline = self.deadlines.get(Severity.CRITICAL, deadline)
        bdu_records = self._bdu_records(f)
        refs = self.references(f, bdu_records)

        own = _clean(getattr(f, "remediation", None))
        if own:
            return Remediation(own, RemediationSource.FINDING, refs, deadline)

        for rec in bdu_records:
            text = _clean(rec.remediation)
            if text:
                return Remediation(text, RemediationSource.BDU, refs, deadline,
                                   fix_method=_clean(rec.fix_method))

        for cve in self._cves(f):
            text = _clean(self.nvd.get(cve))
            if text:
                return Remediation(text, RemediationSource.NVD, refs, deadline)

        if f.finding_type is FindingType.CONFIG and f.vuln_id:
            text = _clean(self.benchmark.get(f.vuln_id))
            if text:
                return Remediation(text, RemediationSource.BENCHMARK, refs, deadline)

        return Remediation(_GENERIC[f.finding_type], RemediationSource.GENERIC, refs, deadline)
