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

ОС хоста. Если известна ОС хоста (сводка инвентаризации по учётной записи
«ОС: …», строка сверки с бюллетенем вендора или host_results — `host_os`),
рекомендация и ссылки привязываются к ней: из текста БДУ остаётся фрагмент
«Для <ОС хоста>: …» (а не перечень мер для всех дистрибутивов), впереди —
действие по бюллетеню вендора («обновите пакет P до версии V»), бюллетени
других дистрибутивов из ссылок убираются, а бюллетень ОС хоста идёт первым.
ОС не известна — поведение прежнее.

Справочники передаются извне (из БД или фидов), поэтому модуль не зависит от
persistence и тестируется на фикстурах.
"""
from __future__ import annotations

import ipaddress
import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from enum import IntEnum, StrEnum
from typing import Protocol
from urllib.parse import urlsplit

from scanner.core.models import Finding, FindingType, Severity
from scanner.core.osfamily import classify, is_distro


class RemediationSource(StrEnum):
    FINDING = "finding"
    BDU = "bdu_fstec"
    VENDOR = "vendor_bulletin"   # бюллетень дистрибутива хоста (+ фрагмент БДУ для этой ОС)
    NVD = "nvd"
    BENCHMARK = "benchmark"
    GENERIC = "generic"


SOURCE_LABELS: dict[RemediationSource, str] = {
    RemediationSource.FINDING: "Модуль сканирования",
    RemediationSource.BDU: "БДУ ФСТЭК России",
    RemediationSource.VENDOR: "Бюллетень вендора ОС, БДУ ФСТЭК России",
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
    "hackerone.com", "ycombinator.com", "securelist.com", "securelist.ru",
    "content.kaspersky-labs.com", "opennet.ru", "xakep.ru", "bleepingcomputer.com",
    "thehackernews.com", "theregister.com", "securityweek.com",
)
_SKIP_PREFIXES = ("lists.", "bugzilla.", "bugs.", "blog.", "blogs.", "news.")

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
    "cve.omp.ru": "ОС Аврора", "cve.omprussia.ru": "ОС Аврора",
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

# Подпись бюллетеня ОС (_OS) -> семейство (scanner.core.osfamily)
_OS_FAMILY = {"Astra Linux": "astra", "РЕД ОС": "redos", "Альт": "alt",
              "ОС «Основа» (НППКТ)": "osnova", "РОСА": "rosa", "Ubuntu": "ubuntu",
              "Debian": "debian", "Debian LTS": "debian", "Red Hat": "rhel",
              "SUSE": "suse", "Gentoo": "gentoo",
              "ОС Аврора": "aurora"}
_WINDOWS_ONLY_VENDORS = frozenset({"Бюллетень Microsoft"})


@dataclass(frozen=True, slots=True)
class HostOs:
    """ОС хоста для привязки рекомендаций: семейство и выпуск (если известен)."""
    family: str                 # ключ scanner.core.osfamily (astra, redos, debian…)
    release: str | None = None  # 1.7 / 7.3 / 12 / 22.04

    @classmethod
    def of(cls, name: str | None, family: str | None = None) -> HostOs | None:
        """По названию ОС («Astra Linux 1.7_x86-64», «Ubuntu 22.04.4 LTS»).
        None — дистрибутив не определён (просто «Linux», Windows и т. п.)."""
        fam = family if is_distro(family) else classify(name)
        if not is_distro(fam):
            return None
        return cls(fam, _release(fam, name or ""))  # type: ignore[arg-type]

    def matches_release(self, text: str) -> bool | None:
        """Указан ли в тексте выпуск хоста: True/False; None — выпуска в тексте нет
        или он хосту не известен."""
        if not self.release:
            return None
        found = _release(self.family, text)
        if found is None:
            return None
        return found == self.release


_RELEASE_RX = {   # выпуск ищется рядом с названием ОС, а не любое число в строке
    "astra": re.compile(r"(?:astra|астра)\D{0,40}?(?<![\d.])(\d\.\d{1,2})(?![\d])",
                        re.IGNORECASE),
    "redos": re.compile(r"(?:red\s*os|ред\s*ос|redos)\D{0,20}?(?<![\d.])(7\.[1-3]|8|9)"
                        r"(?:\.\d+)?(?![\d])", re.IGNORECASE),
    "ubuntu": re.compile(r"ubuntu\D{0,12}?(?<![\d.])(\d{2}\.\d{2})(?![\d])", re.IGNORECASE),
    "debian": re.compile(r"\+deb(\d{1,2})u|debian(?:\s+gnu/linux)?\s+(\d{1,2})"
                         r"(?=[\s)(]|$)", re.IGNORECASE),
}
_DEBIAN_CODENAMES = {"buster": "10", "bullseye": "11", "bookworm": "12", "trixie": "13"}
_UBUNTU_CODENAMES = {"focal": "20.04", "jammy": "22.04", "noble": "24.04"}


def _release(family: str, text: str) -> str | None:
    low = text.lower()
    if family == "debian":
        for code, num in _DEBIAN_CODENAMES.items():
            if code in low:
                return num
    if family == "ubuntu":
        for code, num in _UBUNTU_CODENAMES.items():
            if code in low:
                return num
    # astra-linux-se17-bulletin… -> 1.7
    if family == "astra" and (m := re.search(r"(?:linux-|\d)se(\d)(\d)(?![\d])", low)):
        return f"{m.group(1)}.{m.group(2)}"
    rx = _RELEASE_RX.get(family)
    if rx is None:
        return None
    m = rx.search(text)
    if m is None:
        return None
    return next(g for g in m.groups() if g)


def _link_fits_host(link: RefLink, os: HostOs) -> bool:
    """Ссылка подходит ОС хоста: не бюллетень другого дистрибутива/выпуска."""
    if link.label in _WINDOWS_ONLY_VENDORS:
        return False
    if link.kind is not RefKind.OS:
        return True
    fam = _OS_FAMILY.get(link.label.removeprefix("Бюллетень "))
    if fam != os.family:
        return False
    if os.family == "astra" and re.search(r"astra-linux-se\d", link.url):
        return os.matches_release(link.url) is not False
    if os.family == "redos" and (m := re.search(r"/redos/([\d.]+)[a-z]?/", link.url)):
        return os.matches_release(f"РЕД ОС {m.group(1)}") is not False
    return True


def curate_refs(urls: Iterable[str], limit: int = MAX_REFERENCES,
                host_os: HostOs | None = None) -> list[str]:
    """Убирает бесполезные и повторные ссылки, упорядочивает по пользе.

    host_os — ОС хоста: бюллетени других дистрибутивов (и выпусков) убираются,
    бюллетень ОС хоста ставится первым.
    """
    seen: set[str] = set()
    links: list[tuple[int, int, str]] = []
    for i, u in enumerate(urls):
        link = describe_ref(u)
        if link is None:
            continue
        if host_os is not None and not _link_fits_host(link, host_os):
            continue
        key = link.url.rstrip("/").lower().replace("http://", "https://")
        if key in seen:
            continue
        seen.add(key)
        order = -1 if host_os is not None and link.kind is RefKind.OS else int(link.kind)
        links.append((order, i, link.url))
    links.sort()
    return [u for _, _, u in links[:limit]]


# --- привязка текста рекомендации к ОС хоста ---------------------------------

# «Для <кого>: …» — так БДУ перечисляет меры по продуктам и дистрибутивам.
_FOR_RX = re.compile(r"(?:(?<=\s)|^)Для\s+([^:\n]{2,160}?):(?=\s)")
_INTRO_TAIL = re.compile(r"\s*(Использование рекомендаций(?: производителя)?|"
                         r"Установка обновлений из доверенных источников)\s*[:.]?\s*$",
                         re.IGNORECASE)
_EXTRA_OS_RX = re.compile(r"осон|основа|onyx|\bальт\b|alt linux|роса|rosa|astra|астра|"
                          r"windows|microsoft|red hat|redhat|suse|novell|fedora|centos|oracle linux|"
                          r"\bос\b", re.IGNORECASE)


def _segment_family(header: str) -> str | None:
    fam = classify(header)
    if fam in (None, "other", "linux"):
        if re.search(r"астра", header, re.IGNORECASE):
            return "astra"
        if re.search(r"осон|основа|onyx", header, re.IGNORECASE):
            return "osnova"
        return "os" if _EXTRA_OS_RX.search(header) else None
    return fam


def _body_releases(os: HostOs, body: str) -> set[bool]:
    """Совпадают ли с выпуском хоста выпуски, на которые ссылается тело фрагмента
    (бюллетени Astra «se17», репозиторий РЕД ОС «/redos/7.3/»)."""
    if os.family == "astra":
        refs = [f"astra {a}.{b}" for a, b in re.findall(r"(?:linux-|\d)se(\d)(\d)(?!\d)",
                                                          body.lower())]
    elif os.family == "redos":
        refs = [f"РЕД ОС {r}" for r in re.findall(r"/redos/([\d.]+)[a-z]?/", body)]
    else:
        return set()
    return {os.matches_release(r) for r in refs} - {None}  # type: ignore[return-value]


def _tokens(text: str) -> set[str]:
    return {w.lower() for w in re.findall(r"[A-Za-z][A-Za-z0-9_+-]{2,}", text)}


def localize_bdu_text(text: str, os: HostOs, context: str = "") -> str | None:
    """Из текста мер БДУ — вводная часть и фрагменты «Для <ОС хоста>: …».

    Фрагменты для ОС хоста отбираются по выпуску (заголовок «… 1.7» или ссылки
    в теле на бюллетень/репозиторий выпуска). Если фрагментов для ОС хоста нет —
    вводная часть и фрагменты производителя ПО, относящиеся к этой находке
    (название из заголовка встречается в context: название находки, пакет).
    None — текст не разбит на фрагменты «Для …:», менять нечего.
    """
    marks = list(_FOR_RX.finditer(text))
    if not marks:
        return None
    intro = _INTRO_TAIL.sub("", text[:marks[0].start()]).strip()
    segments = []
    for m, nxt in zip(marks, [*marks[1:], None], strict=True):
        # фрагмент — до пустой строки: дальше в БДУ идёт уже другой абзац
        body = text[m.end():nxt.start() if nxt else len(text)].strip().split("\n\n")[0]
        segments.append((m.group(1).strip(), _segment_family(m.group(1)), body))
    own = [s for s in segments if s[1] == os.family]
    rated = []
    for h, fam, body in own:
        head = os.matches_release(h)
        if head is None:
            found = _body_releases(os, body)
            head = True if True in found else (False if found else None)
        rated.append(((h, fam, body), head))
    exact = [s for s, ok in rated if ok is True]
    own = exact or [s for s, ok in rated if ok is None]
    ctx = _tokens(context)
    chosen = own or [s for s in segments if s[1] is None and _tokens(s[0]) & ctx]
    parts = [intro] if intro else []
    parts += [f"Для {h}: {b}" for h, _, b in chosen if b]
    return "\n".join(parts) or None


# Строка сверки с бюллетенем дистрибутива (auth_inventory._vendor_line)
_VENDOR_FIXED = re.compile(
    r"Бюллетень (?P<src>[^:(\n]+?)(?: \((?P<adv>[^)]+)\))?: (?P<cve>\S+) исправлена в версии "
    r"(?P<ver>\S+) \(пакет (?P<pkg>[^)]+)\)")
_VENDOR_NOFIX = re.compile(
    r"Бюллетень (?P<src>[^:(\n]+?)(?: \((?P<adv>[^)]+)\))?: исправления (?P<cve>\S+) для "
    r"пакета (?P<pkg>\S+) у вендора пока нет")


def vendor_action(evidence: str | None) -> tuple[str, str] | None:
    """(действие, «Debian bookworm») по строке сверки с бюллетенем в evidence."""
    if not evidence:
        return None
    fixed = list(_VENDOR_FIXED.finditer(evidence))
    if fixed:
        by_pkg: dict[str, re.Match] = {}
        for m in fixed:
            by_pkg.setdefault(m["pkg"], m)
        src = fixed[0]["src"].strip()
        what = "; ".join(f"{p} — до версии {m['ver']} или выше" for p, m in by_pkg.items())
        advs = sorted({m["adv"] for m in fixed if m["adv"]})
        tail = f" (бюллетень {', '.join(advs)})" if advs else ""
        return (f"Обновите пакет {what} из репозитория {src}{tail}.", src)
    if nofix := _VENDOR_NOFIX.search(evidence):
        src = nofix["src"].strip()
        text = (f"Исправления {nofix['cve']} для пакета {nofix['pkg']} в бюллетенях {src} "
                "пока нет: до выхода обновления примените компенсирующие меры, ограничьте "
                "доступ к уязвимому компоненту и отслеживайте бюллетени вендора.")
        return (text, src)
    return None


def _norm_host(host: object) -> str:
    text = str(host).split("/")[0]
    try:
        return str(ipaddress.ip_address(text))
    except ValueError:
        return text


def host_os_from_findings(findings: Iterable[Finding]) -> dict[str, str]:
    """ОС хостов из находок прогона: строка «ОС: …» сводки инвентаризации по
    учётной записи, иначе — источник строки сверки с бюллетенем вендора."""
    out: dict[str, str] = {}
    fallback: dict[str, str] = {}
    for f in findings:
        ev = f.evidence or ""
        if (f.vuln_id or "").startswith(("INFO:auth-inventory", "INFO:win-inventory")):
            m = re.search(r"^ОС: (.+)$", ev, re.MULTILINE)
            if m and "не определена" not in m.group(1):
                out[_norm_host(f.host)] = m.group(1).strip()
        elif (va := vendor_action(ev)) is not None:
            fallback.setdefault(_norm_host(f.host), va[1])
    return {**fallback, **out}


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
        host_os: Mapping[str, str] | None = None,
    ):
        # bdu: bdu_id -> запись БДУ; nvd: cve_id -> текст мер;
        # benchmark: id правила -> текст исправления;
        # nvd_refs: cve_id -> ссылки NVD (feeds.nvd.NvdRecord.refs);
        # benchmark_refs: id правила -> ссылки на описание правила;
        # host_os: адрес -> название ОС («Astra Linux 1.7», «Ubuntu 22.04.4 LTS»).
        self.bdu = {k.upper(): v for k, v in (bdu or {}).items()}
        self.nvd = {k.upper(): v for k, v in (nvd or {}).items()}
        self.benchmark = dict(benchmark or {})
        self.nvd_refs = {k.upper(): list(v) for k, v in (nvd_refs or {}).items()}
        self.benchmark_refs = {k: list(v) for k, v in (benchmark_refs or {}).items()}
        self.deadlines = dict(DEFAULT_DEADLINES if deadlines is None else deadlines)
        self.host_os: dict[str, HostOs] = {}
        self.add_host_os(host_os or {})
        # обратный индекс CVE -> записи БДУ (одна CVE может быть в нескольких)
        self._bdu_by_cve: dict[str, list[BduLike]] = {}
        for rec in self.bdu.values():
            for cve in rec.cve_ids or []:
                self._bdu_by_cve.setdefault(cve.upper(), []).append(rec)

    def add_host_os(self, names: Mapping[str, str], *, override: bool = True) -> None:
        """Добавить ОС хостов (адрес -> название ОС). override=False — не менять
        уже известные (например, ОС из прогона точнее инвентаря договора)."""
        for host, name in names.items():
            key = _norm_host(host)
            if not override and key in self.host_os:
                continue
            info = HostOs.of(name)
            if info is not None:
                self.host_os[key] = info

    def os_of(self, f: Finding) -> HostOs | None:
        """ОС хоста находки: по известным ОС хостов, иначе — по строке сверки
        с бюллетенем вендора в самой находке."""
        known = self.host_os.get(_norm_host(f.host))
        if known is not None:
            return known
        va = vendor_action(f.evidence)
        return HostOs.of(va[1]) if va else None

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
        os = self.os_of(f) if f.finding_type is FindingType.VULN else None
        urls: list[str] = []
        if os is not None:
            urls.extend(_os_cve_urls(os, cves, f.evidence))
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
        if f.finding_type is FindingType.CONFIG:
            # ссылки правила бенчмарка (config_audit пишет их в evidence)
            urls.extend(u.rstrip(";,.)") for u in _split_urls(f.evidence))
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
        return curate_refs(urls, host_os=os)

    def resolve(self, f: Finding) -> Remediation:
        deadline = self.deadlines.get(f.severity)
        if f.finding_type is FindingType.CRED:
            # подобранный пароль эксплуатируется сразу — срок как у критических
            deadline = self.deadlines.get(Severity.CRITICAL, deadline)
        bdu_records = self._bdu_records(f)
        refs = self.references(f, bdu_records)

        own = _clean(getattr(f, "remediation", None))
        if own:
            # у находок аудита конфигураций это fixtext самого правила бенчмарка
            source = (RemediationSource.BENCHMARK if f.finding_type is FindingType.CONFIG
                      else RemediationSource.FINDING)
            return Remediation(own, source, refs, deadline)

        os = self.os_of(f) if f.finding_type is FindingType.VULN else None
        action = vendor_action(f.evidence) if f.finding_type is FindingType.VULN else None
        for rec in bdu_records:
            text = _clean(rec.remediation)
            if text:
                if os is not None:
                    ctx = f"{f.title} {(f.evidence or '').splitlines()[0] if f.evidence else ''}"
                    text = localize_bdu_text(text, os, ctx) or text
                if action is not None:
                    return Remediation(f"{action[0]}\n{text}", RemediationSource.VENDOR,
                                       refs, deadline, fix_method=_clean(rec.fix_method))
                return Remediation(text, RemediationSource.BDU, refs, deadline,
                                   fix_method=_clean(rec.fix_method))
        if action is not None:
            return Remediation(action[0], RemediationSource.VENDOR, refs, deadline)

        for cve in self._cves(f):
            text = _clean(self.nvd.get(cve))
            if text:
                return Remediation(text, RemediationSource.NVD, refs, deadline)

        if f.finding_type is FindingType.CONFIG and f.vuln_id:
            text = _clean(self.benchmark.get(f.vuln_id))
            if text:
                return Remediation(text, RemediationSource.BENCHMARK, refs, deadline)

        return Remediation(_GENERIC[f.finding_type], RemediationSource.GENERIC, refs, deadline)


def _os_cve_urls(os: HostOs, cves: Sequence[str], evidence: str | None) -> list[str]:
    """Страницы трекеров дистрибутива хоста по CVE находки (для Debian и Ubuntu
    есть устойчивый адрес на CVE; Astra/РЕД ОС — из ссылок записи БДУ)."""
    urls: list[str] = []
    for cve in cves:
        if os.family == "debian":
            urls.append(f"https://security-tracker.debian.org/tracker/{cve}")
        elif os.family == "ubuntu":
            urls.append(f"https://ubuntu.com/security/{cve}")
    for usn in sorted(set(re.findall(r"\bUSN-\d+-\d+\b", evidence or ""))):
        urls.insert(0, f"https://ubuntu.com/security/notices/{usn}")
    for dsa in sorted(set(re.findall(r"\b(?:DSA|DLA)-\d+-\d+\b", evidence or ""))):
        urls.insert(0, f"https://security-tracker.debian.org/tracker/{dsa}")
    return urls
