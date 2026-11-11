"""План исправлений для администраторов: что сделать, на каких хостах и как.

Вкладка «Находки» отвечает администратору не «что нашли», а «что сделать»:
находки прогона собираются в действия исправления. Одно действие — например,
«обновить пакет openssl до 3.0.15-1~deb12u1 на Debian 12» — обычно закрывает
сразу несколько CVE на нескольких хостах.

Как находки собираются в действия:

* **package** — пакет, для которого бюллетень дистрибутива хоста называет
  исправленную версию (строка сверки auth_inventory). Группа — ОС и выпуск
  хоста + пакет вендора; версия «до» — наибольшая из исправленных версий по
  CVE группы (сравнение по правилам dpkg/rpm/apk). Команды — для менеджера
  пакетов хоста (apt-get / dnf / yum / zypper / apk), проверка — запрос
  установленной версии;
* **package_nofix** — бюллетень вендора говорит, что исправления пока нет:
  компенсирующие меры и наблюдение за бюллетенем;
* **package_upgrade** — уязвимость пакета найдена по версии апстрима, а
  данных вендора нет: обновить пакет до последней версии из репозитория ОС;
* **kernel** — уязвимости работающего ядра и «обновлённое ядро не загружено»:
  обновление ядра и перезагрузка (или только перезагрузка);
* **software** — ПО, определённое по баннеру сервиса (nmap -sV / Nuclei):
  обновить продукт до версии производителя с исправлением;
* **config** / **cred** / **vuln** / **other** — правило аудита конфигурации,
  найденная учётная запись, уязвимость без известного ПО: текст исправления
  правила (fixtext) или рекомендация БДУ/NVD, по одной группе на правило.

Команды строятся из данных, собранных на сканируемых хостах, поэтому имя
пакета попадает в команду только если оно похоже на имя пакета (буквы, цифры
и `.+_:~@-`); иначе команды не показываются, остаётся текстовое действие.
Ссылки на эксплойты не выводятся — только меры устранения (remediation.py).

Модуль не зависит от БД: на вход — находки с id, резолвер рекомендаций,
менеджеры пакетов хостов и приоритеты (R6).
"""
from __future__ import annotations

import hashlib
import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field

from scanner.core.models import Finding, FindingType, ServiceInfo, Severity
from scanner.core.osfamily import family_label
from scanner.core.software import software_of
from scanner.reporting.remediation import (
    HostOs,
    RemediationResolver,
    _norm_host,
    curate_refs,
)
from scanner.reporting.risk import RiskAssessment

KINDS = ("package", "package_nofix", "package_upgrade", "kernel", "software",
         "config", "cred", "vuln", "other")

KIND_LABELS = {
    "package": "Обновление пакета",
    "package_nofix": "Исправления пока нет",
    "package_upgrade": "Обновление пакета",
    "kernel": "Ядро Linux",
    "software": "Обновление ПО",
    "config": "Настройка",
    "cred": "Учётные записи",
    "vuln": "Уязвимость",
    "other": "Прочее",
}

_SEV_RANK = {s: i for i, s in enumerate(
    (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO))}

# Имя пакета, которое можно подставить в команду (без кавычек и подстановок).
_SAFE_PKG = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.+_:~@-]{0,127}$")

# Первая строка evidence находки пакета: «Пакет a, b (1:9.2p1-2+deb12u3) → OpenSSH 9.2p1»
_PKG_HEAD = re.compile(r"^Пакет (?P<names>.+?) \((?P<ver>[^()]*)\) → ")
# Строки сверки с бюллетенем (auth_inventory._vendor_line / _kernel_line)
_VENDOR_FIXED = re.compile(
    r"Бюллетень (?P<src>[^:(\n]+?)(?: \((?P<adv>[^)]+)\))?: (?P<cve>\S+) исправлена в версии "
    r"(?P<ver>\S+) \(пакет (?P<pkg>[^)]+)\); установлена (?P<inst>\S+)")
_VENDOR_NOFIX = re.compile(
    r"Бюллетень (?P<src>[^:(\n]+?)(?: \((?P<adv>[^)]+)\))?: исправления (?P<cve>\S+) для "
    r"пакета (?P<pkg>\S+) у вендора пока нет")
_KERNEL_FIXED = re.compile(
    r"Бюллетень (?P<src>[^:(\n]+?)(?: \((?P<adv>[^)]+)\))?: (?P<cve>\S+) исправлена в ядре "
    r"версии (?P<ver>\S+);")
_KERNEL_LABEL = "Ядро Linux"
_REBOOT_ONLY = "уже установлено, но хост не перезагружен"
_PENDING_RX = re.compile(r"Установлено более новое ядро (?P<rel>\S+)")
_RUNNING_RX = re.compile(r"→ Ядро Linux (?P<rel>\S+)")
_LIB_RX = re.compile(r"^(lib|openssl|glibc|gnutls|nss|zlib)", re.IGNORECASE)

# Семейства ОС -> менеджер пакетов (если пакеты хоста не собраны).
_DPKG = frozenset({"debian", "ubuntu", "astra", "osnova"})
_APK = frozenset({"alpine"})
_ADV_LABEL_FAMILY = {"Debian": "debian", "Ubuntu": "ubuntu", "Astra Linux": "astra",
                     "РЕД ОС": "redos", "Альт": "alt", "Alpine Linux": "alpine",
                     "Red Hat Enterprise Linux": "rhel"}


# --- структура плана ---------------------------------------------------------

@dataclass(slots=True)
class FixFinding:
    """Находка внутри действия — для отметки ложного срабатывания из карточки."""
    id: int
    label: str          # CVE / правило
    severity: Severity

    def to_dict(self) -> dict:
        return {"id": self.id, "label": self.label, "severity": str(self.severity)}


@dataclass(slots=True)
class FixHost:
    host: str
    installed: str | None = None      # установленная версия пакета / ядра / ПО
    note: str | None = None           # особенность хоста («только перезагрузка»)
    ports: list[int] = field(default_factory=list)
    findings: list[FixFinding] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {"host": self.host, "installed": self.installed, "note": self.note,
                "ports": sorted(self.ports),
                "findings": [f.to_dict() for f in self.findings]}


@dataclass(slots=True)
class FixTask:
    key: str
    kind: str
    title: str
    os: str | None = None             # «Debian 12», «РЕД ОС 7.3»
    os_family: str | None = None
    manager: str | None = None        # dpkg | rpm | apk
    packages: list[str] = field(default_factory=list)
    fixed_version: str | None = None
    software: str | None = None
    steps: list[str] = field(default_factory=list)
    commands: list[str] = field(default_factory=list)
    verify: list[str] = field(default_factory=list)
    reboot: bool = False
    details: str | None = None        # текст мер БДУ / правила бенчмарка
    details_source: str | None = None
    severity: Severity = Severity.INFO
    priority: RiskAssessment | None = None
    cves: list[str] = field(default_factory=list)
    bdu_ids: list[str] = field(default_factory=list)
    advisories: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    hosts: list[FixHost] = field(default_factory=list)

    @property
    def findings(self) -> int:
        return sum(len(h.findings) for h in self.hosts)

    def search_text(self) -> str:
        return " ".join([self.title, self.os or "", self.software or "", *self.packages,
                         *self.cves, *self.bdu_ids, *self.advisories,
                         *(h.host for h in self.hosts)]).lower()

    def to_dict(self) -> dict:
        p = self.priority
        return {
            "key": self.key, "kind": self.kind, "kind_label": KIND_LABELS[self.kind],
            "title": self.title, "os": self.os, "os_family": self.os_family,
            "manager": self.manager, "packages": list(self.packages),
            "fixed_version": self.fixed_version, "software": self.software,
            "steps": list(self.steps), "commands": list(self.commands),
            "verify": list(self.verify), "reboot": self.reboot,
            "details": self.details, "details_source": self.details_source,
            "severity": str(self.severity),
            "priority": None if p is None else {"score": p.score, "label": p.label,
                                                "label_ru": p.label_ru, "rank": p.rank},
            "cves": list(self.cves), "bdu_ids": list(self.bdu_ids),
            "advisories": list(self.advisories), "references": list(self.references),
            "hosts": [h.to_dict() for h in self.hosts],
            "host_count": len(self.hosts), "finding_count": self.findings,
        }


# --- команды ---------------------------------------------------------------------

def os_label(os: HostOs | None) -> str | None:
    if os is None:
        return None
    return " ".join(x for x in (family_label(os.family), os.release) if x)


def _manager_of(os: HostOs | None, known: str | None) -> str | None:
    if known:
        return known
    if os is None:
        return None
    if os.family in _DPKG:
        return "dpkg"
    if os.family in _APK:
        return "apk"
    return "rpm"


def _rpm_tool(os: HostOs | None) -> str:
    """dnf на современных RPM-дистрибутивах, yum — на 7-й ветке RHEL и РЕД ОС 7.x."""
    if os is None:
        return "dnf"
    rel = os.release or ""
    if os.family in ("redos",) and rel.startswith("7"):
        return "yum"
    if os.family in ("rhel", "centos", "oracle") and rel.split(".")[0] in ("6", "7"):
        return "yum"
    return "dnf"


def safe_packages(names: Iterable[str]) -> list[str] | None:
    """Имена пакетов для команды; None — среди них есть что-то, кроме имени пакета."""
    out = list(dict.fromkeys(n.strip() for n in names if n.strip()))
    if not out or not all(_SAFE_PKG.match(n) for n in out):
        return None
    return out


def package_commands(os: HostOs | None, manager: str | None,
                     packages: Sequence[str]) -> tuple[list[str], list[str]]:
    """(команды обновления, команды проверки) для пакетов на ОС хоста."""
    names = safe_packages(packages)
    if names is None or manager is None:
        return [], []
    pk = " ".join(names)
    fam = os.family if os else None
    if manager == "dpkg":
        return (["sudo apt-get update",
                 f"sudo apt-get install --only-upgrade -y {pk}"],
                [f"dpkg-query -W -f='${{Package}} ${{Version}}\\n' {pk}"])
    if manager == "apk":
        return (["apk update", f"apk upgrade {pk}"], [f"apk info -v {pk}"])
    if manager == "rpm":
        if fam == "alt":
            cmds = ["apt-get update", f"apt-get install {pk}"]
        elif fam == "suse":
            cmds = ["sudo zypper refresh", f"sudo zypper update -y {pk}"]
        else:
            tool = _rpm_tool(os)
            cmds = ([f"sudo yum update -y {pk}"] if tool == "yum"
                    else [f"sudo dnf upgrade -y --refresh {pk}"])
        return cmds, [f"rpm -q {pk}"]
    return [], []


def kernel_commands(os: HostOs | None, manager: str | None,
                    reboot_only: bool) -> tuple[list[str], list[str]]:
    if reboot_only:
        return ["sudo reboot"], ["uname -r"]
    fam = os.family if os else None
    if manager == "dpkg":
        # новое ядро — обычно новый пакет (новый ABI), его ставит метапакет ядра;
        # --with-new-pkgs разрешает установку новых пакетов при обновлении
        cmds = ["sudo apt-get update", "sudo apt-get upgrade --with-new-pkgs -y"]
    elif manager == "apk":
        cmds = ["apk update", "apk upgrade linux-lts"]
    elif fam == "alt":
        cmds = ["update-kernel"]
    elif fam == "suse":
        cmds = ["sudo zypper refresh", "sudo zypper update -y kernel-default"]
    elif manager == "rpm":
        tool = _rpm_tool(os)
        cmds = (["sudo yum update -y kernel"] if tool == "yum"
                else ["sudo dnf upgrade -y --refresh kernel"])
    else:
        return [], []
    return [*cmds, "sudo reboot"], ["uname -r"]


def _restart_hint(manager: str | None, packages: Sequence[str]) -> str | None:
    if not any(_LIB_RX.match(p) for p in packages):
        return None
    tool = ("needrestart" if manager == "dpkg" else
            "dnf needs-restarting -s" if manager == "rpm" else None)
    tail = f" (список покажет `{tool}`)" if tool else ""
    return ("Перезапустите службы, которые используют обновлённую библиотеку"
            f"{tail}, или перезагрузите хост в окно обслуживания.")


# --- разбор находок --------------------------------------------------------------

def _max_version(manager: str | None, versions: Iterable[str]) -> str | None:
    from scanner.feeds.vercmp import compare

    best: str | None = None
    for v in versions:
        if best is None:
            best = v
            continue
        try:
            if manager and compare(manager, v, best) > 0:
                best = v
        except Exception:                       # noqa: BLE001 — нестандартная версия
            best = max(best, v)
    return best


def _head_packages(evidence: str | None) -> tuple[list[str], str | None]:
    """Бинарные пакеты и установленная версия из первой строки evidence."""
    first = (evidence or "").split("\n", 1)[0].strip()
    m = _PKG_HEAD.match(first)
    if not m:
        return [], None
    names = [n.strip() for n in m["names"].split(",") if n.strip()]
    return names, m["ver"].strip() or None


def _label(f: Finding) -> str:
    if f.cve_ids:
        return f.cve_ids[0]
    return f.vuln_id or f.title[:60]


def _key(*parts: object) -> str:
    raw = "\x1f".join("" if p is None else str(p) for p in parts)
    return hashlib.sha1(raw.encode()).hexdigest()[:16]


def _is_kernel(f: Finding, sw_name: str | None) -> bool:
    return f.vuln_id == "KERNEL-REBOOT-PENDING" or (
        f.finding_type is FindingType.VULN and (sw_name or "").startswith(_KERNEL_LABEL))


@dataclass(slots=True)
class _Group:
    kind: str
    os: HostOs | None
    items: list[tuple[int, Finding]] = field(default_factory=list)
    ident: str | None = None          # пакет вендора / ПО / правило
    installed: dict[str, str | None] = field(default_factory=dict)


def build_fix_plan(
    findings: Iterable[tuple[int, Finding]],
    *,
    resolver: RemediationResolver | None = None,
    managers: Mapping[str, str] | None = None,
    services: Mapping[tuple[str, int], ServiceInfo] | None = None,
    priorities: Mapping[str, RiskAssessment] | None = None,
    include_info: bool = False,
) -> list[FixTask]:
    """Действия исправления по находкам прогона (без ложных срабатываний —
    их отфильтровывает вызывающий код), от важных к менее важным."""
    resolver = resolver or RemediationResolver()
    managers = {_norm_host(h): m for h, m in (managers or {}).items()}
    priorities = priorities or {}
    groups: dict[tuple, _Group] = {}
    svc = dict(services or {})

    def add(key: tuple, kind: str, os: HostOs | None, item: tuple[int, Finding],
            ident: str | None = None) -> None:
        g = groups.setdefault(key, _Group(kind, os, ident=ident))
        g.items.append(item)

    for fid, f in findings:
        if f.severity is Severity.INFO and not include_info:
            continue
        sw = software_of(f, svc)
        os = resolver.os_of(f)
        os_key = (os.family, os.release) if os else None
        ev = f.evidence or ""
        if _is_kernel(f, sw.name if sw else None):
            add(("kernel", os_key), "kernel", os, (fid, f))
            continue
        if f.finding_type is FindingType.VULN:
            fixed = list(_VENDOR_FIXED.finditer(ev))
            if fixed:
                pkg = ", ".join(sorted({m["pkg"] for m in fixed}))
                add(("package", os_key, pkg), "package", os, (fid, f), pkg)
                continue
            if nofix := _VENDOR_NOFIX.search(ev):
                add(("package_nofix", os_key, nofix["pkg"]), "package_nofix", os, (fid, f),
                    nofix["pkg"])
                continue
            if sw is not None and sw.source == "package":
                names, _ = _head_packages(ev)
                ident = ", ".join(names) or sw.name
                add(("package_upgrade", os_key, ident), "package_upgrade", os, (fid, f), ident)
                continue
            if sw is not None:
                add(("software", sw.name.lower()), "software", None, (fid, f), sw.name)
                groups[("software", sw.name.lower())].installed.setdefault(
                    _norm_host(f.host), sw.version)
                continue
            add(("vuln", (f.vuln_id or f.title).upper()), "vuln", None, (fid, f),
                f.vuln_id or f.title)
            continue
        kind = {FindingType.CONFIG: "config", FindingType.CRED: "cred"}.get(
            f.finding_type, "other")
        add((kind, f.vuln_id or f.title), kind, None, (fid, f), f.vuln_id or f.title)

    tasks = [_task(key, g, resolver, managers, priorities)
             for key, g in groups.items()]
    tasks.sort(key=lambda t: (-(t.priority.score if t.priority else -1.0),
                              _SEV_RANK[t.severity], -len(t.hosts), t.title))
    return tasks


def _hosts(items: Sequence[tuple[int, Finding]],
           installed: Mapping[str, str | None] | None = None,
           notes: Mapping[str, str | None] | None = None) -> list[FixHost]:
    import ipaddress

    by: dict[str, FixHost] = {}
    for fid, f in items:
        h = _norm_host(f.host)
        fh = by.setdefault(h, FixHost(h, (installed or {}).get(h), (notes or {}).get(h)))
        if f.port is not None and f.port not in fh.ports:
            fh.ports.append(f.port)
        fh.findings.append(FixFinding(fid, _label(f), f.severity))
    for fh in by.values():
        fh.findings.sort(key=lambda x: (_SEV_RANK[x.severity], x.label))

    def order(h: str) -> tuple:
        try:
            a = ipaddress.ip_address(h)
            return (0, a.version, int(a))
        except ValueError:
            return (1, 0, h)
    return [by[h] for h in sorted(by, key=order)]


def _task(key: tuple, g: _Group, resolver: RemediationResolver,
          managers: Mapping[str, str],
          priorities: Mapping[str, RiskAssessment]) -> FixTask:
    fs = [f for _, f in g.items]
    os = g.os
    host_mgr = next((managers[_norm_host(f.host)] for f in fs
                     if _norm_host(f.host) in managers), None)
    manager = _manager_of(os, host_mgr)
    cves = sorted({c.upper() for f in fs for c in f.cve_ids}
                  | {f.vuln_id.upper() for f in fs
                     if f.vuln_id and f.vuln_id.upper().startswith("CVE-")})
    bdus = sorted({b.upper() for f in fs for b in f.bdu_ids})
    t = FixTask(
        key=_key(*key), kind=g.kind, title="", os=os_label(os),
        os_family=os.family if os else None, manager=manager,
        severity=min((f.severity for f in fs), key=_SEV_RANK.__getitem__),
        cves=cves, bdu_ids=bdus)
    scored = [priorities[f.dedup_key()] for f in fs if f.dedup_key() in priorities]
    if scored:
        t.priority = max(scored, key=lambda a: (a.score, -(a.rank or 0)))
    refs: list[str] = []
    for f in fs[:25]:                        # ссылки — по первым находкам группы
        refs.extend(resolver.references(f))
    t.references = curate_refs(refs, limit=8, host_os=os)
    fill = {"package": _fill_package, "package_nofix": _fill_nofix,
            "package_upgrade": _fill_upgrade, "kernel": _fill_kernel,
            "software": _fill_software}.get(g.kind, _fill_generic)
    fill(t, g, resolver)
    return t


def _scope(t: FixTask) -> str:
    return f" ({t.os})" if t.os else ""


def _rescan_step() -> str:
    return "Запустите повторный прогон по этим хостам — исправленные находки закроются."


def _fill_package(t: FixTask, g: _Group, resolver: RemediationResolver) -> None:
    installed: dict[str, str | None] = {}
    names: list[str] = []
    fixed_versions: list[str] = []
    advisories: set[str] = set()
    src = None
    for _, f in g.items:
        heads, ver = _head_packages(f.evidence)
        names.extend(heads)
        for m in _VENDOR_FIXED.finditer(f.evidence or ""):
            fixed_versions.append(m["ver"])
            src = src or m["src"].strip()
            installed.setdefault(_norm_host(f.host), ver or m["inst"])
            if m["adv"]:
                advisories.update(a.strip() for a in m["adv"].split(","))
    pkgs = list(dict.fromkeys(names)) or [p.strip() for p in (g.ident or "").split(",")]
    t.packages = pkgs
    t.fixed_version = _max_version(t.manager, fixed_versions)
    t.advisories = sorted(advisories)
    t.hosts = _hosts(g.items, installed)
    t.title = f"Обновить {', '.join(pkgs[:3])}{' …' if len(pkgs) > 3 else ''}" + (
        f" до {t.fixed_version}" if t.fixed_version else "")
    repo = src or t.os or "дистрибутива"
    adv = f" (бюллетень {', '.join(t.advisories[:4])})" if t.advisories else ""
    t.steps = [(f"Обновите пакет{'ы' if len(pkgs) > 1 else ''} {', '.join(pkgs)} до версии "
               f"не ниже {t.fixed_version} из репозитория {repo}{adv}.")]
    if hint := _restart_hint(t.manager, pkgs):
        t.steps.append(hint)
    t.steps.append(_rescan_step())
    t.commands, t.verify = package_commands(g.os, t.manager, pkgs)


def _fill_nofix(t: FixTask, g: _Group, resolver: RemediationResolver) -> None:
    names: list[str] = []
    installed: dict[str, str | None] = {}
    src = None
    for _, f in g.items:
        heads, ver = _head_packages(f.evidence)
        names.extend(heads)
        installed.setdefault(_norm_host(f.host), ver)
        if m := _VENDOR_NOFIX.search(f.evidence or ""):
            src = src or m["src"].strip()
    t.packages = list(dict.fromkeys(names)) or [g.ident or ""]
    t.hosts = _hosts(g.items, installed)
    t.title = f"Нет исправления: {g.ident}{_scope(t)}"
    t.steps = [
        f"В бюллетенях {src or 'вендора'} исправления для пакета {g.ident} пока нет.",
        ("До выхода обновления ограничьте доступ к уязвимому компоненту (межсетевой экран, "
        "отключение неиспользуемой функции или службы) и примените меры из описания ниже."),
        ("Отслеживайте бюллетень вендора: когда исправление выйдет, это действие сменится "
        "на обновление пакета в следующем прогоне."),
    ]
    _details(t, g, resolver)


def _fill_upgrade(t: FixTask, g: _Group, resolver: RemediationResolver) -> None:
    names: list[str] = []
    installed: dict[str, str | None] = {}
    for _, f in g.items:
        heads, ver = _head_packages(f.evidence)
        names.extend(heads)
        installed.setdefault(_norm_host(f.host), ver)
    pkgs = list(dict.fromkeys(names)) or [g.ident or ""]
    t.packages = pkgs
    t.hosts = _hosts(g.items, installed)
    t.title = f"Обновить {', '.join(pkgs[:3])}{' …' if len(pkgs) > 3 else ''}{_scope(t)}"
    t.steps = [
        (f"Обновите пакет{'ы' if len(pkgs) > 1 else ''} {', '.join(pkgs)} до последней "
        f"версии из репозитория {t.os or 'ОС'}."),
        ("Уязвимость найдена по версии апстрима: в бюллетенях вендора для этой ОС "
        "записи о ней нет (или бюллетени не загружены), поэтому исправленная версия "
        "пакета не указана. Если вендор перенёс исправление в старую версию (бэкпорт), "
        "находка закроется после загрузки или обновления бюллетеней («Справочники» → "
        "«Бюллетени дистрибутивов»)."),
    ]
    if hint := _restart_hint(t.manager, pkgs):
        t.steps.append(hint)
    t.steps.append(_rescan_step())
    t.commands, t.verify = package_commands(g.os, t.manager, pkgs)
    _details(t, g, resolver, only_extra=True)


def _fill_kernel(t: FixTask, g: _Group, resolver: RemediationResolver) -> None:
    installed: dict[str, str | None] = {}
    notes: dict[str, str | None] = {}
    fixed: list[str] = []
    advisories: set[str] = set()
    reboot_hosts: set[str] = set()
    update_hosts: set[str] = set()
    pending: dict[str, str] = {}
    for _, f in g.items:
        h = _norm_host(f.host)
        ev = f.evidence or ""
        if (m := _RUNNING_RX.search(ev.split("\n", 1)[0])) is not None:
            installed.setdefault(h, m["rel"])
        if p := _PENDING_RX.search(ev):
            pending[h] = p["rel"]
        if f.vuln_id == "KERNEL-REBOOT-PENDING" or _REBOOT_ONLY in ev:
            reboot_hosts.add(h)
        else:
            update_hosts.add(h)
        for m in _KERNEL_FIXED.finditer(ev):
            fixed.append(m["ver"])
            if m["adv"]:
                advisories.update(a.strip() for a in m["adv"].split(","))
    only_reboot = reboot_hosts - update_hosts
    for h in reboot_hosts | update_hosts:
        target = pending.get(h)
        notes[h] = ((f"только перезагрузка — загрузится {target}" if target else
                     "только перезагрузка") if h in only_reboot else
                    "обновить ядро и перезагрузить")
    t.hosts = _hosts(g.items, installed, notes)
    t.reboot = True
    t.software = _KERNEL_LABEL
    t.fixed_version = _max_version(t.manager, fixed)
    t.advisories = sorted(advisories)
    reboot_all = not update_hosts
    t.title = ("Перезагрузить хосты: загрузить обновлённое ядро" if reboot_all else
               "Обновить ядро Linux и перезагрузить") + _scope(t)
    t.steps = []
    if update_hosts:
        ver = f" до версии не ниже {t.fixed_version}" if t.fixed_version else ""
        t.steps.append(f"Обновите ядро из репозитория {t.os or 'дистрибутива'}{ver}.")
    t.steps.append("Перезагрузите хост в согласованное окно обслуживания — уязвимости ядра "
                   "закрываются только после загрузки нового ядра.")
    if update_hosts:
        t.steps.append("Если перезагрузка сейчас невозможна — примените livepatch вендора "
                       "(Canonical Livepatch, kpatch), если он подключён.")
    t.steps.append("После перезагрузки проверьте, что работает новое ядро (`uname -r`).")
    t.commands, t.verify = kernel_commands(g.os, t.manager, reboot_all)


def _fill_software(t: FixTask, g: _Group, resolver: RemediationResolver) -> None:
    t.software = g.ident
    t.hosts = _hosts(g.items, g.installed)
    t.title = f"Обновить {g.ident}"
    t.steps = [
        (f"Обновите {g.ident} до версии производителя, в которой исправлены перечисленные "
        "уязвимости (см. бюллетени в ссылках)."),
        ("Если ПО установлено из пакетов ОС — обновите пакет через менеджер пакетов "
        "дистрибутива: тогда исправленную версию подскажет инвентаризация по учётной записи."),
        "Если обновление сейчас невозможно — ограничьте сетевой доступ к сервису.",
        _rescan_step(),
    ]
    _details(t, g, resolver, only_extra=True)


def _fill_generic(t: FixTask, g: _Group, resolver: RemediationResolver) -> None:
    f0 = g.items[0][1]
    t.hosts = _hosts(g.items)
    title = f0.title
    if g.kind == "config":
        t.title = f"Настроить: {title}"
    elif g.kind == "cred":
        t.title = f"Сменить учётные данные: {title}"
    else:
        t.title = title
    _details(t, g, resolver)
    # у правил и учётных записей мера — это и есть «что сделать»
    if f0.finding_type is FindingType.INFO and f0.evidence and not f0.remediation:
        t.steps = [f0.evidence.strip().splitlines()[-1]]
    elif t.details:
        t.steps = [line.strip() for line in t.details.split("\n") if line.strip()]
        t.details = None
    t.steps.append(_rescan_step())


def _details(t: FixTask, g: _Group, resolver: RemediationResolver,
             only_extra: bool = False) -> None:
    """Текст мер (БДУ для ОС хоста, fixtext правила, NVD) — по первой находке
    группы, у которой он есть. only_extra — только если это не типовой текст."""
    for _, f in g.items[:10]:
        r = resolver.resolve(f)
        if only_extra and r.source.value == "generic":
            continue
        t.details, t.details_source = r.text, r.source_label
        return
