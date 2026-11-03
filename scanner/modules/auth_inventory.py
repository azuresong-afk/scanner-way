"""Модуль: аутентифицированная инвентаризация (поиск уязвимостей по учётной записи).

Альтернатива (или дополнение) сетевому движку Nuclei: вместо проверок снаружи
сканер входит на хост по учётке договора (SSH, пароль или ключ), читает
установленные пакеты и их версии и сопоставляет их с БДУ ФСТЭК и NVD.

На хосте выполняется ОДНА фиксированная команда только на чтение
(`INVENTORY_SCRIPT`): /etc/os-release, `uname`, `hostname`, список пакетов
dpkg / rpm / apk и состояние ядра (`uname -r`, модули /sys/kernel/livepatch,
`canonical-livepatch status`, флаг /var/run/reboot-required). Ничего не
устанавливается, права root не нужны, в команду не подставляется ничего из
входных данных (нет места для инъекции).

Безопасность:
- цели — только литеральные IP, уже прошедшие allowlist оркестратора; если в
  прогоне был discovery, подключаемся только к хостам, которые он нашёл;
- учётки — только выбранные оператором для прогона (ctx.credentials), и только
  те, в область действия которых входит хост; на хосте пробуется не больше
  `MAX_CREDENTIALS_PER_HOST` учёток (защита от блокировки учётных записей);
- секреты не пишутся ни в аудит, ни в находки — только id/имя учётки, логин,
  порт и способ аутентификации;
- подключения ограничены профилем нагрузки: не больше max_concurrency хостов
  параллельно и минимальный интервал между подключениями;
- вывод хоста недоверенный: лимит размера, строки разбираются без eval.

Результат:
- инвентарь (ОС, пакеты) — в ctx.inventory, оркестратор сохраняет его в БД;
- находки VULN — по одной на CVE/БДУ для ПО хоста (port=None, ключ сравнения
  прогонов host+vuln_id+module стабилен), severity/CVSS — из справочников;
- учёт бэкпортов (R2): если для выпуска ОС загружены бюллетени вендора
  (scanner.feeds.advisories), находка сверяется с ними по ТОЧНОЙ версии пакета:
  закрыто бэкпортом / не затронут — находки нет; уязвим — находка с версией
  исправления; нет записи вендора — как раньше, с оговоркой. Бюллетень может
  и добавить находку: CVE, исправленную вендором в версии выше установленной;
- ядро (scanner.feeds.kernel): уязвимости РАБОТАЮЩЕГО ядра по бюллетеням вендора,
  с учётом livepatch и «новое ядро установлено, но хост не перезагружен»;
- INFO-находки: сводка инвентаризации хоста и ошибки (нет доступа, отказ входа).
"""
from __future__ import annotations

import ipaddress
import re
import shlex
import time
from collections.abc import Callable, Sequence
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field

from scanner.core.credentials import HostCredential, credentials_for_host
from scanner.core.models import (
    Finding,
    FindingType,
    HostInventory,
    InstalledPackage,
    Severity,
)
from scanner.core.osfamily import family_label
from scanner.core.sshexec import (
    AuthFailed,
    HostKeyMismatch,
    RemoteShell,
    SshError,
    SshOptions,
    Unreachable,
    connect,
)
from scanner.feeds import kernel as kn
from scanner.feeds import packages as pk
from scanner.feeds.advisories import host_release
from scanner.feeds.advisories.assess import Decision, Verdict, combine, decide
from scanner.feeds.advisories.base import Advisory, FamilySpec
from scanner.feeds.advisories.store import AdvisoryStore, CachingAdvisoryStore
from scanner.feeds.matcher import BACKPORT_CAVEAT
from scanner.modules.base import ScanContext, ScanModule
from scanner.modules.config_audit import _Throttle

MODULE = "auth_inventory"

# Единственная команда, выполняемая на хосте. Только чтение, без sudo.
INVENTORY_SCRIPT = r"""LC_ALL=C; export LC_ALL
echo '@@os-release'; cat /etc/os-release 2>/dev/null || cat /usr/lib/os-release 2>/dev/null
echo '@@uname'; uname -srm 2>/dev/null
echo '@@hostname'; hostname 2>/dev/null || cat /etc/hostname 2>/dev/null
if command -v dpkg-query >/dev/null 2>&1; then
  echo '@@dpkg'; dpkg-query -W -f='${Status}\t${Package}\t${Version}\t${Architecture}\t${source:Package}\t${source:Version}\n' 2>/dev/null
fi
if command -v rpm >/dev/null 2>&1; then
  echo '@@rpm'; rpm -qa --qf '%{NAME}\t%{EPOCH}:%{VERSION}-%{RELEASE}\t%{ARCH}\t%{SOURCERPM}\n' 2>/dev/null
fi
if command -v apk >/dev/null 2>&1; then
  echo '@@apk'; apk info -v 2>/dev/null
fi
echo '@@kernel-release'; uname -r 2>/dev/null
echo '@@livepatch'
for d in /sys/kernel/livepatch/*; do
  [ -d "$d" ] && echo "${d##*/} $(cat "$d/enabled" 2>/dev/null)"
done
LP=$(command -v canonical-livepatch 2>/dev/null)
[ -z "$LP" ] && [ -x /snap/bin/canonical-livepatch ] && LP=/snap/bin/canonical-livepatch
if [ -n "$LP" ]; then
  echo '@@canonical-livepatch'
  if command -v timeout >/dev/null 2>&1; then
    timeout 20 "$LP" status --format json 2>/dev/null | head -c 200000
  else
    "$LP" status --format json 2>/dev/null | head -c 200000
  fi
  echo
fi
echo '@@reboot-required'
[ -f /var/run/reboot-required ] && echo yes
echo '@@end'
"""
INVENTORY_COMMAND = "sh -c " + shlex.quote(INVENTORY_SCRIPT)

MAX_PACKAGES = 20000
_APK_RE = re.compile(r"^(?P<name>.+)-(?P<ver>\d[^-]*)-r(?P<rel>\d+)$")
_SRPM_RE = re.compile(r"^(?P<name>.+)-[^-]+-[^-]+\.(?:no)?src\.rpm$")
# Исходные пакеты ядра: с ядром по версии не сопоставляем (см. feeds.packages).
_KERNEL_SOURCE_RE = re.compile(r"linux(-signed(-[\w.]+)?|-latest(-[\w.]+)?)?|kernel")

Connector = Callable[[str, HostCredential, SshOptions], RemoteShell]


# ---------- разбор вывода ----------

def _os_release(lines: list[str]) -> dict[str, str]:
    out: dict[str, str] = {}
    for line in lines:
        key, sep, value = line.partition("=")
        if sep and re.fullmatch(r"[A-Z_]+", key):
            out[key] = value.strip().strip('"').strip("'")[:200]
    return out


def parse_inventory(text: str, host: str) -> HostInventory:
    """Вывод INVENTORY_SCRIPT -> HostInventory. Неполный вывод не ошибка."""
    sections: dict[str, list[str]] = {}
    current: list[str] | None = None
    for line in text.splitlines():
        if line.startswith("@@"):
            current = sections.setdefault(line[2:].strip(), [])
            continue
        if current is not None:
            current.append(line.rstrip("\r"))
    osr = _os_release(sections.get("os-release", []))
    inv = HostInventory(
        host=host, os_id=osr.get("ID") or None,
        os_name=osr.get("PRETTY_NAME") or osr.get("NAME") or None,
        os_version=osr.get("VERSION_ID") or None, os_like=osr.get("ID_LIKE") or None,
        os_codename=osr.get("VERSION_CODENAME") or None,
        kernel=next((x.strip()[:200] for x in sections.get("uname", []) if x.strip()), None),
        hostname=next((x.strip()[:255] for x in sections.get("hostname", []) if x.strip()),
                      None))
    seen: set[tuple[str, str, str]] = set()

    def add(p: InstalledPackage) -> None:
        key = (p.manager, p.name, p.version)
        if p.name and p.version and key not in seen and len(inv.packages) < MAX_PACKAGES:
            seen.add(key)
            inv.packages.append(p)

    for line in sections.get("dpkg", []):
        parts = line.split("\t")
        if len(parts) < 3 or not parts[0].endswith(" installed"):
            continue              # rc (удалён, остались конфиги), half-installed…
        src = parts[4].strip()[:200] if len(parts) > 4 else ""
        src_ver = parts[5].strip()[:200] if len(parts) > 5 else ""
        add(InstalledPackage(parts[1][:200], parts[2][:200], "dpkg",
                             (parts[3][:32] if len(parts) > 3 else None) or None,
                             source=src if src and src != parts[1] else None,
                             source_version=src_ver if src_ver and src_ver != parts[2]
                             else None))
    for line in sections.get("rpm", []):
        parts = line.split("\t")
        if len(parts) < 2 or parts[0].startswith("gpg-pubkey"):
            continue
        version = parts[1].replace("(none):", "")
        m = _SRPM_RE.match(parts[3].strip()) if len(parts) > 3 else None
        srpm = m["name"][:200] if m and m["name"] != parts[0] else None
        add(InstalledPackage(parts[0][:200], version[:200], "rpm",
                             (parts[2][:32] if len(parts) > 2 else None) or None,
                             source=srpm))
    for line in sections.get("apk", []):
        m = _APK_RE.match(line.strip())
        if m:
            add(InstalledPackage(m["name"][:200], f"{m['ver']}-r{m['rel']}"[:200], "apk"))
    # Работающее ядро: uname -r, а у старого вывода — второе поле uname -srm.
    rel = next((x.strip() for x in sections.get("kernel-release", []) if x.strip()), None)
    if rel is None and inv.kernel and len(inv.kernel.split()) >= 2:
        rel = inv.kernel.split()[1]
    if rel and re.fullmatch(r"[\w.+~-]{1,128}", rel):
        inv.kernel_release = rel
    inv.livepatch_modules = kn.parse_livepatch_modules(sections.get("livepatch", []))[:50]
    if "canonical-livepatch" in sections:
        lp = "\n".join(sections["canonical-livepatch"])
        inv.livepatch_tool = bool(lp.strip())
        inv.livepatch_cves = sorted(kn.parse_canonical_livepatch(lp))[:5000]
    inv.reboot_required = any(x.strip() == "yes" for x in sections.get("reboot-required", []))
    return inv


# ---------- пакеты -> ПО ----------

@dataclass(slots=True)
class SoftwareGroup:
    software: pk.Software
    upstream: str
    distro: str
    packages: list[str] = field(default_factory=list)
    installed: list[InstalledPackage] = field(default_factory=list)


def group_software(packages: Sequence[InstalledPackage],
                   bdu_names: set[str]) -> list[SoftwareGroup]:
    """Пакеты -> ПО для сопоставления. Пакеты одного ПО одной версии
    (openssh-server + openssh-client, openssl + libssl3) — одна группа."""
    groups: dict[tuple[str, str], SoftwareGroup] = {}
    for p in packages:
        if pk.is_kernel(p.name):
            continue
        sw = pk.lookup(p.name) or pk.generic_software(p.name, bdu_names)
        upstream = pk.upstream_version(p.version) if sw else None
        if sw is None or not upstream:
            continue
        g = groups.setdefault((sw.key, upstream),
                              SoftwareGroup(sw, upstream, pk.distro_version(p.version)))
        if p.name not in g.packages:
            g.packages.append(p.name)
            g.installed.append(p)
    return list(groups.values())


# ---------- бюллетени дистрибутива (учёт бэкпортов) ----------

@dataclass(slots=True)
class BackportReport:
    """Итог сверки находок хоста с бюллетенями вендора (для сводки и аудита)."""
    source: str                           # «Debian bookworm» / причина, почему данных нет
    has_data: bool = False
    closed: list[str] = field(default_factory=list)       # закрыто бэкпортом / не затронут
    confirmed: int = 0                    # вендор подтвердил: уязвим
    no_record: int = 0                    # у вендора нет записи — оставлено с оговоркой
    added: int = 0                        # добавлено по бюллетеню

    def summary(self) -> str:
        if not self.has_data:
            return (f"бюллетени дистрибутива: {self.source} — находки по версии "
                    "апстрима, с оговоркой о возможном бэкпорте")
        return (f"бюллетени дистрибутива ({self.source}): закрыто бэкпортом / не "
                f"затронуто — {len(self.closed)}, подтверждено вендором — "
                f"{self.confirmed}, добавлено по бюллетеню — {self.added}, нет записи "
                f"вендора — {self.no_record}")


def _version_for(p: InstalledPackage, by_source: bool) -> str:
    # Трекер Debian хранит версии исходного пакета: у бинарного версия может
    # отличаться (gcc из gcc-defaults), поэтому сравниваем с версией исходного.
    return (p.source_version or p.version) if by_source else p.version


class _HostAdvisories:
    """Данные вендора для одного хоста: выпуск ОС и записи по его пакетам."""

    def __init__(self, inv: HostInventory, store: AdvisoryStore | None,
                 loaded: set[tuple[str, str]] | None,
                 fetch_errors: dict[tuple[str, str], str] | None = None):
        self.spec: FamilySpec | None = None
        self.release: str | None = None
        self._rows: dict[str, list[Advisory]] = {}
        self._store: AdvisoryStore | None = None
        family = inv.os_family
        target = host_release(family, inv.os_version, inv.os_codename)
        if target is None:
            self.report = BackportReport(
                f"для «{family_label(family)}» данных вендора нет")
            return
        self.spec, self.release = target
        label = f"{self.spec.label} {self.release}"
        if family != self.spec.family:   # Rocky/Alma/… по данным Red Hat
            label += f" (для {family_label(family)})"
        if store is None or loaded is None or (self.spec.family, self.release) not in loaded:
            why = (fetch_errors or {}).get((self.spec.family, self.release))
            self.report = BackportReport(f"бюллетени {label} не загружены"
                                         + (f" ({why})" if why else ""))
            return
        names = {n for p in inv.packages for n in (p.name, p.source) if n}
        names.update(kn.SOURCE_ALIASES.get(self.spec.manager, ()))   # ядро: linux / kernel
        self._rows = store.for_packages(self.spec.family, self.release, names)
        self._store = store
        self.report = BackportReport(label, has_data=True)

    @property
    def has_data(self) -> bool:
        return self.report.has_data

    def decide(self, p: InstalledPackage, cve: str) -> Decision:
        manager = self.spec.manager if self.spec else p.manager
        if p.manager != manager:
            return Decision(Verdict.NO_DATA, cve, p.name, p.version)
        by_name = [e for e in self._rows.get(p.name, []) if e.cve == cve]
        if by_name:
            return decide(by_name, cve, package=p.name, installed=p.version,
                          manager=manager)
        by_src = [e for e in self._rows.get(p.source or "", []) if e.cve == cve]
        return decide(by_src, cve, package=p.name, installed=_version_for(p, True),
                      manager=manager)

    def rows(self, names: set[str]) -> list[Advisory]:
        return [e for n in sorted(names) for e in self._rows.get(n, [])]

    def uname_rows(self, release: str) -> list[Advisory]:
        """Записи Ubuntu «работает ядро по шаблону uname», подходящие к uname -r."""
        if self._store is None or self.spec is None or self.release is None:
            return []
        with_prefix = getattr(self._store, "with_prefix", None)
        if with_prefix is None:
            return []
        rows = with_prefix(self.spec.family, self.release, kn.UNAME_PREFIX)
        return [e for name, es in rows.items()
                if kn.uname_matches(name[len(kn.UNAME_PREFIX):], release) for e in es]

    def fixed_cves(self, p: InstalledPackage) -> dict[str, Decision]:
        """CVE, исправленные вендором в версии выше установленной (находки по бюллетеню).
        Ядро и kpatch проверяются отдельно — по работающему ядру (_kernel_findings)."""
        if not self.has_data or pk.is_kernel(p.name) or kn.is_kpatch(p.name) or \
                _KERNEL_SOURCE_RE.fullmatch(p.source or ""):
            return {}
        cves = {e.cve for n in (p.name, p.source) if n for e in self._rows.get(n, [])
                if e.fixed_version}
        out = {}
        for cve in cves:
            d = self.decide(p, cve)
            if d.verdict is Verdict.VULNERABLE and d.advisory and d.advisory.fixed_version:
                out[cve] = d
        return out


def _vendor_line(adv: _HostAdvisories, d: Decision) -> str:
    src = adv.report.source
    a = d.advisory
    ref = f" ({a.advisory_id})" if a and a.advisory_id else ""
    if a is None or not a.fixed_version:
        return (f"Бюллетень {src}{ref}: исправления {d.cve} для пакета {d.package} у "
                "вендора пока нет — пакет уязвим.")
    return (f"Бюллетень {src}{ref}: {d.cve} исправлена в версии {a.fixed_version} "
            f"(пакет {a.package}); установлена {d.installed} — пакет уязвим, обновите "
            "его из репозитория дистрибутива.")


# ---------- ядро ----------

KERNEL_LABEL = "Ядро Linux"

@dataclass(slots=True)
class KernelReport:
    """Итог проверки работающего ядра (для сводки и аудита)."""
    release: str | None                   # uname -r
    package: str | None = None            # пакет работающего ядра и версия
    checked: bool = False
    reason: str | None = None             # почему не проверено
    vulnerable: int = 0
    livepatched: list[str] = field(default_factory=list)
    fixed_by_reboot: int = 0
    pending: str | None = None            # установлено, но не загружено
    livepatch_modules: list[str] = field(default_factory=list)

    def summary(self) -> str:
        head = f"ядро: {self.release or 'не определено'}" + (
            f" (пакет {self.package})" if self.package else "")
        if not self.checked:
            parts = [f"{head} — уязвимости ядра не проверены: {self.reason}"]
        else:
            parts = [(f"{head} — уязвимостей работающего ядра по бюллетеням вендора: "
                      f"{self.vulnerable}")]
            if self.livepatched:
                parts.append(f"закрыто livepatch: {len(self.livepatched)}")
        if self.pending:
            parts.append(f"установлено более новое ядро {self.pending}, хост не "
                         "перезагружен" + (f" (перезагрузка закроет {self.fixed_by_reboot})"
                                           if self.fixed_by_reboot else ""))
        if self.livepatch_modules:
            parts.append("активны модули livepatch: " + ", ".join(self.livepatch_modules[:5]))
        return "; ".join(parts)


def _kernel_head(st: kn.KernelState) -> str:
    """Первая строка evidence находок по ядру: по ней страница хоста и отчёт
    относят находку к ПО «Ядро Linux <uname -r>» (scanner.core.software)."""
    run = st.package
    pkg = f"{run.name} ({run.version})" if run else f"ядра ({st.release})"
    return f"Пакет {pkg} → {KERNEL_LABEL} {st.release}"


def _kernel_line(adv: _HostAdvisories, d: Decision, release: str) -> str:
    a = d.advisory
    ref = f" ({a.advisory_id})" if a and a.advisory_id else ""
    fixed = a.fixed_version if a else "?"
    return (f"Бюллетень {adv.report.source}{ref}: {d.cve} исправлена в ядре версии {fixed}; "
            f"работает ядро {release} (версия {d.installed}) — уязвимо.")


# ---------- модуль ----------

@dataclass(slots=True)
class AuthInventoryOptions:
    ssh: SshOptions = field(default_factory=SshOptions)
    command_timeout_sec: float = 180.0
    max_parallel_hosts: int = 8          # верхняя граница; реальная — min с профилем


class _Matcher:
    """Интерфейс слоя сопоставления (feeds.matcher.VulnMatcher)."""

    store: object

    def findings_for_package(self, host: str, **kw) -> list[Finding]: ...


class AuthInventoryModule(ScanModule):
    name = MODULE

    def __init__(self, options: AuthInventoryOptions | None = None,
                 matcher: _Matcher | None = None, connector: Connector | None = None,
                 sleep: Callable[[float], None] = time.sleep,
                 advisories: AdvisoryStore | None = None,
                 fetch_advisories: Callable[[list[tuple[str, str]]], list] | None = None):
        self.options = options or AuthInventoryOptions()
        self._matcher = matcher
        self._advisories = advisories
        # Подгрузка бюллетеней выпусков, встреченных на хостах (feeds.advisories.ondemand)
        self._fetch_advisories = fetch_advisories
        self._connect = connector or connect
        self._sleep = sleep

    # --- сбор ---
    def _collect(self, ctx: ScanContext, throttle: _Throttle, host: str,
                 creds: list[HostCredential]) -> tuple[HostInventory | None, list[Finding]]:
        notes: list[Finding] = []
        for cred in creds:
            info = cred.describe()
            throttle.wait()
            ctx.audit.record(subject="scanner", action="auth_inventory_ssh", target=host,
                             result="started", details=info)
            try:
                shell = self._connect(host, cred, self.options.ssh)
            except AuthFailed as e:
                ctx.audit.record(subject="scanner", action="auth_inventory_ssh",
                                 target=host, result="auth_failed",
                                 details={**info, "error": str(e)[:300]})
                notes.append(self._info(host, "INFO:auth-inventory-auth-failed",
                                        "Вход по учётной записи отклонён",
                                        f"учётка «{cred.name}» ({cred.username}@{host}:"
                                        f"{cred.port}): {e}"))
                continue                      # следующая учётка из области хоста
            except HostKeyMismatch as e:
                ctx.audit.record(subject="scanner", action="auth_inventory_ssh",
                                 target=host, result="host_key_mismatch",
                                 details={**info, "error": str(e)[:300]})
                return None, [self._info(host, "INFO:auth-inventory-host-key",
                                         "Ключ SSH хоста не прошёл проверку", str(e))]
            except Unreachable as e:
                ctx.audit.record(subject="scanner", action="auth_inventory_ssh",
                                 target=host, result="unreachable",
                                 details={**info, "error": str(e)[:300]})
                return None, [self._info(host, "INFO:auth-inventory-unreachable",
                                         "Хост недоступен по SSH",
                                         f"{host}:{cred.port}: {e}")]
            except (SshError, ValueError) as e:
                ctx.audit.record(subject="scanner", action="auth_inventory_ssh",
                                 target=host, result="error",
                                 details={**info, "error": str(e)[:300]})
                notes.append(self._info(host, "INFO:auth-inventory-error",
                                        "Инвентаризация по учётной записи не выполнена",
                                        str(e)[:500]))
                continue
            try:
                res = shell.run(INVENTORY_COMMAND, self.options.command_timeout_sec)
            except SshError as e:
                ctx.audit.record(subject="scanner", action="auth_inventory_exec",
                                 target=host, result="error",
                                 details={**info, "error": str(e)[:300]})
                return None, [*notes, self._info(
                    host, "INFO:auth-inventory-error",
                    "Инвентаризация по учётной записи не выполнена", str(e)[:500])]
            finally:
                shell.close()
            inv = parse_inventory(res.stdout.decode("utf-8", "replace"), host)
            inv.credential_id = cred.id
            ctx.audit.record(subject="scanner", action="auth_inventory_exec", target=host,
                             result="ok" if inv.packages else "no_packages",
                             details={**info, "rc": res.returncode,
                                      "packages": len(inv.packages),
                                      "truncated": res.truncated, "os": inv.os_label})
            return inv, []   # вход удался — заметки об отказах других учёток не нужны
        return None, notes

    # --- сопоставление ---
    def _match(self, ctx: ScanContext, inv: HostInventory, matcher: _Matcher | None,
               bdu_names: set[str],
               adv: _HostAdvisories | None = None) -> list[Finding]:
        out: dict[str, Finding] = {}
        origin: dict[str, list[InstalledPackage]] = {}
        groups = group_software(inv.packages, bdu_names) if matcher is not None else []
        for g in groups:
            assert matcher is not None
            sw = g.software
            try:
                found = matcher.findings_for_package(
                    inv.host, product=sw.label, version=g.upstream, cpe=sw.cpe,
                    bdu_names=sw.bdu_names, distro_version=g.distro,
                    packages=g.packages, use_nvd=sw.cpe is not None, module=self.name)
            except Exception as e:  # noqa: BLE001 — справочник недоступен: инвентарь важнее
                ctx.audit.record(subject="scanner", action="auth_inventory_match",
                                 target=inv.host, result="error",
                                 details={"software": sw.label,
                                          "error": f"{type(e).__name__}: {e}"[:300]})
                continue
            for f in found:
                key = f.vuln_id or ""
                origin.setdefault(key, []).extend(
                    p for p in g.installed if p not in origin.get(key, []))
                prev = out.get(key)
                if prev is None:
                    out[key] = f
                elif f.evidence and f.evidence not in (prev.evidence or ""):
                    prev.evidence = f"{prev.evidence}\n{f.evidence}"   # libssl1.1 + libssl3
        if adv is not None:
            self._apply_advisories(ctx, inv, adv, out, origin, matcher)
        ctx.audit.record(subject="scanner", action="auth_inventory_match", target=inv.host,
                         result="ok", details={"software": len(groups),
                                               "findings": len(out)})
        return list(out.values())

    def _apply_advisories(self, ctx: ScanContext, inv: HostInventory,
                          adv: _HostAdvisories, out: dict[str, Finding],
                          origin: dict[str, list[InstalledPackage]],
                          matcher: _Matcher | None) -> None:
        """Сверка находок с бюллетенями вендора (изменяет out на месте)."""
        rep = adv.report
        if not adv.has_data:
            for f in out.values():
                if f.evidence and BACKPORT_CAVEAT in f.evidence:
                    f.evidence += f"\nНет данных вендора: {rep.source}."
            return
        for key in list(out):
            f = out[key]
            cves = [key] if key.startswith("CVE-") else list(f.cve_ids)
            pkgs = origin.get(key, [])
            decisions = [adv.decide(p, c) for p in pkgs for c in cves]
            verdict = combine(decisions)
            if verdict in (Verdict.FIXED, Verdict.NOT_AFFECTED):
                rep.closed.append(key)
                del out[key]
                continue
            if verdict is Verdict.VULNERABLE:
                rep.confirmed += 1
                lines = list(dict.fromkeys(_vendor_line(adv, d) for d in decisions
                                           if d.verdict is Verdict.VULNERABLE))
                text = "\n".join(lines)
                f.evidence = (f.evidence.replace(BACKPORT_CAVEAT, text)
                              if f.evidence and BACKPORT_CAVEAT in f.evidence
                              else "\n".join(x for x in (f.evidence, text) if x))
                continue
            rep.no_record += 1
            why = ("в записи нет CVE — сверить с бюллетенем нельзя" if not cves else
                   f"в бюллетенях {rep.source} нет записи о "
                   f"{', '.join(cves[:3])} для пакета {', '.join(p.name for p in pkgs)}")
            f.evidence = "\n".join(x for x in (f.evidence, f"Нет данных вендора: {why}.") if x)

        # Находки по бюллетеню: CVE, исправленные вендором выше установленной версии,
        # которых не нашло сопоставление по версии апстрима.
        known = {c for f in out.values() for c in (f.vuln_id, *f.cve_ids) if c}
        known.update(rep.closed)
        added: dict[str, Finding] = {}
        for p in inv.packages:
            for cve, d in sorted(adv.fixed_cves(p).items()):
                if cve in known:
                    continue
                line = _vendor_line(adv, d)
                prev = added.get(cve)
                if prev is not None:
                    if line not in (prev.evidence or ""):
                        prev.evidence = f"{prev.evidence}\n{line}"
                    continue
                f = Finding(module=MODULE, host=inv.host, finding_type=FindingType.VULN,
                            vuln_id=cve, cve_ids=[cve],
                            title=f"{cve}: пакет {p.name} {d.installed} (исправлено в "
                                  f"{d.advisory.fixed_version if d.advisory else '?'})")
                if matcher is not None and hasattr(matcher, "enrich"):
                    try:
                        matcher.enrich(f)  # type: ignore[attr-defined]
                    except Exception as e:  # noqa: BLE001 — находка важнее обогащения
                        ctx.audit.record(subject="scanner", action="auth_inventory_match",
                                         target=inv.host, result="error",
                                         details={"cve": cve,
                                                  "error": f"{type(e).__name__}: {e}"[:300]})
                note = ""
                if f.severity is Severity.INFO:
                    f.severity = Severity.MEDIUM
                    note = ("\nУровень опасности не найден в NVD/БДУ — принят средний; "
                            "уточните по бюллетеню.")
                sw = pk.lookup(p.name)
                label = (f"{sw.label if sw else p.name} "
                         f"{pk.upstream_version(p.version) or pk.distro_version(p.version)}")
                f.evidence = (f"Пакет {p.name} ({p.version}) → {label}\n"
                              f"Находка по бюллетеню вендора.\n{line}{note}")
                added[cve] = f
        rep.added = len(added)
        out.update(added)

    def _kernel_findings(self, ctx: ScanContext, inv: HostInventory,
                         adv: _HostAdvisories | None, matcher: _Matcher | None,
                         existing: dict[str, Finding]) -> tuple[list[Finding], KernelReport]:
        """Уязвимости РАБОТАЮЩЕГО ядра по бюллетеням вендора (scanner.feeds.kernel)."""
        st = kn.kernel_state(inv.kernel_release, inv.packages)
        run = st.package
        rep = KernelReport(release=st.release, livepatch_modules=list(inv.livepatch_modules),
                           package=f"{run.name} {run.version}" if run else None,
                           pending=st.pending_release)
        out: list[Finding] = []
        if not inv.packages:
            return out, rep
        if not st.release:
            rep.reason = "версия работающего ядра (uname -r) не получена"
        elif adv is None or not adv.has_data or adv.spec is None:
            rep.reason = (adv.report.source if adv is not None
                          else "нет данных вендора для этой ОС")
        if rep.reason is None:
            assert adv is not None and adv.spec is not None and st.release
            manager = adv.spec.manager
            # (записи вендора, установленная версия работающего ядра, версия
            # ожидающего перезагрузки ядра) по каждой CVE
            sources: dict[str, list[tuple[list[Advisory], str, str | None]]] = {}
            if run is not None:
                names = {p.name for p in st.running} | {p.source for p in st.running
                                                       if p.source}
                if manager == "dpkg" and any((p.source or "").startswith("linux")
                                             for p in st.running):
                    names.add("linux")                     # трекер Debian: исходный linux
                if manager == "rpm" and run.name in ("kernel", "kernel-core"):
                    names.add("kernel")
                rows = adv.rows(names)
                for cve in {e.cve for e in rows}:
                    sources.setdefault(cve, []).append(
                        ([e for e in rows if e.cve == cve], run.version,
                         st.pending.version if st.pending else None))
            urows = adv.uname_rows(st.release)
            abi = kn.abi(st.release)
            if urows and abi:
                for cve in {e.cve for e in urows}:
                    sources.setdefault(cve, []).append(
                        ([e for e in urows if e.cve == cve], abi,
                         kn.abi(st.pending_release)))
            if run is None and not urows:
                rep.reason = (f"пакет работающего ядра {st.release} не найден среди "
                              "установленных (самосборное ядро?) — сверить с бюллетенем "
                              "нельзя")
            else:
                rep.checked = True
                out.extend(self._kernel_vulns(ctx, inv, adv, matcher, existing, st, rep,
                                              sources, manager))
        head = _kernel_head(st)
        if not rep.checked and st.release:
            # Не INFO: пробел в проверке ядра должен быть виден среди уязвимостей хоста.
            note = self._info(
                inv.host, "INFO:kernel-unchecked",
                f"Уязвимости ядра {st.release} не проверены",
                f"{head}\n{rep.reason}. Загрузите бюллетени дистрибутива («Справочники» → "
                "«Бюллетени дистрибутивов» или файл в каталоге бюллетеней) и повторите "
                "проверку.")
            note.severity = Severity.LOW
            out.append(note)
        if st.pending is not None:
            sev = Severity.MEDIUM if rep.fixed_by_reboot else Severity.LOW
            ev = [head,
                  (f"Установлено более новое ядро {st.pending_release} (пакет "
                   f"{st.pending.name} {st.pending.version}), но хост с него не загружен.")]
            if rep.fixed_by_reboot:
                ev.append(f"Перезагрузка закроет уязвимостей ядра: {rep.fixed_by_reboot}.")
            if inv.reboot_required:
                ev.append("Система сама сообщает о необходимости перезагрузки "
                          "(/var/run/reboot-required).")
            out.append(Finding(
                module=MODULE, host=inv.host, finding_type=FindingType.CONFIG,
                vuln_id="KERNEL-REBOOT-PENDING", severity=sev,
                title=f"Обновлённое ядро установлено, но не загружено: работает "
                      f"{st.release}", evidence="\n".join(ev),
                remediation=f"Перезагрузите хост в согласованное окно обслуживания, чтобы "
                            f"загрузилось ядро {st.pending_release}; после перезагрузки "
                            "проверьте `uname -r`."))
        return out, rep

    def _kernel_vulns(self, ctx: ScanContext, inv: HostInventory, adv: _HostAdvisories,
                      matcher: _Matcher | None, existing: dict[str, Finding],
                      st: kn.KernelState, rep: KernelReport,
                      sources: dict[str, list[tuple[list[Advisory], str, str | None]]],
                      manager: str) -> list[Finding]:
        out: list[Finding] = []
        run = st.package
        pkg_name = run.name if run else f"ядро {st.release}"
        livepatch = set(inv.livepatch_cves)
        kp_rows = adv.rows({p.name for p in st.kpatch})
        for cve in sorted(sources):
            vuln: Decision | None = None
            reboot_fixes = True
            for rows, installed, pending in sources[cve]:
                d = decide(rows, cve, package=pkg_name, installed=installed, manager=manager)
                if d.verdict is not Verdict.VULNERABLE or not (d.advisory and
                                                               d.advisory.fixed_version):
                    continue                  # открытые без исправления находку не создают
                vuln = vuln or d
                if pending is None or not decide(rows, cve, package=pkg_name,
                                                 installed=pending,
                                                 manager=manager).closed:
                    reboot_fixes = False
            if vuln is None:
                continue
            if cve in livepatch:
                rep.livepatched.append(cve)
                continue
            kp = [e for e in kp_rows if e.cve == cve]
            if kp and any(decide(kp, cve, package=p.name, installed=p.version,
                                 manager=manager).verdict is Verdict.FIXED
                          for p in st.kpatch):
                rep.livepatched.append(cve)
                continue
            line = _kernel_line(adv, vuln, st.release or "?")
            prev = existing.get(cve)
            if prev is not None:                 # та же CVE уже найдена у другого пакета
                prev.evidence = "\n".join(x for x in (prev.evidence, line) if x)
                continue
            rep.vulnerable += 1
            reboot = reboot_fixes and st.pending is not None
            if reboot:
                rep.fixed_by_reboot += 1
            assert vuln.advisory is not None
            fixed = vuln.advisory.fixed_version
            f = Finding(module=MODULE, host=inv.host, finding_type=FindingType.VULN,
                        vuln_id=cve, cve_ids=[cve],
                        title=f"{cve}: ядро Linux {st.release} (исправлено в {fixed})")
            if matcher is not None and hasattr(matcher, "enrich"):
                try:
                    matcher.enrich(f)  # type: ignore[attr-defined]
                except Exception as e:  # noqa: BLE001 — находка важнее обогащения
                    ctx.audit.record(subject="scanner", action="auth_inventory_kernel",
                                     target=inv.host, result="error",
                                     details={"cve": cve,
                                              "error": f"{type(e).__name__}: {e}"[:300]})
            note = ""
            if f.severity is Severity.INFO:
                f.severity = Severity.MEDIUM
                note = ("\nУровень опасности не найден в NVD/БДУ — принят средний; "
                        "уточните по бюллетеню.")
            ev = [_kernel_head(st), line]
            if reboot:
                ev.append(f"Исправленное ядро {st.pending_release} уже установлено, но хост "
                          "не перезагружен.")
            f.evidence = "\n".join(ev) + note
            f.remediation = (
                f"Исправленное ядро {st.pending_release} уже установлено: перезагрузите "
                "хост, чтобы оно загрузилось." if reboot else
                f"Обновите ядро из репозитория дистрибутива (пакет {pkg_name} — до версии "
                f"не ниже {fixed}) и перезагрузите хост. Если перезагрузка сейчас "
                "невозможна — примените livepatch вендора, если он подключён.")
            out.append(f)
        return out

    @staticmethod
    def _info(host: str, vuln_id: str, title: str, evidence: str | None) -> Finding:
        return Finding(module=MODULE, host=host, finding_type=FindingType.INFO,
                       title=title, severity=Severity.INFO, vuln_id=vuln_id,
                       evidence=evidence)

    def _summary(self, inv: HostInventory, cred: HostCredential | None,
                 matched: int, backports: BackportReport | None = None,
                 bdu_linked: int | None = None,
                 kernel: KernelReport | None = None) -> Finding:
        managers = sorted({p.manager for p in inv.packages})
        lines = [f"ОС: {inv.os_label or 'не определена'}"]
        if kernel is not None and inv.packages:
            lines.append(kernel.summary())
        elif inv.kernel:
            lines.append(f"ядро: {inv.kernel}")
        if inv.hostname:
            lines.append(f"имя хоста: {inv.hostname}")
        lines.append(f"пакетов: {len(inv.packages)}"
                     + (f" ({', '.join(managers)})" if managers else ""))
        lines.append(f"уязвимостей по версиям пакетов: {matched}")
        if bdu_linked is not None:
            lines.append(f"привязано к БДУ ФСТЭК: {bdu_linked} из {matched}"
                         + ("" if bdu_linked == matched else
                            " (у остальных CVE записи в БДУ нет или справочник БДУ "
                            "не загружен)"))
        if backports is not None:
            lines.append(backports.summary())
        if cred is not None:
            lines.append(f"учётная запись: «{cred.name}» ({cred.username}, {cred.auth})")
        if not inv.packages:
            lines.append("менеджер пакетов dpkg/rpm/apk не найден или недоступен")
        title = (f"Инвентаризация по учётной записи: {inv.os_label or inv.host}, "
                 f"пакетов — {len(inv.packages)}")
        return self._info(inv.host, "INFO:auth-inventory", title, "\n".join(lines))

    def _hosts(self, ctx: ScanContext) -> list[str]:
        hosts = []
        for t in ctx.targets:
            try:
                hosts.append(str(ipaddress.ip_address(t.strip())))
            except ValueError:
                ctx.audit.record(subject="scanner", action="auth_inventory_deny", target=t,
                                 result="not_an_ip_literal")
        if "discovery" in ctx.completed and ctx.services is not None:
            # discovery отработал: не стучимся по SSH в хосты, которых он не нашёл.
            # Если он упал (нет nmap, ошибка) — пробуем все цели прогона.
            alive = {s.host for s in ctx.services}
            for h in hosts:
                if h not in alive:
                    ctx.audit.record(subject="scanner", action="auth_inventory_skip",
                                     target=h, result="host_not_discovered")
            hosts = [h for h in hosts if h in alive]
        return hosts

    def run(self, ctx: ScanContext) -> list[Finding]:
        jobs: list[tuple[str, list[HostCredential]]] = []
        for host in self._hosts(ctx):
            creds = credentials_for_host(host, ctx.credentials)
            if not creds:
                ctx.audit.record(subject="scanner", action="auth_inventory_skip",
                                 target=host, result="no_credentials")
                continue
            jobs.append((host, creds))
        if not jobs:
            return []

        throttle = _Throttle(ctx.rate, sleep=self._sleep)
        workers = max(1, min(self.options.max_parallel_hosts, ctx.rate.max_concurrency,
                             len(jobs)))
        with ThreadPoolExecutor(max_workers=workers,
                                thread_name_prefix="auth-inventory") as pool:
            collected = list(pool.map(lambda j: (j, self._collect(ctx, throttle, *j)), jobs))

        matcher = self._run_matcher()
        bdu_names: set[str] = set()
        if matcher is not None:
            try:
                bdu_names = set(matcher.store.bdu_software_names())  # type: ignore[attr-defined]
            except Exception as e:  # noqa: BLE001 — без индекса работают известные пакеты
                ctx.audit.record(subject="scanner", action="auth_inventory_match",
                                 target="bdu_software_names", result="error",
                                 details=f"{type(e).__name__}: {e}"[:300])
        advisories, loaded = self._run_advisories(ctx)
        inventories = [inv for _, (inv, _) in collected if inv is not None]
        fetch_errors = self._fetch_missing(ctx, inventories, loaded)
        if fetch_errors is not None and any(v is None for v in fetch_errors.values()):
            advisories, loaded = self._run_advisories(ctx)   # перечитать с новыми выпусками
        errors = {k: v for k, v in (fetch_errors or {}).items() if v}
        findings: list[Finding] = []
        for (host, creds), (inv, notes) in collected:
            findings.extend(notes)
            if inv is None:
                continue
            ctx.inventory[host] = inv
            adv = self._host_advisories(ctx, inv, advisories, loaded, errors)
            matched = (self._match(ctx, inv, matcher, bdu_names, adv)
                       if matcher or (adv and adv.has_data) else [])
            if adv is not None:
                r = adv.report
                ctx.audit.record(subject="scanner", action="auth_inventory_backport",
                                 target=host, result="ok" if r.has_data else "no_data",
                                 details={"source": r.source, "closed": len(r.closed),
                                          "closed_ids": r.closed[:50],
                                          "confirmed": r.confirmed, "added": r.added,
                                          "no_record": r.no_record})
            kernel_found, krep = self._kernel_findings(
                ctx, inv, adv, matcher,
                {f.vuln_id: f for f in matched if f.vuln_id})
            ctx.audit.record(subject="scanner", action="auth_inventory_kernel", target=host,
                             result="ok" if krep.checked else "not_checked",
                             details={"release": krep.release, "package": krep.package,
                                      "vulnerable": krep.vulnerable,
                                      "livepatched": krep.livepatched[:50],
                                      "pending": krep.pending,
                                      "reason": krep.reason})
            matched.extend(kernel_found)
            cred = next((c for c in creds if c.id == inv.credential_id), None)
            vulns = [f for f in matched if f.finding_type is FindingType.VULN]
            findings.append(self._summary(inv, cred, len(vulns),
                                          adv.report if adv else None,
                                          bdu_linked=sum(1 for f in vulns if f.bdu_ids),
                                          kernel=krep))
            findings.extend(matched)
        return findings

    def _run_advisories(self, ctx: ScanContext
                        ) -> tuple[AdvisoryStore | None, set[tuple[str, str]] | None]:
        """Бюллетени прогона (с кэшем) и список загруженных выпусков."""
        if self._advisories is None:
            return None, None
        store = CachingAdvisoryStore(self._advisories)
        try:
            return store, store.releases()
        except Exception as e:  # noqa: BLE001 — без бюллетеней работаем как раньше
            ctx.audit.record(subject="scanner", action="auth_inventory_backport",
                             target="distro_advisory", result="error",
                             details=f"{type(e).__name__}: {e}"[:300])
            return None, None

    def _fetch_missing(self, ctx: ScanContext, inventories: list[HostInventory],
                       loaded: set[tuple[str, str]] | None
                       ) -> dict[tuple[str, str], str | None] | None:
        """Подгружает бюллетени выпусков ОС хостов, которых ещё нет в базе.
        -> {(семейство, выпуск): None | причина неудачи}; None — нечего делать."""
        if self._fetch_advisories is None or self._advisories is None or loaded is None:
            return None
        needed: set[tuple[str, str]] = set()
        for inv in inventories:
            if not inv.packages:
                continue
            target = host_release(inv.os_family, inv.os_version, inv.os_codename)
            if target is not None:
                needed.add((target[0].family, target[1]))
        missing = sorted(needed - loaded)
        if not missing:
            return None
        try:
            results = self._fetch_advisories(missing)
        except Exception as e:  # noqa: BLE001 — без бюллетеней работаем как раньше
            ctx.audit.record(subject="scanner", action="advisory_fetch",
                             target=",".join(f"{f}:{r}" for f, r in missing),
                             result="error", details=f"{type(e).__name__}: {e}"[:300])
            return {t: f"{type(e).__name__}: {e}"[:300] for t in missing}
        out: dict[tuple[str, str], str | None] = {}
        for r in results:
            out[(r.family, r.release)] = r.error
            ctx.audit.record(subject="scanner", action="advisory_fetch",
                             target=f"{r.family}:{r.release}",
                             result="error" if r.error else "ok",
                             details={"records": r.count, "source": r.source[:300],
                                      "error": (r.error or "")[:300] or None})
        return out

    @staticmethod
    def _host_advisories(ctx: ScanContext, inv: HostInventory,
                         store: AdvisoryStore | None,
                         loaded: set[tuple[str, str]] | None,
                         fetch_errors: dict[tuple[str, str], str] | None = None
                         ) -> _HostAdvisories | None:
        if not inv.packages:
            return None
        try:
            return _HostAdvisories(inv, store, loaded, fetch_errors)
        except Exception as e:  # noqa: BLE001
            ctx.audit.record(subject="scanner", action="auth_inventory_backport",
                             target=inv.host, result="error",
                             details=f"{type(e).__name__}: {e}"[:300])
            return None

    def _run_matcher(self) -> _Matcher | None:
        """Matcher прогона с кэшем справочника (одни и те же пакеты на сотнях хостов)."""
        if self._matcher is None:
            return None
        store = getattr(self._matcher, "store", None)
        if store is None:
            return self._matcher
        from scanner.feeds.matcher import VulnMatcher
        from scanner.feeds.store import CachingReferenceStore
        if not isinstance(self._matcher, VulnMatcher):
            return self._matcher
        m = self._matcher
        return VulnMatcher(CachingReferenceStore(store),  # type: ignore[arg-type]
                           bdu_product_match=m.bdu_product_match,
                           bdu_software_aliases=m.bdu_software_aliases)
