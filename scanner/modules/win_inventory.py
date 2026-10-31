"""Модуль: аутентифицированная инвентаризация Windows по WinRM (R3).

Windows-аналог `auth_inventory`: вместо сетевых проверок снаружи сканер входит
на Windows-хост по учётной записи договора (WinRM, HTTPS + NTLM, только пароль),
читает установленные обновления (KB), установленное ПО из реестра и несколько
параметров безопасности, затем сопоставляет:

- ОС хоста и установленные KB — со справочником обновлений Microsoft
  (`feeds.msrc`): какие CVE продукта Windows ещё не закрыты, с учётом замещения
  накопительных обновлений и ``FixedBuild``;
- установленное ПО (имя + версия из реестра) — с БДУ ФСТЭК и NVD обычным
  `VulnMatcher` (как для пакетов Linux).

На хосте выполняются ТОЛЬКО фиксированные скрипты PowerShell на чтение
(`INVENTORY_PARTS`), через ``-EncodedCommand``; в скрипты не подставляется
ничего из входных данных (нет места для инъекции), ничего не устанавливается и
не меняется, повышение прав не используется.

Безопасность (как у `auth_inventory`):
- цели — только литеральные IP, уже прошедшие allowlist оркестратора; если в
  прогоне был discovery, подключаемся только к найденным им хостам;
- учётки — только WinRM-учётки, выбранные оператором для прогона и подходящие
  хосту по области действия; на хосте пробуется не больше
  `MAX_CREDENTIALS_PER_HOST` учёток (защита от блокировки учётных записей);
- пароль берётся из памяти процесса и не попадает в argv, журнал, аудит и тексты
  находок — пишутся только id/имя учётки, логин, порт и протокол;
- сертификат хоста закрепляется при первом входе (TOFU, см. `core.winexec`);
- подключения ограничены профилем нагрузки (max_concurrency, интервал);
- вывод хоста недоверенный: лимит размера, строки разбираются без eval.

Результат:
- инвентарь (ОС, ПО) — в ctx.inventory (оркестратор сохраняет в БД, ПО видно на
  странице хоста как для Linux; менеджер пакетов — ``windows``);
- находки VULN: по одной на CVE отсутствующего обновления Windows (из MSRC) и по
  одной на CVE/БДУ установленного ПО (port=None, ключ сравнения прогонов
  host+vuln_id+module стабилен);
- INFO-находки: сводка инвентаризации хоста, параметры безопасности, ошибки
  (недоступен, отказ входа, сертификат не прошёл проверку, нет данных MSRC).
"""
from __future__ import annotations

import ipaddress
import time
from collections.abc import Callable
from dataclasses import dataclass, field

from scanner.compliance.facts import record as record_fact
from scanner.core.credentials import (
    PROTOCOL_WINRM,
    HostCredential,
    credentials_for_host,
)
from scanner.core.models import (
    Finding,
    FindingType,
    HostInventory,
    InstalledPackage,
    Severity,
)
from scanner.core.winexec import (
    AuthFailed,
    CertMismatch,
    Unreachable,
    WinRmError,
    WinRmOptions,
    WinShell,
    connect,
)
from scanner.feeds.msrc import (
    CATALOG_URL,
    GUIDE_URL,
    Assessment,
    KbGap,
    WindowsOs,
    assess,
)
from scanner.feeds.severity import max_severity, severity_from_cvss
from scanner.modules.base import ScanContext, ScanModule
from scanner.modules.config_audit import _Throttle

MODULE = "win_inventory"
PKG_MANAGER = "windows"
MAX_SOFTWARE = 20000

# Severity бюллетеня MSRC -> наша шкала (критичность по CVSS, если выше, берёт
# верх при обогащении через VulnMatcher).
_MSRC_SEVERITY = {
    "critical": Severity.CRITICAL,
    "important": Severity.HIGH,
    "moderate": Severity.MEDIUM,
    "low": Severity.LOW,
}

Connector = Callable[[str, HostCredential, WinRmOptions], WinShell]


# ---------- фиксированные скрипты сбора ----------
#
# Каждый скрипт — отдельная команда PowerShell (-EncodedCommand). Разбиты на
# части, чтобы закодированная командная строка каждой укладывалась в предел
# cmd.exe (winexec.MAX_COMMAND_LINE) — это проверяется тестом. Все — только на
# чтение, `$ErrorActionPreference='SilentlyContinue'` глушит отсутствующие
# ключи/значения, "`t" — табуляция в выводе.

_PART_OS = r"""
$ErrorActionPreference='SilentlyContinue'
$v=Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
Write-Output '@@os'
Write-Output ('ProductName' + "`t" + $v.ProductName)
Write-Output ('EditionID' + "`t" + $v.EditionID)
Write-Output ('DisplayVersion' + "`t" + $v.DisplayVersion)
Write-Output ('ReleaseId' + "`t" + $v.ReleaseId)
Write-Output ('CurrentBuildNumber' + "`t" + $v.CurrentBuildNumber)
Write-Output ('UBR' + "`t" + $v.UBR)
Write-Output ('InstallationType' + "`t" + $v.InstallationType)
Write-Output ('Arch' + "`t" + $env:PROCESSOR_ARCHITECTURE)
Write-Output ('Hostname' + "`t" + $env:COMPUTERNAME)
Write-Output '@@end'
""".strip()

_PART_KB = r"""
$ErrorActionPreference='SilentlyContinue'
Write-Output '@@kb'
Get-HotFix | ForEach-Object { Write-Output $_.HotFixID }
Get-ChildItem -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\Packages' |
  ForEach-Object { if ($_.PSChildName -match 'KB[0-9]{6,}') { Write-Output $matches[0] } }
Write-Output '@@end'
""".strip()

_PART_SOFTWARE = r"""
$ErrorActionPreference='SilentlyContinue'
Write-Output '@@software'
$p=@('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
     'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*')
Get-ItemProperty -Path $p |
  Where-Object { $_.DisplayName -and -not $_.SystemComponent -and -not $_.ParentKeyName } |
  ForEach-Object { Write-Output ($_.DisplayName + "`t" + $_.DisplayVersion + "`t" + $_.Publisher) }
Write-Output '@@end'
""".strip()

_PART_POLICY = r"""
$ErrorActionPreference='SilentlyContinue'
Write-Output '@@policy'
function P($n,$path,$name){ Write-Output ($n + "`t" + (Get-ItemProperty -Path $path).$name) }
P 'SMB1' 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' 'SMB1'
P 'RDP_fDenyTSConnections' 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' 'fDenyTSConnections'
P 'RDP_NLA' 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' 'UserAuthentication'
P 'LmCompatibilityLevel' 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'LmCompatibilityLevel'
P 'RunAsPPL' 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'RunAsPPL'
P 'UAC_EnableLUA' 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'EnableLUA'
P 'NoAutoUpdate' 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' 'NoAutoUpdate'
Write-Output '@@end'
""".strip()

INVENTORY_PARTS: tuple[str, ...] = (_PART_OS, _PART_KB, _PART_SOFTWARE, _PART_POLICY)

# Понятное название параметра безопасности для сводки.
_POLICY_LABELS = {
    "SMB1": "SMBv1 (LanmanServer)",
    "RDP_fDenyTSConnections": "RDP (fDenyTSConnections)",
    "RDP_NLA": "RDP NLA (UserAuthentication)",
    "LmCompatibilityLevel": "LM/NTLM (LmCompatibilityLevel)",
    "RunAsPPL": "LSA Protected Process (RunAsPPL)",
    "UAC_EnableLUA": "UAC (EnableLUA)",
    "NoAutoUpdate": "Автообновление отключено (NoAutoUpdate)",
}


# ---------- разбор вывода ----------

def _sections(text: str) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    current: list[str] | None = None
    for line in text.splitlines():
        s = line.rstrip("\r")
        if s.startswith("@@"):
            tag = s[2:].strip()
            current = None if tag == "end" else out.setdefault(tag, [])
            continue
        if current is not None:
            current.append(s)
    return out


def _kv(lines: list[str]) -> dict[str, str]:
    out: dict[str, str] = {}
    for line in lines:
        key, sep, value = line.partition("\t")
        if sep and key.strip():
            out[key.strip()] = value.strip()
    return out


def _int(value: str | None) -> int | None:
    if not value:
        return None
    try:
        return int(str(value).strip())
    except ValueError:
        return None


def parse_os(lines: list[str]) -> WindowsOs:
    kv = _kv(lines)
    return WindowsOs(
        product_name=(kv.get("ProductName") or None),
        edition=(kv.get("EditionID") or None),
        display_version=(kv.get("DisplayVersion") or kv.get("ReleaseId") or None),
        build=_int(kv.get("CurrentBuildNumber")),
        ubr=_int(kv.get("UBR")),
        installation_type=(kv.get("InstallationType") or None),
        arch=(kv.get("Arch") or None),
    )


def parse_kbs(lines: list[str]) -> list[str]:
    seen: dict[str, None] = {}
    for line in lines:
        s = line.strip().upper().removeprefix("KB")
        if s.isdigit() and 6 <= len(s) <= 8:
            seen.setdefault(s, None)
    return list(seen)


def parse_software(lines: list[str]) -> list[InstalledPackage]:
    out: list[InstalledPackage] = []
    seen: set[tuple[str, str]] = set()
    for line in lines:
        parts = line.split("\t")
        name = parts[0].strip()[:200] if parts else ""
        version = (parts[1].strip()[:200] if len(parts) > 1 else "")
        if not name:
            continue
        key = (name, version)
        if key in seen or len(out) >= MAX_SOFTWARE:
            continue
        seen.add(key)
        out.append(InstalledPackage(name=name, version=version or "—",
                                    manager=PKG_MANAGER))
    return out


def parse_policy(lines: list[str]) -> dict[str, str]:
    return {k: v for k, v in _kv(lines).items() if v != ""}


@dataclass(slots=True)
class WinInventory:
    """Разобранный инвентарь Windows-хоста."""
    os: WindowsOs
    kbs: list[str] = field(default_factory=list)
    software: list[InstalledPackage] = field(default_factory=list)
    policy: dict[str, str] = field(default_factory=dict)


def parse_inventory(text: str) -> WinInventory:
    sec = _sections(text)
    return WinInventory(
        os=parse_os(sec.get("os", [])),
        kbs=parse_kbs(sec.get("kb", [])),
        software=parse_software(sec.get("software", [])),
        policy=parse_policy(sec.get("policy", [])),
    )


def to_host_inventory(host: str, inv: WinInventory, credential_id: int | None
                      ) -> HostInventory:
    """WinInventory -> HostInventory для сохранения (ОС + ПО как «пакеты»)."""
    return HostInventory(
        host=host, os_id="windows", os_name=inv.os.label,
        os_version=inv.os.version, kernel=None, hostname=None,
        packages=list(inv.software), credential_id=credential_id)


# ---------- модуль ----------

@dataclass(slots=True)
class WinInventoryOptions:
    winrm: WinRmOptions = field(default_factory=WinRmOptions)
    command_timeout_sec: float = 180.0
    max_parallel_hosts: int = 8          # верхняя граница; реальная — min с профилем


class _Matcher:
    """Интерфейс слоя сопоставления (feeds.matcher.VulnMatcher)."""

    store: object

    def findings_for_package(self, host: str, **kw) -> list[Finding]: ...

    def enrich(self, finding: Finding) -> Finding: ...


class WinInventoryModule(ScanModule):
    name = MODULE

    def __init__(self, options: WinInventoryOptions | None = None,
                 matcher: _Matcher | None = None, connector: Connector | None = None,
                 msrc_store: object | None = None,
                 sleep: Callable[[float], None] = time.sleep):
        self.options = options or WinInventoryOptions()
        self._matcher = matcher
        self._connect = connector or connect
        self._msrc_store = msrc_store
        self._sleep = sleep

    # --- сбор ---
    def _collect(self, ctx: ScanContext, throttle: _Throttle, host: str,
                 creds: list[HostCredential]
                 ) -> tuple[WinInventory | None, HostCredential | None, list[Finding]]:
        notes: list[Finding] = []
        for cred in creds:
            info = cred.describe()
            throttle.wait()
            ctx.audit.record(subject="scanner", action="win_inventory_winrm", target=host,
                             result="started", details=info)
            try:
                shell = self._connect(host, cred, self.options.winrm)
            except AuthFailed as e:
                ctx.audit.record(subject="scanner", action="win_inventory_winrm",
                                 target=host, result="auth_failed",
                                 details={**info, "error": str(e)[:300]})
                notes.append(self._info(host, "INFO:win-inventory-auth-failed",
                                        "Вход по учётной записи WinRM отклонён",
                                        f"учётка «{cred.name}» ({cred.username}@{host}:"
                                        f"{cred.port}): {e}"))
                continue                      # следующая WinRM-учётка из области хоста
            except CertMismatch as e:
                ctx.audit.record(subject="scanner", action="win_inventory_winrm",
                                 target=host, result="cert_mismatch",
                                 details={**info, "error": str(e)[:300]})
                return None, None, [self._info(
                    host, "INFO:win-inventory-cert", "Сертификат WinRM не прошёл проверку",
                    str(e))]
            except Unreachable as e:
                ctx.audit.record(subject="scanner", action="win_inventory_winrm",
                                 target=host, result="unreachable",
                                 details={**info, "error": str(e)[:300]})
                return None, None, [self._info(
                    host, "INFO:win-inventory-unreachable", "Хост недоступен по WinRM",
                    f"{host}:{cred.port}: {e}")]
            except (WinRmError, ValueError) as e:
                ctx.audit.record(subject="scanner", action="win_inventory_winrm",
                                 target=host, result="error",
                                 details={**info, "error": str(e)[:300]})
                notes.append(self._info(host, "INFO:win-inventory-error",
                                        "Инвентаризация Windows по WinRM не выполнена",
                                        str(e)[:500]))
                continue
            try:
                text, truncated = self._run_parts(shell)
            except WinRmError as e:
                ctx.audit.record(subject="scanner", action="win_inventory_exec",
                                 target=host, result="error",
                                 details={**info, "error": str(e)[:300]})
                return None, None, [*notes, self._info(
                    host, "INFO:win-inventory-error",
                    "Инвентаризация Windows по WinRM не выполнена", str(e)[:500])]
            finally:
                shell.close()
            inv = parse_inventory(text)
            ctx.audit.record(subject="scanner", action="win_inventory_exec", target=host,
                             result="ok" if inv.os.build is not None else "no_os",
                             details={**info, "truncated": truncated,
                                      "kbs": len(inv.kbs), "software": len(inv.software),
                                      "os": inv.os.label})
            return inv, cred, []   # вход удался — заметки об отказах не нужны
        return None, None, notes

    def _run_parts(self, shell: WinShell) -> tuple[str, bool]:
        """Выполняет части сбора по очереди в одной сессии; вывод конкатенируется."""
        chunks: list[str] = []
        truncated = False
        for part in INVENTORY_PARTS:
            res = shell.run_powershell(part, self.options.command_timeout_sec)
            chunks.append(res.stdout.decode("utf-8", "replace"))
            truncated = truncated or res.truncated
        return "\n".join(chunks), truncated

    # --- сопоставление ОС -> отсутствующие обновления (MSRC) ---
    def _assess_os(self, ctx: ScanContext, host: str, inv: WinInventory,
                   store: object) -> tuple[Assessment, list[Finding]]:
        try:
            a = assess(inv.os, inv.kbs, store)
        except Exception as e:  # noqa: BLE001 — справочник недоступен: инвентарь важнее
            ctx.audit.record(subject="scanner", action="win_inventory_msrc", target=host,
                             result="error", details=f"{type(e).__name__}: {e}"[:300])
            return Assessment(None, no_data=True, reason="ошибка справочника MSRC"), []
        findings = [self._gap_finding(host, inv.os, a.product, g) for g in a.gaps]
        ctx.audit.record(subject="scanner", action="win_inventory_msrc", target=host,
                         result="no_data" if a.no_data else "ok",
                         details={"product": a.product, "gaps": len(a.gaps),
                                  "fixed": a.fixed, "reason": a.reason})
        return a, findings

    def _gap_finding(self, host: str, os: WindowsOs, product: str | None,
                     gap: KbGap) -> Finding:
        msrc_sev = _MSRC_SEVERITY.get((gap.severity or "").lower())
        cvss_sev = severity_from_cvss(gap.cvss)
        # Нет ни severity бюллетеня, ни CVSS — отсутствующее обновление всё равно
        # не INFO: по умолчанию MEDIUM (max_severity вернул бы INFO).
        sev = (max_severity(msrc_sev, cvss_sev) if (msrc_sev or cvss_sev)
               else Severity.MEDIUM)
        title = gap.title or f"{gap.cve_id}: нет обновления безопасности Windows"
        rec = gap.recommended_kb or (gap.fix_kbs[0] if gap.fix_kbs else None)
        remediation_lines = []
        if rec:
            remediation_lines.append(
                f"Установите обновление Microsoft KB{rec} (последнее в цепочке "
                f"замещения закрывает {gap.cve_id}).")
            remediation_lines.append(CATALOG_URL.format(kb=rec))
        if gap.fixed_build:
            remediation_lines.append(f"Сборка с исправлением: не ниже {gap.fixed_build}.")
        remediation_lines.append(GUIDE_URL.format(cve=gap.cve_id))
        f = Finding(module=MODULE, host=host, port=None, finding_type=FindingType.VULN,
                    title=title, severity=sev, vuln_id=gap.cve_id, cve_ids=[gap.cve_id],
                    cvss=gap.cvss, remediation="\n".join(remediation_lines))
        if self._matcher is not None:          # связать с БДУ ФСТЭК по CVE
            try:
                self._matcher.enrich(f)
            except Exception:  # noqa: BLE001 — справочник недоступен: находка остаётся по CVE
                pass
        evidence = [f"Продукт MSRC: {product or '—'}",
                    f"ОС хоста: {os.label}" + (f" ({os.version})" if os.version else "")]
        if gap.fix_kbs:
            evidence.append("KB с исправлением: "
                            + ", ".join(f"KB{k}" for k in gap.fix_kbs))
        if rec:
            evidence.append(f"Рекомендуемое (накопительное) обновление: KB{rec}")
        evidence.append(f"Бюллетень: {gap.release}")
        f.evidence = "\n".join(evidence)
        return f

    # --- сопоставление ПО -> БДУ/NVD ---
    def _match_software(self, ctx: ScanContext, host: str,
                        software: list[InstalledPackage], matcher: _Matcher
                        ) -> list[Finding]:
        out: dict[str, Finding] = {}
        matched = 0
        for sw in software:
            if not sw.version or sw.version == "—":
                continue
            try:
                found = matcher.findings_for_package(
                    host, product=sw.name, version=sw.version, cpe=None,
                    packages=[sw.name], use_nvd=False, module=self.name)
            except Exception as e:  # noqa: BLE001 — справочник недоступен: ПО важнее
                ctx.audit.record(subject="scanner", action="win_inventory_match",
                                 target=host, result="error",
                                 details={"software": sw.name,
                                          "error": f"{type(e).__name__}: {e}"[:300]})
                continue
            if found:
                matched += 1
            for f in found:
                out.setdefault(f.vuln_id or "", f)
        ctx.audit.record(subject="scanner", action="win_inventory_match", target=host,
                         result="ok", details={"software": len(software),
                                               "matched_software": matched,
                                               "findings": len(out)})
        return list(out.values())

    @staticmethod
    def _info(host: str, vuln_id: str, title: str, evidence: str | None) -> Finding:
        return Finding(module=MODULE, host=host, finding_type=FindingType.INFO,
                       title=title, severity=Severity.INFO, vuln_id=vuln_id,
                       evidence=evidence)

    def _summary(self, host: str, inv: WinInventory, cred: HostCredential | None,
                 a: Assessment, sw_findings: int) -> Finding:
        lines = [f"ОС: {inv.os.label}"]
        if inv.os.version:
            lines.append(f"версия (сборка): {inv.os.version}")
        lines.append(f"установленных обновлений (KB): {len(inv.kbs)}")
        lines.append(f"установленного ПО: {len(inv.software)}")
        if a.no_data:
            lines.append(f"обновления Windows: {a.reason or 'нет данных MSRC'}")
        else:
            lines.append(f"отсутствующих обновлений (CVE продукта Windows): "
                         f"{len(a.gaps)}; закрыто установленными: {a.fixed}")
        lines.append(f"уязвимостей по версиям ПО: {sw_findings}")
        if cred is not None:
            lines.append(f"учётная запись: «{cred.name}» ({cred.username}, WinRM)")
        title = (f"Инвентаризация Windows по учётной записи: {inv.os.label}, "
                 f"ПО — {len(inv.software)}, KB — {len(inv.kbs)}")
        return self._info(host, "INFO:win-inventory", title, "\n".join(lines))

    def _policy_finding(self, host: str, policy: dict[str, str]) -> Finding | None:
        if not policy:
            return None
        lines = [f"{_POLICY_LABELS.get(k, k)}: {v}" for k, v in policy.items()]
        return self._info(host, "INFO:win-inventory-policy",
                          "Параметры безопасности Windows", "\n".join(lines))

    def _hosts(self, ctx: ScanContext) -> list[str]:
        hosts = []
        for t in ctx.targets:
            try:
                hosts.append(str(ipaddress.ip_address(t.strip())))
            except ValueError:
                ctx.audit.record(subject="scanner", action="win_inventory_deny", target=t,
                                 result="not_an_ip_literal")
        if "discovery" in ctx.completed and ctx.services is not None:
            # discovery отработал: не стучимся по WinRM в хосты, которых он не нашёл.
            alive = {s.host for s in ctx.services}
            for h in hosts:
                if h not in alive:
                    ctx.audit.record(subject="scanner", action="win_inventory_skip",
                                     target=h, result="host_not_discovered")
            hosts = [h for h in hosts if h in alive]
        return hosts

    def run(self, ctx: ScanContext) -> list[Finding]:
        from concurrent.futures import ThreadPoolExecutor

        jobs: list[tuple[str, list[HostCredential]]] = []
        for host in self._hosts(ctx):
            creds = credentials_for_host(host, ctx.credentials, protocol=PROTOCOL_WINRM)
            if not creds:
                ctx.audit.record(subject="scanner", action="win_inventory_skip",
                                 target=host, result="no_winrm_credentials")
                continue
            jobs.append((host, creds))
        if not jobs:
            return []

        throttle = _Throttle(ctx.rate, sleep=self._sleep)
        workers = max(1, min(self.options.max_parallel_hosts, ctx.rate.max_concurrency,
                             len(jobs)))
        with ThreadPoolExecutor(max_workers=workers,
                                thread_name_prefix="win-inventory") as pool:
            collected = list(pool.map(lambda j: (j, self._collect(ctx, throttle, *j)), jobs))

        matcher = self._run_matcher()
        store = self._resolve_msrc_store()
        findings: list[Finding] = []
        for (host, _creds), (inv, cred, notes) in collected:
            findings.extend(notes)
            if inv is None:
                continue
            ctx.inventory[host] = to_host_inventory(host, inv,
                                                    cred.id if cred else None)
            if store is not None:
                a, os_findings = self._assess_os(ctx, host, inv, store)
            else:
                a = Assessment(None, no_data=True,
                               reason="справочник MSRC не загружен "
                                      "(scanner feeds sync-msrc)")
                os_findings = []
                ctx.audit.record(subject="scanner", action="win_inventory_msrc",
                                 target=host, result="no_store")
            sw_findings = (self._match_software(ctx, host, inv.software, matcher)
                           if matcher is not None else [])
            findings.append(self._summary(host, inv, cred, a, len(sw_findings)))
            if inv.policy:
                record_fact(ctx.compliance_facts, host, "windows_policy", dict(inv.policy))
            policy = self._policy_finding(host, inv.policy)
            if policy is not None:
                findings.append(policy)
            findings.extend(os_findings)
            findings.extend(sw_findings)
        return findings

    def _resolve_msrc_store(self) -> object | None:
        """Справочник MSRC: переданный явно или над тем же engine, что и matcher."""
        if self._msrc_store is not None:
            return self._msrc_store
        store = getattr(self._matcher, "store", None)
        engine = getattr(store, "engine", None)
        if engine is None:
            return None
        from scanner.feeds.msrc import MsrcStore
        try:
            s = MsrcStore(engine)
            return s if s.count() else None     # пустой справочник -> «нет данных»
        except Exception:  # noqa: BLE001 — таблицы нет/БД недоступна
            return None

    def _run_matcher(self) -> _Matcher | None:
        """Matcher прогона с кэшем справочника (одно и то же ПО на многих хостах)."""
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
