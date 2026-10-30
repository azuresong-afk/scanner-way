"""Аудит Windows по WinRM (modules/win_inventory.py): разбор, сопоставление, модуль.

WinRM-сессия заменяется фейковой оболочкой (FakeWinShell): модуль прогоняет свои
фиксированные скрипты PowerShell, а оболочка возвращает заранее заданный вывод —
так проверяется разбор вывода, сопоставление с MSRC/БДУ и гарантии безопасности
(только WinRM-учётки, пароль не утекает в аудит) без настоящего Windows-хоста.
"""
from __future__ import annotations

from scanner.core.credentials import PROTOCOL_SSH, PROTOCOL_WINRM, HostCredential
from scanner.core.models import Finding, FindingType, Severity
from scanner.core.ratelimit import RateProfile
from scanner.core.sshexec import CommandResult
from scanner.core.winexec import AuthFailed, MAX_COMMAND_LINE, Unreachable, encode_powershell
from scanner.feeds.msrc import InMemoryMsrcStore, MsrcFix
from scanner.modules.base import ScanContext
from scanner.modules.win_inventory import (
    INVENTORY_PARTS,
    WinInventoryModule,
    parse_inventory,
)
from tests.test_auth_inventory import Audit

FAST = RateProfile("t", 1000, 4, 0.0, 3, 2.0)
HOST = "10.0.0.7"
WIN_PASSWORD = "Win-Pa55-do-not-leak"
SERVER2019 = "Windows Server 2019"

OS_OUT = (
    "@@os\n"
    "ProductName\tWindows Server 2019 Standard\n"
    "EditionID\tServerStandard\n"
    "DisplayVersion\t1809\n"
    "CurrentBuildNumber\t17763\n"
    "UBR\t100\n"
    "InstallationType\tServer\n"
    "Arch\tAMD64\n"
    "Hostname\tDC01\n"
    "@@end\n"
)
KB_OUT = "@@kb\nKB5000001\nKB5033420\n@@end\n"
SOFTWARE_OUT = (
    "@@software\n"
    "Google Chrome\t120.0.6099.109\tGoogle LLC\n"
    "7-Zip 23.01\t23.01\tIgor Pavlov\n"
    "Служебное\t\tMicrosoft\n"                 # без версии — в сопоставление не идёт
    "@@end\n"
)
POLICY_OUT = "@@policy\nSMB1\t0\nRDP_NLA\t1\nRunAsPPL\t\n@@end\n"
ALL_OUT = [OS_OUT, KB_OUT, SOFTWARE_OUT, POLICY_OUT]


class FakeWinShell:
    """Оболочка WinRM: отдаёт вывод для каждого скрипта по порядку частей сбора."""

    def __init__(self, outputs: list[str]):
        self._outputs = list(outputs)
        self.scripts: list[str] = []
        self.closed = False

    def run_powershell(self, script: str, timeout: float) -> CommandResult:
        self.scripts.append(script)
        out = self._outputs.pop(0) if self._outputs else ""
        return CommandResult(0, out.encode("utf-8"), "")

    def close(self) -> None:
        self.closed = True


class FakeMatcher:
    """Лёгкий слой сопоставления: Chrome -> запись БДУ, остальное — пусто."""
    store = None

    def findings_for_package(self, host, *, product, version, **kw):
        if product.startswith("Google Chrome"):
            return [Finding(module=kw["module"], host=host, port=None,
                            finding_type=FindingType.VULN,
                            title=f"Уязвимость в {product}", severity=Severity.HIGH,
                            vuln_id="BDU:2024-10000", bdu_ids=["BDU:2024-10000"])]
        return []

    def enrich(self, finding: Finding) -> Finding:
        if finding.vuln_id and finding.vuln_id.startswith("CVE-"):
            finding.bdu_ids = [*finding.bdu_ids, "BDU:2024-00001"]
        return finding


def _winrm_cred(cid=1, targets=()):
    return HostCredential(cid, "win", "password", "DOMAIN\\svc", port=5986,
                          targets=targets, password=WIN_PASSWORD,
                          protocol=PROTOCOL_WINRM)


def _msrc_store():
    return InMemoryMsrcStore([
        MsrcFix("2024-Jan", "CVE-2024-0001", "11569", SERVER2019, "5034127",
                supersedes=("5033420",), fixed_build="10.0.17763.5329",
                severity="Critical", cvss=9.8, title="RCE в SMB"),
    ])


def _ctx(creds):
    return ScanContext(engagement_id=1, scan_run_id=1, targets=[HOST], rate=FAST,
                       audit=Audit(), credentials=list(creds))


def _run(creds, connector=None, msrc_store=None, matcher=None):
    shell = FakeWinShell(ALL_OUT)
    module = WinInventoryModule(
        matcher=matcher if matcher is not None else FakeMatcher(),
        connector=connector or (lambda h, c, o: shell),
        msrc_store=msrc_store if msrc_store is not None else _msrc_store(),
        sleep=lambda s: None)
    ctx = _ctx(creds)
    findings = module.run(ctx)
    return findings, ctx, shell


# ---------- разбор вывода ----------

def test_parse_inventory_reads_os_kbs_software_policy():
    inv = parse_inventory("".join(ALL_OUT))
    assert inv.os.build == 17763 and inv.os.ubr == 100 and inv.os.is_server
    assert "Server 2019" in inv.os.label and inv.os.version == "10.0.17763.100"
    assert set(inv.kbs) == {"5000001", "5033420"}
    names = {p.name for p in inv.software}
    assert "Google Chrome" in names and "7-Zip 23.01" in names
    assert all(p.manager == "windows" for p in inv.software)
    assert inv.policy["SMB1"] == "0" and inv.policy["RDP_NLA"] == "1"
    assert "RunAsPPL" not in inv.policy          # пустое значение отброшено


def test_command_line_parts_fit_budget():
    for part in INVENTORY_PARTS:
        assert len(encode_powershell(part)) <= MAX_COMMAND_LINE


# ---------- модуль целиком ----------

def test_run_collects_and_matches_os_and_software():
    findings, ctx, shell = _run([_winrm_cred()])
    assert shell.closed
    by_id = {f.vuln_id: f for f in findings}

    # отсутствующее обновление Windows из MSRC
    gap = by_id["CVE-2024-0001"]
    assert gap.finding_type == FindingType.VULN and gap.severity == Severity.CRITICAL
    assert gap.port is None and gap.module == "win_inventory"
    assert "KB5034127" in gap.remediation and "catalog.update.microsoft.com" in gap.remediation
    assert "BDU:2024-00001" in gap.bdu_ids        # связано с БДУ при обогащении

    # уязвимость установленного ПО (Chrome -> БДУ)
    assert by_id["BDU:2024-10000"].module == "win_inventory"

    # инвентарь сохранён для страницы хоста (ОС + ПО как «пакеты»)
    inv = ctx.inventory[HOST]
    assert inv.os_family == "windows" and inv.credential_id == 1
    assert {p.name for p in inv.packages} >= {"Google Chrome", "7-Zip 23.01"}

    # сводка и параметры безопасности
    summary = by_id["INFO:win-inventory"]
    assert "отсутствующих обновлений" in summary.evidence
    assert by_id["INFO:win-inventory-policy"].finding_type == FindingType.INFO


def test_password_never_in_audit():
    _, ctx, _ = _run([_winrm_cred()])
    assert WIN_PASSWORD not in repr(ctx.audit.records)
    started = ctx.audit.actions("win_inventory_winrm")
    assert started and all(WIN_PASSWORD not in str(r["details"]) for r in started)


def test_skips_host_without_winrm_credential():
    ssh = HostCredential(2, "ssh", "password", "root", port=22, password="x",
                         protocol=PROTOCOL_SSH)
    findings, ctx, _ = _run([ssh])
    assert findings == []
    assert ctx.audit.actions("win_inventory_skip")[0]["result"] == "no_winrm_credentials"


def test_auth_failure_is_reported_not_fatal():
    def connector(h, c, o):
        raise AuthFailed("учётные данные отклонены")

    findings, ctx, _ = _run([_winrm_cred()], connector=connector)
    ids = {f.vuln_id for f in findings}
    assert "INFO:win-inventory-auth-failed" in ids
    assert HOST not in ctx.inventory
    assert ctx.audit.actions("win_inventory_winrm")[-1]["result"] == "auth_failed"


def test_unreachable_host_reported():
    def connector(h, c, o):
        raise Unreachable("нет WinRM-соединения")

    findings, ctx, _ = _run([_winrm_cred()], connector=connector)
    assert {f.vuln_id for f in findings} == {"INFO:win-inventory-unreachable"}


def test_no_msrc_store_means_no_data_not_no_vulns():
    # msrc_store=None и matcher.store=None -> справочник MSRC не разрешить
    module = WinInventoryModule(matcher=FakeMatcher(),
                                connector=lambda h, c, o: FakeWinShell(ALL_OUT),
                                msrc_store=None, sleep=lambda s: None)
    ctx = _ctx([_winrm_cred()])
    out = module.run(ctx)
    summary = next(f for f in out if f.vuln_id == "INFO:win-inventory")
    assert "нет данных" in summary.evidence or "не загружен" in summary.evidence
    assert not any(f.vuln_id == "CVE-2024-0001" for f in out)   # без справочника — не «нет уязвимостей»
