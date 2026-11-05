"""«Нет ложной чистоты»: сломанная проверка — пробел покрытия («Частично»),
а не «проверено, уязвимостей нет».

Каждый тест воспроизводит сбой, который раньше попадал только в журнал аудита
(или вовсе никуда), а хост оставался «проверен».
"""
from __future__ import annotations

import pytest

from scanner.core import coverage as cv
from scanner.core.models import ServiceInfo
from scanner.core.ratelimit import RateProfile, get_profile
from scanner.feeds.matcher import VulnMatcher
from scanner.feeds.store import (
    CachingReferenceStore,
    InMemoryReferenceStore,
    UnavailableReferenceStore,
)
from scanner.modules.base import ScanContext
from scanner.modules.config_audit import ConfigAuditError, parse_lynis_report
from scanner.modules.cred_audit import (
    AuthOutcome,
    CredentialAuditModule,
    CredentialAuditOptions,
    Probe,
)
from scanner.modules.discovery import DiscoveryModule, nmap_timed_out_hosts
from scanner.modules.vuln import (
    NucleiOutput,
    VulnModule,
    VulnOptions,
    VulnScanError,
    build_nuclei_command,
    nuclei_no_templates,
    nuclei_skipped_hosts,
)
from tests import test_auth_inventory as ai
from tests import test_win_inventory as wi
from tests.test_cred_audit import ScriptedAuth, _creds
from tests.test_vuln import ListAudit

LINE_5 = ('{"template-id":"x","host":"http://10.0.0.5:80","ip":"10.0.0.5","port":"80",'
          '"info":{"name":"X","severity":"high","classification":{"cve-id":["CVE-2021-1"]}}}')


def _vctx(services, targets=None):
    return ScanContext(engagement_id=1, scan_run_id=1,
                       targets=targets or sorted({s.host for s in services}),
                       rate=get_profile("gentle"), audit=ListAudit(), services=services)


def _http(host, product=None, version=None):
    return ServiceInfo(host=host, port=80, protocol="tcp", service="http",
                       product=product, version=version)


def _gap(ctx, host, module):
    e = ctx.coverage.get(host, module)
    assert e is not None and e.is_gap, f"{host}/{module}: {e}"
    return e


# ---------- Nuclei ----------

def test_failed_batch_keeps_other_batches_and_marks_only_its_hosts():
    calls = []

    def runner(cmd, targets, timeout):
        calls.append(targets)
        if "10.0.0.6" in targets:
            raise VulnScanError("nuclei rc=1: boom")
        return LINE_5

    ctx = _vctx([_http("10.0.0.5"), _http("10.0.0.6")])
    out = VulnModule(VulnOptions(batch_size=1), runner=runner).run(ctx)
    assert len(calls) == 2
    assert any(f.vuln_id == "CVE-2021-1" for f in out)        # находки 1-й пачки целы
    assert "boom" in _gap(ctx, "10.0.0.6", "vuln").reason
    assert ctx.coverage.get("10.0.0.5", "vuln") is None        # отметит finalize: completed
    assert any(f.vuln_id == "INFO:vuln-scan-error" and f.host == "10.0.0.6" for f in out)


def test_all_batches_failed_is_module_error():
    def runner(cmd, targets, timeout):
        raise VulnScanError("nuclei rc=1")

    ctx = _vctx([_http("10.0.0.5"), _http("10.0.0.6")])
    with pytest.raises(VulnScanError):
        VulnModule(VulnOptions(batch_size=1), runner=runner).run(ctx)


def test_host_skipped_by_nuclei_is_gap():
    err = ("[INF] Templates loaded for current scan: 4000\n"
           "[WRN] [http-missing-security-headers] Skipped 10.0.0.6:80 from target list "
           "as found unresponsive 30 times\n")
    ctx = _vctx([_http("10.0.0.5"), _http("10.0.0.6")])
    out = VulnModule(runner=lambda c, t, s: NucleiOutput(LINE_5, err)).run(ctx)
    assert "серии ошибок" in _gap(ctx, "10.0.0.6", "vuln").reason
    assert ctx.coverage.get("10.0.0.5", "vuln") is None
    assert any(f.vuln_id == "INFO:vuln-host-skipped" for f in out)


def test_stderr_parsing():
    assert nuclei_skipped_hosts(
        "Skipped http://10.0.0.7:8080 from target list as found unresponsive 30 times\n"
        "Skipped [fd00::1]:443 from target list as found unresponsive permanently\n"
        "Skipped 10.0.0.8 from target list as found unresponsive 30 times") == [
        "10.0.0.7", "fd00::1", "10.0.0.8"]
    assert nuclei_no_templates("[INF] Templates loaded for current scan: 0")
    assert nuclei_no_templates("[FTL] Could not run nuclei: no templates provided for scan")
    assert not nuclei_no_templates("[INF] Templates loaded for current scan: 12")
    assert not nuclei_no_templates("")


def test_zero_templates_is_error_not_clean():
    ctx = _vctx([_http("10.0.0.5")])
    with pytest.raises(VulnScanError, match="ни одного шаблона"):
        VulnModule(runner=lambda c, t, s: NucleiOutput(
            "", "[INF] Templates loaded for current scan: 0\n")).run(ctx)


def test_nuclei_log_is_kept_for_parsing():
    # -silent гасит лог Nuclei, а по нему видно исключённые хосты
    assert "-silent" not in build_nuclei_command(get_profile("gentle"), VulnOptions())


class _BrokenServiceMatcher:
    store = None

    def enrich(self, f):
        return f

    def findings_for_service(self, service, *, module):
        raise RuntimeError("database is locked")


def test_banner_match_error_is_gap():
    ctx = _vctx([_http("10.0.0.5", "Apache httpd", "2.4.49")])
    VulnModule(runner=lambda c, t, s: "", matcher=_BrokenServiceMatcher()).run(ctx)
    assert "database is locked" in _gap(ctx, "10.0.0.5", "vuln").reason


def test_empty_bdu_is_gap_only_where_versions_exist():
    ctx = _vctx([_http("10.0.0.5", "Apache httpd", "2.4.49"), _http("10.0.0.6")])
    VulnModule(runner=lambda c, t, s: "",
               matcher=VulnMatcher(InMemoryReferenceStore())).run(ctx)
    assert "БДУ ФСТЭК пуст" in _gap(ctx, "10.0.0.5", "vuln").reason
    assert ctx.coverage.get("10.0.0.6", "vuln") is None      # сопоставлять было нечего


def test_reference_gap():
    assert cv.reference_gap(None) is None
    assert cv.reference_gap(VulnMatcher(ai.reference_store())) is None
    assert "пуст" in cv.reference_gap(VulnMatcher(InMemoryReferenceStore()))
    cached = VulnMatcher(CachingReferenceStore(InMemoryReferenceStore()))
    assert "пуст" in cv.reference_gap(cached)
    assert "недоступны" in cv.reference_gap(VulnMatcher(UnavailableReferenceStore("x")))


# ---------- инвентаризация по SSH ----------

def _auth_run(matcher):
    mod = ai.AuthInventoryModule(matcher=matcher, sleep=lambda s: None,
                                 connector=lambda h, c, o: ai.FakeShell(ai.DPKG_OUT))
    ctx = ai.ctx_for(["10.0.0.5"], [ai.cred(1)], ai.Audit())
    return mod.run(ctx), ctx


def test_auth_inventory_happy_path_is_completed():
    _, ctx = _auth_run(VulnMatcher(ai.reference_store()))
    assert ctx.coverage.status("10.0.0.5", "auth_inventory") == cv.COMPLETED


def test_auth_inventory_empty_reference_is_gap():
    _, ctx = _auth_run(VulnMatcher(InMemoryReferenceStore()))
    assert "БДУ ФСТЭК пуст" in _gap(ctx, "10.0.0.5", "auth_inventory").reason
    assert ctx.inventory["10.0.0.5"].packages                  # инвентарь сохранён


def test_auth_inventory_unavailable_reference_is_gap():
    _, ctx = _auth_run(VulnMatcher(UnavailableReferenceStore("connection refused")))
    assert "недоступны" in _gap(ctx, "10.0.0.5", "auth_inventory").reason


class _FlakyStore(InMemoryReferenceStore):
    """Справочник, у которого падает запрос по одному продукту (OpenSSH)."""

    def cpe_matches(self, product):
        if "openssh" in product.lower():
            raise RuntimeError("statement timeout")
        return super().cpe_matches(product)


def _flaky_store():
    src, store = ai.reference_store(), _FlakyStore()
    store.upsert_nvd(src.nvd.values())
    store.upsert_bdu(src.bdu.values())
    return store


def test_auth_inventory_match_error_is_gap_but_keeps_other_findings():
    findings, ctx = _auth_run(VulnMatcher(_flaky_store()))
    assert "statement timeout" in _gap(ctx, "10.0.0.5", "auth_inventory").reason
    assert any(f.vuln_id == "CVE-2023-0464" for f in findings)   # OpenSSL сопоставлен


# ---------- Windows ----------

def test_windows_without_msrc_is_gap():
    module = wi.WinInventoryModule(matcher=wi.FakeMatcher(), msrc_store=None,
                                   connector=lambda h, c, o: wi.FakeWinShell(wi.ALL_OUT),
                                   sleep=lambda s: None)
    ctx = wi._ctx([wi._winrm_cred()])
    module.run(ctx)
    assert "обновления Windows не проверены" in _gap(ctx, wi.HOST, "win_inventory").reason


def test_windows_with_msrc_is_completed():
    _, ctx, _ = wi._run([wi._winrm_cred()])
    assert ctx.coverage.status(wi.HOST, "win_inventory") == cv.COMPLETED


class _BrokenWinMatcher(wi.FakeMatcher):
    def findings_for_package(self, host, **kw):
        raise RuntimeError("bdu down")

    def enrich(self, finding):
        raise RuntimeError("bdu down")


def test_windows_matcher_errors_are_gap():
    findings, ctx, _ = wi._run([wi._winrm_cred()], matcher=_BrokenWinMatcher())
    assert "bdu down" in _gap(ctx, wi.HOST, "win_inventory").reason
    assert any(f.vuln_id == "CVE-2024-0001" for f in findings)   # находка MSRC цела


# ---------- аудит конфигурации / паролей / discovery ----------

def test_empty_lynis_report_is_error():
    with pytest.raises(ConfigAuditError, match="пустой отчёт"):
        parse_lynis_report("", "10.0.0.5")
    findings, _ = parse_lynis_report("lynis_version=3.0.9\ntests_executed=AUTH-9208|\n",
                                     "10.0.0.5")
    assert findings == []                                       # чистый, но реальный отчёт


@pytest.mark.parametrize("sequence,expect", [
    ([AuthOutcome.FAILURE, AuthOutcome.LOCKOUT], "блокировка"),
    ([AuthOutcome.ERROR] * 3, "ошибок соединения"),
])
def test_cred_audit_stopped_host_is_gap(sequence, expect):
    auth = ScriptedAuth(default=AuthOutcome.FAILURE, sequence=sequence)
    opts = CredentialAuditOptions(credentials=_creds(*[(f"u{i}", "p") for i in range(5)]),
                                  max_attempts_per_account=9, max_consecutive_errors=3,
                                  probes=[Probe("10.0.0.5", 22, "ssh")])
    ctx = ScanContext(engagement_id=1, scan_run_id=1, targets=["10.0.0.5"],
                      rate=RateProfile("t", 100, 8, 0.0, 50, 2.0), audit=ListAudit())
    CredentialAuditModule(opts, authenticator=auth, sleep=lambda s: None).run(ctx)
    assert expect in _gap(ctx, "10.0.0.5", "cred_audit").reason


NMAP_TIMEOUT_XML = """<?xml version="1.0"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap" args="nmap" start="1" version="7.94" xmloutputversion="1.05">
<host starttime="1" endtime="2"><status state="up" reason="echo-reply"/>
<address addr="10.0.0.5" addrtype="ipv4"/>
<ports><port protocol="tcp" portid="22"><state state="open" reason="syn-ack"/>
<service name="ssh"/></port></ports></host>
<host starttime="1" endtime="900" timedout="true"><status state="up" reason="echo-reply"/>
<address addr="10.0.0.6" addrtype="ipv4"/>
<ports><port protocol="tcp" portid="80"><state state="open" reason="syn-ack"/>
<service name="http"/></port></ports></host>
<runstats><finished time="900"/><hosts up="2" down="0" total="2"/></runstats>
</nmaprun>
"""


def test_nmap_host_timeout_is_gap():
    assert nmap_timed_out_hosts(NMAP_TIMEOUT_XML) == ["10.0.0.6"]
    assert nmap_timed_out_hosts("not xml") == []
    ctx = ScanContext(engagement_id=1, scan_run_id=1, targets=["10.0.0.5", "10.0.0.6"],
                      rate=get_profile("gentle"), audit=ListAudit())
    DiscoveryModule(runner=lambda cmd, timeout: NMAP_TIMEOUT_XML).run(ctx)
    assert ctx.coverage.status("10.0.0.5", "discovery") == cv.COMPLETED
    assert _gap(ctx, "10.0.0.6", "discovery").status == cv.TIMEOUT


# ---------- итог прогона ----------

def test_match_gap_makes_run_partial_not_done():
    cov = cv.Coverage()
    cov.mark("10.0.0.5", "discovery", cv.COMPLETED)
    cov.mark("10.0.0.5", "auth_inventory", cv.COMPLETED)
    cov.mark("10.0.0.5", "auth_inventory", cv.ERROR,
             cv.match_failed("сопоставление OpenSSH с БДУ/NVD", RuntimeError("x")))
    status, message = cv.run_verdict(cov, ["10.0.0.5"])
    assert status == "partial" and "сопоставление OpenSSH" in message

