"""Достоверность прогонов (лабораторные проверки на Kali / Debian 13).

1. Выключенный хост: прогон не «успешный», причина — «Хост недоступен,
   проверка не выполнена».
2. Хост доступен, SSH timeout: сетевые результаты есть, прогон partial,
   отсутствие пакетного аудита видно в покрытии.
5. Находка только по баннеру — пониженная уверенность; проверка по учётке
   главнее.
6. Прогоны с разными хостами/модулями: нет ложных fixed/regression.
Плюс предварительная проверка TCP/SSH с повтором, -Pn и профили проверки.
"""
from __future__ import annotations

import socket
import threading

import pytest

from scanner.core import coverage as cv
from scanner.core import repository as repo
from scanner.core.audit import DbAuditSink
from scanner.core.credentials import HostCredential
from scanner.core.db import session_scope
from scanner.core.findings_query import summary
from scanner.core.models import Finding, FindingType, HostOs, ServiceInfo, Severity
from scanner.core.orchestrator import RunService, inline_executor
from scanner.core.ratelimit import get_profile
from scanner.core.sshexec import (
    SshOptions,
    SshTimeout,
    Unreachable,
    connect,
    preflight_ssh,
)
from scanner.modules.auth_inventory import AuthInventoryModule
from scanner.modules.base import ScanContext, ScanModule
from scanner.modules.discovery import DiscoveryModule, build_nmap_command
from scanner.reporting.diff import diff_runs

NMAP_DOWN = """<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap" args="nmap" start="1" version="7.94" xmloutputversion="1.05">
<host><status state="down" reason="no-response" reason_ttl="0"/>
<address addr="10.0.0.7" addrtype="ipv4"/></host>
<runstats><finished time="2" elapsed="1" exit="success"/><hosts up="0" down="1" total="1"/>
</runstats></nmaprun>"""


class FakeNet:
    """Хосты сети стенда: какие «включены» и какие порты открыты."""

    def __init__(self):
        self.up: dict[str, list[ServiceInfo]] = {}
        self.cves: dict[str, list[str]] = {}      # хост -> CVE «по баннеру»


class FakeDiscovery(ScanModule):
    name = "discovery"

    def __init__(self, net: FakeNet):
        self.net = net

    def run(self, ctx: ScanContext) -> list[Finding]:
        ctx.services = []
        out = []
        for t in ctx.targets:
            if t in self.net.up:
                ctx.services.extend(self.net.up[t])
                ctx.hosts[t] = HostOs(t, "Debian 13", "debian", 95, "banner")
                out.append(Finding(module=self.name, host=t, finding_type=FindingType.INFO,
                                   title="up", vuln_id="INFO:host-up"))
        DiscoveryModule._mark_coverage(self, ctx, ctx.targets, False)
        return out


class FakeVuln(ScanModule):
    """Находки «по баннеру» (как VulnModule._banner_findings)."""
    name = "vuln"

    def __init__(self, net: FakeNet):
        self.net = net

    def run(self, ctx: ScanContext) -> list[Finding]:
        out = []
        for t in ctx.alive_hosts() or ():
            for c in self.net.cves.get(t, []):
                out.append(Finding(module=self.name, host=t, port=22,
                                   finding_type=FindingType.VULN, title=f"OpenSSH: {c}",
                                   severity=Severity.HIGH, vuln_id=c, cve_ids=[c],
                                   source="banner", confidence="low"))
        return out


def _timeout_connector(host, cred, opts):
    raise SshTimeout(f"{host}:22: таймаут SSH (TimeoutError)")


@pytest.fixture
def net():
    return FakeNet()


@pytest.fixture
def svc(sqlite_factory, net):
    registry = {
        "discovery": lambda: FakeDiscovery(net),
        "vuln": lambda: FakeVuln(net),
        "auth_inventory": lambda: AuthInventoryModule(connector=_timeout_connector,
                                                      sleep=lambda s: None),
    }
    return RunService(sqlite_factory, DbAuditSink(sqlite_factory), registry=registry,
                      executor=inline_executor(), vault=None, heartbeat_seconds=0)


def _eng(factory) -> int:
    with session_scope(factory) as s:
        eid = repo.create_engagement(s, name="Стенд")
        repo.add_allowlist_entry(s, engagement_id=eid, cidr="10.0.0.0/24")
    return eid


def _submit(svc, eid, targets, modules, **kw):
    return svc.submit(engagement_id=eid, modules=modules, rate_profile="gentle",
                      requested_targets=targets, actor="user:op", **kw)


def _run(factory, rid):
    with session_scope(factory) as s:
        run = repo.get_scan_run(s, rid)
        s.expunge(run)
        return run


def _ssh(host="10.0.0.5", port=22):
    return ServiceInfo(host, port, "tcp", "ssh", "OpenSSH", "10.0p2 Debian 7")


# ---------- 1. выключенный хост ----------
def test_host_down_run_is_not_successful(svc, sqlite_factory):
    eid = _eng(sqlite_factory)
    rid = _submit(svc, eid, ["10.0.0.7"], ["discovery", "vuln"])
    run = _run(sqlite_factory, rid)
    assert run.status == "failed"
    assert run.error_message.startswith(cv.MSG_HOST_DOWN)
    assert "-Pn" in run.error_message
    with session_scope(sqlite_factory) as s:
        cov = repo.run_coverage(s, rid)
        assert cov.status("10.0.0.7", "discovery") == cv.UNREACHABLE
        assert cov.status("10.0.0.7", "vuln") == cv.UNREACHABLE
        assert cov.host_status("10.0.0.7") == "unreachable"
        assert summary(s, rid, eid)["coverage"]["hosts_unreachable"] == 1


def test_real_discovery_marks_down_host_unreachable():
    calls = []
    mod = DiscoveryModule(runner=lambda cmd, t: calls.append(cmd) or NMAP_DOWN)
    ctx = ScanContext(engagement_id=1, scan_run_id=1, targets=["10.0.0.7"],
                      rate=get_profile("gentle"), audit=_NullAudit(),
                      options={"no_ping": True})
    mod.run(ctx)
    assert "-Pn" in calls[0]
    e = ctx.coverage.get("10.0.0.7", "discovery")
    assert e.status == cv.UNREACHABLE and "ответил" in e.reason
    assert "-Pn" not in build_nmap_command(["10.0.0.7"], get_profile("gentle"))


def test_no_ping_option_is_saved_and_passed(svc, sqlite_factory, net):
    seen = {}

    class Spy(FakeDiscovery):
        def run(self, ctx):
            seen.update(ctx.options)
            return super().run(ctx)

    svc.registry["discovery"] = lambda: Spy(net)
    eid = _eng(sqlite_factory)
    rid = _submit(svc, eid, ["10.0.0.7"], ["discovery"],
                  options={"no_ping": True, "junk": "x"})
    assert seen == {"no_ping": True}
    assert _run(sqlite_factory, rid).options == {"no_ping": True}


# ---------- 2. SSH timeout ----------
def test_ssh_timeout_makes_run_partial(svc, sqlite_factory, net):
    net.up["10.0.0.5"] = [_ssh()]
    net.cves["10.0.0.5"] = ["CVE-2025-26465"]
    eid = _eng(sqlite_factory)
    cred = HostCredential(id=1, name="root", auth="password", username="root",
                          password="x")
    svc.check_credentials = lambda *a, **k: None
    with session_scope(sqlite_factory) as s:
        rid = repo.create_scan_run(s, engagement_id=eid,
                                   modules=["discovery", "vuln", "auth_inventory"],
                                   targets=["10.0.0.5"])
    import scanner.core.repository as r
    orig = r.load_host_credentials
    r.load_host_credentials = lambda *a, **k: [cred]
    svc.vault = object()
    try:
        with session_scope(sqlite_factory) as s:
            s.get(r.ScanRun, rid).credential_ids = [1]
        assert svc.execute(rid, ["10.0.0.5"]) == "partial"
    finally:
        r.load_host_credentials = orig
    run = _run(sqlite_factory, rid)
    assert "таймаут" in run.error_message and "10.0.0.5" in run.error_message
    with session_scope(sqlite_factory) as s:
        cov = repo.run_coverage(s, rid)
        assert cov.status("10.0.0.5", "discovery") == cv.COMPLETED
        assert cov.status("10.0.0.5", "vuln") == cv.COMPLETED
        assert cov.status("10.0.0.5", "auth_inventory") == cv.TIMEOUT
        assert cov.host_status("10.0.0.5") == "partial"
        found = {f.vuln_id: f for f in repo.get_findings(s, rid)}
    # сетевые результаты есть, но с пониженной уверенностью и предупреждением
    assert found["CVE-2025-26465"].confidence == "low"
    assert "пакеты не проверены" in found["INFO:auth-inventory-unreachable"].title
    assert any(w["kind"] == "banner_only" for w in run.warnings)
    # отчёт: пробел покрытия и предупреждение видны, находка по баннеру — не подтверждена
    from scanner.reporting.model import build_report
    from scanner.reporting.render import ReportRenderer
    rep = build_report(list(found.values()), coverage=cov, run_status=run.status,
                       warnings=list(run.warnings))
    assert rep.coverage_gaps
    html = ReportRenderer().render_html(rep)
    assert "Полнота проверки" in html and "Таймаут" in html
    assert "Не подтверждено" in html or "низкая" in html.lower()


# ---------- предварительная проверка TCP/SSH ----------
def _server(handler):
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(5)
    stop = threading.Event()

    def loop():
        srv.settimeout(0.2)
        while not stop.is_set():
            try:
                conn, _ = srv.accept()
            except OSError:
                continue
            handler(conn)
    t = threading.Thread(target=loop, daemon=True)
    t.start()
    return srv, stop


def test_preflight_closed_port_has_recommendation():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    with pytest.raises(Unreachable, match="sshd") as e:
        preflight_ssh("127.0.0.1", port, 1.0)
    assert not isinstance(e.value, SshTimeout)


def test_preflight_silent_port_is_timeout_and_retried():
    held = []
    srv, stop = _server(held.append)          # принимает и молчит
    port = srv.getsockname()[1]
    try:
        with pytest.raises(SshTimeout, match="SSH-баннер не получен"):
            preflight_ssh("127.0.0.1", port, 0.3)
        sleeps = []
        cred = HostCredential(id=1, name="c", auth="password", username="u",
                              password="p", port=port)
        with pytest.raises(SshTimeout, match="попыток: 2"):
            connect("127.0.0.1", cred, SshOptions(connect_timeout_sec=0.3, attempts=2,
                                                  retry_delay_sec=0.01),
                    sleep=sleeps.append)
        assert sleeps == [0.01]
    finally:
        stop.set()
        srv.close()
        for c in held:
            c.close()


def test_preflight_accepts_ssh_banner():
    def hello(conn):
        conn.sendall(b"SSH-2.0-OpenSSH_10.0p2 Debian-7\r\n")
        conn.close()
    srv, stop = _server(hello)
    try:
        preflight_ssh("127.0.0.1", srv.getsockname()[1], 1.0)
    finally:
        stop.set()
        srv.close()


# ---------- 5. только баннер ----------
def test_banner_finding_low_confidence_and_superseded_by_package_check():
    from scanner.core.confidence import supersede_banner, warnings_for
    from scanner.modules.vuln import mark_banner
    f = Finding(module="vuln", host="10.0.0.5", port=22, finding_type=FindingType.VULN,
                title="OpenSSH", vuln_id="CVE-2023-38408", cve_ids=["CVE-2023-38408"])
    mark_banner(f, _ssh())
    assert (f.source, f.confidence) == ("banner", "low")
    assert "бэкпорт" in f.evidence and "сборку дистрибутива" in f.evidence
    other = Finding(module="vuln", host="10.0.0.5", port=22, finding_type=FindingType.VULN,
                    title="x", vuln_id="CVE-2099-0001", cve_ids=["CVE-2099-0001"],
                    source="banner", confidence="low")
    keep, dropped = supersede_banner(
        [f, other], {"10.0.0.5": {"CVE-2023-38408": "closed"}})
    assert dropped == [f] and keep == [other]   # закрыто бюллетенем вендора — убрано
    w = warnings_for(keep, [], None)
    assert w[0]["kind"] == "banner_only" and w[0]["count"] == 1


def test_advisories_missing_warning_merged_per_release():
    from scanner.core.confidence import warnings_for
    notes = [{"kind": "advisories_missing", "host": h, "family": "debian",
              "release": "trixie", "os": "Debian 13", "message": "x", "loadable": True}
             for h in ("10.0.0.5", "10.0.0.6")]
    w = warnings_for([], notes)
    assert len(w) == 1 and w[0]["hosts"] == ["10.0.0.5", "10.0.0.6"]
    assert w[0]["message"].startswith("Бэкпорты не учтены: нет бюллетеней debian:trixie")


# ---------- 6. сравнение прогонов ----------
def _f(host, vid, module="vuln"):
    return Finding(module=module, host=host, finding_type=FindingType.VULN, title=vid,
                   severity=Severity.HIGH, vuln_id=vid, cve_ids=[vid])


def test_diff_does_not_fix_unchecked_hosts():
    prev = [_f("10.0.0.5", "CVE-1"), _f("10.0.0.6", "CVE-2")]
    cur = [_f("10.0.0.5", "CVE-1")]
    pc, cc = cv.Coverage(), cv.Coverage()
    for h in ("10.0.0.5", "10.0.0.6"):
        pc.mark(h, "vuln", cv.COMPLETED)
    cc.mark("10.0.0.5", "vuln", cv.COMPLETED)
    cc.mark("10.0.0.6", "vuln", cv.UNREACHABLE)
    d = diff_runs(prev, cur, previous_coverage=pc, current_coverage=cc)
    assert d.fixed == [] and [f.vuln_id for f in d.unverified] == ["CVE-2"]
    # без покрытия — прежнее поведение
    assert [f.vuln_id for f in diff_runs(prev, cur).fixed] == ["CVE-2"]


def test_no_false_regression_when_baseline_did_not_check_host():
    cur = [_f("10.0.0.6", "CVE-2")]
    pc = cv.Coverage()
    pc.mark("10.0.0.5", "vuln", cv.COMPLETED)
    pc.mark("10.0.0.6", "vuln", cv.TIMEOUT)
    d = diff_runs([], cur, {cur[0].dedup_key()}, previous_coverage=pc,
                  current_coverage=cv.Coverage())
    assert d.regression == [] and d.open == cur


def test_runs_over_different_hosts_and_modules(svc, sqlite_factory, net):
    net.up = {"10.0.0.5": [_ssh()], "10.0.0.6": [_ssh("10.0.0.6")]}
    net.cves = {"10.0.0.5": ["CVE-1"], "10.0.0.6": ["CVE-2"]}
    eid = _eng(sqlite_factory)
    first = _submit(svc, eid, ["10.0.0.5", "10.0.0.6"], ["discovery", "vuln"])
    # второй прогон: 10.0.0.6 выключен — его находка не «исправлена»
    del net.up["10.0.0.6"]
    second = _submit(svc, eid, ["10.0.0.5", "10.0.0.6"], ["discovery", "vuln"])
    assert _run(sqlite_factory, second).status == "partial"
    with session_scope(sqlite_factory) as s:
        sm = summary(s, second, eid)
        assert sm["previous_run_id"] == first
        assert sm["fixed"] == 0 and sm["unverified"] == 1
        assert sm["comparability"]["level"] == "partial"
        assert any("не считаются исправленными" in w
                   for w in sm["comparability"]["warnings"])
    # третий: только обнаружение на другом хосте — с прошлыми несопоставим
    net.up["10.0.0.9"] = [_ssh("10.0.0.9")]
    third = _submit(svc, eid, ["10.0.0.9"], ["discovery"])
    with session_scope(sqlite_factory) as s:
        assert repo.previous_scan_run_id(s, third) is None
    # четвёртый: 10.0.0.6 вернулся — CVE-2 не «повторная» и не «новая» ложно
    net.up["10.0.0.6"] = [_ssh("10.0.0.6")]
    fourth = _submit(svc, eid, ["10.0.0.5", "10.0.0.6"], ["discovery", "vuln"])
    with session_scope(sqlite_factory) as s:
        st = {r.vuln_id: r.status for r in repo.get_finding_rows(s, fourth)
              if r.module == "vuln"}
    assert st == {"CVE-1": "open", "CVE-2": "open"}


def test_comparison_with_disjoint_runs_is_flagged():
    a, b = cv.Coverage(), cv.Coverage()
    a.mark("10.0.0.5", "vuln", cv.COMPLETED)
    b.mark("10.0.0.6", "discovery", cv.COMPLETED)
    c = cv.comparability(a, b)
    assert c.level == "none" and "несопоставимы" in c.warnings[0]


# ---------- профили и состав прогона ----------
def test_profiles_and_inapplicable_modules():
    from scanner.core.profiles import PROFILES, plan_modules
    known = ["discovery", "vuln", "auth_inventory", "win_inventory", "config_audit",
             "password_policy", "cred_audit"]
    p = plan_modules(["discovery", "auth_inventory", "win_inventory"], protocols={"ssh"},
                     engine_modules={"auth_inventory", "win_inventory"}, known=known)
    assert p.names == ["discovery", "auth_inventory"]
    assert p.removed[0].name == "win_inventory"
    full = plan_modules(PROFILES["linux_full"].modules, protocols={"ssh"},
                        engine_modules=PROFILES["linux_full"].modules, known=known)
    assert full.full_check and not full.warnings
    net = plan_modules(PROFILES["network"].modules, protocols=set(), known=known)
    assert not net.full_check and any("бэкпорты" in w for w in net.warnings)


def test_win_inventory_not_applicable_on_linux_host():
    from scanner.modules.win_inventory import WinInventoryModule
    ctx = ScanContext(engagement_id=1, scan_run_id=1, targets=["10.0.0.5"],
                      rate=get_profile("gentle"), audit=_NullAudit(),
                      hosts={"10.0.0.5": HostOs("10.0.0.5", "Debian", "debian")},
                      services=[_ssh()], completed={"discovery"})
    WinInventoryModule().run(ctx)
    assert ctx.coverage.status("10.0.0.5", "win_inventory") == cv.NOT_APPLICABLE


class _NullAudit:
    def record(self, **kw):
        pass


# ---------- отчёт: выключенный хост и неполная проверка ----------
def test_report_for_down_host_says_not_checked(svc, sqlite_factory):
    """Отчёт по выключенному хосту не говорит «уязвимостей не выявлено»."""
    import io

    from docx import Document

    from scanner.reporting.model import build_report
    from scanner.reporting.render import ReportRenderer
    eid = _eng(sqlite_factory)
    rid = _submit(svc, eid, ["10.0.0.7"], ["discovery", "vuln"])
    with session_scope(sqlite_factory) as s:
        cov = repo.run_coverage(s, rid)
    rep = build_report([], coverage=cov, run_status="failed", hosts=["10.0.0.7"])
    assert rep.summary.risk_label == "Не оценён"
    r = ReportRenderer()
    html = r.render_html(rep)
    assert "Полнота проверки" in html and cv.MSG_HOST_DOWN in html
    assert "не выявлено" not in html.lower()
    data = r.render_json(rep).decode()
    assert '"unreachable"' in data
    doc = Document(io.BytesIO(r.render_docx(rep)))
    text = "\n".join(p.text for p in doc.paragraphs)
    assert "Полнота проверки" in text and "не выявлено" not in text.lower()



def test_vuln_does_not_scan_hosts_discovery_found_down():
    """Nuclei не запускается по хостам, которые обнаружение признало недоступными
    (раньше при нуле сервисов он получал все цели прогона)."""
    from scanner.core.audit import AuditSink
    from scanner.modules.vuln import VulnModule, build_inputs

    class _A(AuditSink):
        def record(self, **kw):
            pass

    calls = []
    ctx = ScanContext(engagement_id=1, scan_run_id=1, targets=["10.0.0.7", "10.0.0.5"],
                      rate=get_profile("gentle"), audit=_A(), services=[],
                      completed={"discovery"})
    assert build_inputs(ctx) == ([], [])
    mod = VulnModule(runner=lambda *a: calls.append(a) or "")
    assert mod.run(ctx) == [] and calls == []
    ctx.services = [_ssh("10.0.0.5")]
    assert build_inputs(ctx)[0] == ["10.0.0.5:22"]
    # без обнаружения — как раньше, все цели
    ctx2 = ScanContext(engagement_id=1, scan_run_id=1, targets=["10.0.0.7"],
                       rate=get_profile("gentle"), audit=_A())
    assert build_inputs(ctx2)[0] == ["10.0.0.7"]
