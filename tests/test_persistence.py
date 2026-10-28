"""Round-trip слоя персистентности на SQLite (без живого Postgres)."""
from __future__ import annotations

import pytest
from sqlalchemy import select

from scanner.core import repository as repo
from scanner.core.audit import DbAuditSink, normalize_details
from scanner.core.db import AuditLogRow, session_scope
from scanner.core.models import Finding, FindingType, ServiceInfo, Severity
from scanner.core.orchestrator import Orchestrator
from scanner.core.ratelimit import get_profile
from scanner.modules.base import ScanContext, ScanModule
from scanner.reporting.diff import diff_runs


def _finding(host="10.0.0.5", port=443, vuln="CVE-2013-5946", **kw) -> Finding:
    return Finding(module="vuln", host=host, finding_type=FindingType.VULN,
                   title=f"{vuln} on {host}", port=port, vuln_id=vuln, **kw)


@pytest.fixture
def engagement(sqlite_factory):
    with session_scope(sqlite_factory) as s:
        eid = repo.create_engagement(s, name="ООО Тест", contract_ref="Д-1/2026")
        repo.add_allowlist_entry(s, engagement_id=eid, cidr="10.0.0.0/24")
    return eid


def test_findings_round_trip(sqlite_factory, engagement):
    src = [
        _finding(cve_ids=["CVE-2013-5946"], bdu_ids=["BDU:2014-00002"],
                 severity=Severity.CRITICAL, cvss=10.0, evidence="banner"),
        Finding(module="discovery", host="10.0.0.6", finding_type=FindingType.INFO,
                title="host up"),
    ]
    with session_scope(sqlite_factory) as s:
        run = repo.create_scan_run(s, engagement_id=engagement, modules=["vuln"])
        assert repo.save_findings(s, engagement_id=engagement, scan_run_id=run,
                                  findings=src) == 2

    with session_scope(sqlite_factory) as s:
        got = repo.get_findings(s, run)
        assert [f.dedup_key() for f in got] == [f.dedup_key() for f in src]
        f = got[0]
        assert f.cve_ids == ["CVE-2013-5946"] and f.bdu_ids == ["BDU:2014-00002"]
        assert f.severity is Severity.CRITICAL and f.cvss == 10.0
        assert f.finding_type is FindingType.VULN and f.evidence == "banner"
        assert [x.module for x in repo.get_findings(s, run, module="discovery")] == [
            "discovery"]
        assert set(repo.get_finding_statuses(s, run).values()) == {"open"}


def test_services_round_trip(sqlite_factory, engagement):
    svcs = [ServiceInfo("10.0.0.5", 22, "tcp", "ssh", "OpenSSH", "8.9p1",
                        "cpe:/a:openbsd:openssh:8.9p1"),
            ServiceInfo("10.0.0.5", 443, "tcp", "https", "nginx", "1.18.0"),
            ServiceInfo("10.0.0.7", 53, "udp", "domain")]
    with session_scope(sqlite_factory) as s:
        run = repo.create_scan_run(s, engagement_id=engagement, modules=["discovery"])
        hosts = repo.save_services(s, scan_run_id=run, services=svcs)
        assert set(hosts) == {"10.0.0.5", "10.0.0.7"}
    with session_scope(sqlite_factory) as s:
        assert repo.get_services(s, run) == svcs


def test_run_lifecycle_and_diff_inputs(sqlite_factory, engagement):
    a, b, c = _finding(vuln="CVE-1"), _finding(vuln="CVE-2"), _finding(vuln="CVE-3")
    runs = []
    # run1: a,b; run2: a (b fixed); run3: a,b (b regression), c new
    for found in ([a, b], [a], [a, b, c]):
        with session_scope(sqlite_factory) as s:
            rid = repo.create_scan_run(s, engagement_id=engagement, modules=["vuln"])
            repo.set_scan_run_status(s, rid, "running")
            repo.save_findings(s, engagement_id=engagement, scan_run_id=rid,
                               findings=found)
            repo.set_scan_run_status(s, rid, "done")
            runs.append(rid)

    with session_scope(sqlite_factory) as s:
        run3 = repo.get_scan_run(s, runs[2])
        assert run3.started_at and run3.finished_at and run3.status == "done"
        prev = repo.previous_scan_run_id(s, runs[2])
        assert prev == runs[1]
        d = diff_runs(repo.get_findings(s, prev), repo.get_findings(s, runs[2]),
                      historically_fixed=repo.historically_fixed_keys(
                          s, engagement, runs[2]))
    assert [f.vuln_id for f in d.open] == ["CVE-1"]
    assert [f.vuln_id for f in d.regression] == ["CVE-2"]
    assert [f.vuln_id for f in d.new] == ["CVE-3"]
    assert d.fixed == []


def test_bad_run_status_rejected(sqlite_factory, engagement):
    with session_scope(sqlite_factory) as s:
        rid = repo.create_scan_run(s, engagement_id=engagement, modules=["vuln"])
        with pytest.raises(ValueError):
            repo.set_scan_run_status(s, rid, "hacked")


def test_allowlist_from_db(sqlite_factory, engagement):
    with session_scope(sqlite_factory) as s:
        repo.add_allowlist_entry(s, engagement_id=engagement, cidr="192.168.1.10/24")
        assert repo.list_allowlist(s, engagement) == ["10.0.0.0/24", "192.168.1.0/24"]
        with pytest.raises(ValueError):
            repo.add_allowlist_entry(s, engagement_id=engagement, cidr="not-a-net")
        gate = repo.load_allowlist_gate(s, engagement)
        other = repo.create_engagement(s, name="Другой договор")
        empty_gate = repo.load_allowlist_gate(s, other)
    assert gate.filter(["10.0.0.9", "192.168.1.200", "8.8.8.8"]) == (
        ["10.0.0.9", "192.168.1.200"], ["8.8.8.8"])
    assert not empty_gate.is_allowed("10.0.0.9")  # пустой allowlist = запрещено всё


def test_db_audit_sink_writes_rows(sqlite_factory):
    sink = DbAuditSink(sqlite_factory)
    sink.record(subject="scanner", action="deny", target="8.8.8.8",
                result="not_in_allowlist")
    sink.record(subject="anton", action="export", target="run:1", result="ok",
                details={"format": "pdf"})
    sink.record(subject="scanner", action="nmap", target="10.0.0.5", result="ok",
                details="nmap -sV 10.0.0.5")
    with session_scope(sqlite_factory) as s:
        rows = s.scalars(select(AuditLogRow).order_by(AuditLogRow.id)).all()
    assert [(r.action, r.target) for r in rows] == [
        ("deny", "8.8.8.8"), ("export", "run:1"), ("nmap", "10.0.0.5")]
    assert rows[1].details == {"format": "pdf"}
    assert rows[2].details == {"message": "nmap -sV 10.0.0.5"}
    assert all(r.ts is not None for r in rows)


def test_audit_survives_business_rollback(sqlite_factory, engagement):
    sink = DbAuditSink(sqlite_factory)
    with pytest.raises(RuntimeError), session_scope(sqlite_factory) as s:
        repo.create_scan_run(s, engagement_id=engagement, modules=["vuln"])
        sink.record(subject="scanner", action="module_start", target="vuln",
                    result="ok")
        raise RuntimeError("module crashed")
    with session_scope(sqlite_factory) as s:
        assert s.scalar(select(AuditLogRow.action)) == "module_start"


def test_normalize_details():
    assert normalize_details(None) is None
    assert normalize_details('{"a": 1}') == {"a": 1}
    assert normalize_details("[1]") == {"message": "[1]"}


class _EchoModule(ScanModule):
    name = "echo"

    def run(self, ctx: ScanContext) -> list[Finding]:
        return [Finding(module=self.name, host=t, finding_type=FindingType.INFO,
                        title="seen") for t in ctx.targets]


def test_orchestrator_with_db_allowlist_and_audit(sqlite_factory, engagement):
    """Сквозной путь ядра: allowlist из БД -> модуль -> находки в БД, отказы в аудите."""
    sink = DbAuditSink(sqlite_factory)
    with session_scope(sqlite_factory) as s:
        gate = repo.load_allowlist_gate(s, engagement)
        run = repo.create_scan_run(s, engagement_id=engagement, modules=["echo"])
    findings = Orchestrator(gate, sink).run(
        engagement_id=engagement, scan_run_id=run,
        requested_targets=["10.0.0.1", "203.0.113.5"], modules=[_EchoModule()],
        rate=get_profile("gentle"))
    with session_scope(sqlite_factory) as s:
        repo.save_findings(s, engagement_id=engagement, scan_run_id=run,
                           findings=findings)
        assert [f.host for f in repo.get_findings(s, run)] == ["10.0.0.1"]
        audit = s.execute(select(AuditLogRow.action, AuditLogRow.target)
                          .order_by(AuditLogRow.id)).all()
    assert ("deny", "203.0.113.5") in audit and ("module_start", "echo") in audit
