"""«Активы» независимо от прогонов (миграция 0022, scanner.core.host_latest).

* хост из прогона №1 остаётся в «Активах» и после прогона №2, где его не было;
* без выбора прогона у хоста — последние известные уязвимости, по модулям из
  последнего прогона, где модуль хост действительно проверил: недоступность,
  таймаут SSH или отсутствие учётки в новом прогоне не «исправляют» старые
  находки;
* найденный прогоном хост заводится активом сам (source=discovery), учётные
  поля существующего актива не меняются; record_seen — общий вход и для
  сканирования портов (source=netscan).
"""
from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from scanner.core import assets, host_latest
from scanner.core import coverage as cv
from scanner.core import repository as repo
from scanner.core.db import AssetRow, FindingRow, session_scope
from scanner.core.models import (
    Finding,
    FindingType,
    HostInventory,
    HostOs,
    ServiceInfo,
    Severity,
)
from scanner.core.orchestrator import RunOutcome, seen_hosts
from tests.test_assets import _run as api_run
from tests.test_assets import api  # noqa: F401 — фикстура API на SQLite


def _f(host, vid, module="vuln", sev=Severity.HIGH):
    return Finding(module=module, finding_type=FindingType.VULN, host=host, port=None,
                   title=vid, severity=sev, vuln_id=vid, cve_ids=[vid])


def _run(s, eid, findings, coverage, status="done"):
    rid = repo.create_scan_run(s, engagement_id=eid, modules=sorted({m for _, m, _ in coverage}))
    cov = cv.Coverage()
    for host, module, st in coverage:
        cov.mark(host, module, st)
    repo.save_coverage(s, rid, cov)
    repo.save_findings(s, engagement_id=eid, scan_run_id=rid, findings=findings)
    repo.set_scan_run_status(s, rid, status)
    return rid


@pytest.fixture
def eng(sqlite_factory):
    with session_scope(sqlite_factory) as s:
        eid = repo.create_engagement(s, name="Договор")
    return sqlite_factory, eid


def test_unchecked_module_keeps_previous_findings(eng):
    sf, eid = eng
    with session_scope(sf) as s:
        r1 = _run(s, eid, [_f("10.0.0.1", "CVE-NET-1", "vuln"),
                           _f("10.0.0.1", "CVE-PKG-1", "auth_inventory"),
                           _f("10.0.0.1", "CVE-PKG-2", "auth_inventory", Severity.CRITICAL),
                           _f("10.0.0.2", "CVE-NET-2", "vuln")],
                  [("10.0.0.1", "vuln", cv.COMPLETED), ("10.0.0.1", "auth_inventory", cv.COMPLETED),
                   ("10.0.0.2", "vuln", cv.COMPLETED)])
        # №2: сеть проверена (CVE-NET-1 исправлена), SSH — таймаут; 10.0.0.2 в прогон не входил
        r2 = _run(s, eid, [],
                  [("10.0.0.1", "vuln", cv.COMPLETED), ("10.0.0.1", "auth_inventory", cv.TIMEOUT)],
                  status="partial")
    with session_scope(sf) as s:
        latest = host_latest.latest_counts(s, eid)
        h1, h2 = latest["10.0.0.1"], latest["10.0.0.2"]
        assert h1.module_runs == {"vuln": r2, "auth_inventory": r1}
        assert h1.counts == {"high": 1, "critical": 1} and h1.total == 2
        assert h1.checked_run_id == r2 and h1.run_ids == [r1, r2]
        # хост не входил в №2 — его данные из №1, а не «исчезли»
        assert h2.module_runs == {"vuln": r1} and h2.total == 1
        lt, rows = host_latest.latest_findings(s, eid, "10.0.0.1")
        assert sorted(r.vuln_id for r in rows) == ["CVE-PKG-1", "CVE-PKG-2"]
        assert lt.checked_run_id == r2


def test_newer_check_replaces_findings_and_unreachable_does_not(eng):
    sf, eid = eng
    with session_scope(sf) as s:
        _run(s, eid, [_f("10.0.0.1", "CVE-OLD")], [("10.0.0.1", "vuln", cv.COMPLETED)])
        r2 = _run(s, eid, [_f("10.0.0.1", "CVE-NEW")], [("10.0.0.1", "vuln", cv.COMPLETED)])
        _run(s, eid, [], [("10.0.0.1", "vuln", cv.UNREACHABLE)], status="failed")
        _run(s, eid, [], [("10.0.0.1", "vuln", cv.NO_CREDENTIALS)], status="partial")
    with session_scope(sf) as s:
        _, rows = host_latest.latest_findings(s, eid, "10.0.0.1")
        assert [r.vuln_id for r in rows] == ["CVE-NEW"]
        assert host_latest.latest_counts(s, eid)["10.0.0.1"].checked_run_id == r2


def test_running_run_and_false_positives_are_ignored(eng):
    sf, eid = eng
    with session_scope(sf) as s:
        _run(s, eid, [_f("10.0.0.1", "CVE-A"), _f("10.0.0.1", "CVE-B")],
             [("10.0.0.1", "vuln", cv.COMPLETED)])
        _run(s, eid, [], [("10.0.0.1", "vuln", cv.COMPLETED)], status="running")
        fp = s.query(FindingRow).filter_by(vuln_id="CVE-B").one()
        repo.mark_false_positive(s, fp, reason="тест", marked_by=None)
    with session_scope(sf) as s:
        h = host_latest.latest_counts(s, eid)["10.0.0.1"]
        assert h.total == 1 and h.counts == {"high": 1}


def test_finding_without_coverage_row_counts_as_checked(eng):
    """Модуль оставил находку — значит хост проверил, даже если покрытие его не
    отметило (старый модуль, другое имя модуля в покрытии)."""
    sf, eid = eng
    with session_scope(sf) as s:
        rid = _run(s, eid, [_f("10.0.0.5", "CVE-X", "nuclei")],
                   [("10.0.0.5", "discovery", cv.COMPLETED)])
    with session_scope(sf) as s:
        assert host_latest.latest_counts(s, eid)["10.0.0.5"].module_runs == {
            "discovery": rid, "nuclei": rid}


def test_record_seen_creates_and_touches_without_overwriting(eng):
    sf, eid = eng
    t1 = datetime(2026, 11, 1, tzinfo=UTC)
    t2 = t1 + timedelta(days=1)
    with session_scope(sf) as s:
        manual = assets.create_asset(s, eid, address="10.0.0.9", criticality="critical",
                                     owner="Петров")
        n = assets.record_seen(s, eid, ["10.0.0.1", "10.0.0.1/32", "bad", "10.0.0.9"],
                               source=assets.SOURCE_DISCOVERY,
                               hostnames={"10.0.0.1": "web01", "10.0.0.9": "db01"},
                               seen_at=t1)
        assert n == 1
        assert assets.record_seen(s, eid, ["10.0.0.1"], source=assets.SOURCE_NETSCAN,
                                  seen_at=t2) == 0
        assert assets.record_seen(s, eid, [], source=assets.SOURCE_NETSCAN) == 0
        with pytest.raises(assets.AssetError):
            assets.record_seen(s, eid, ["10.0.0.3"], source="other")
        manual_id = manual.id
    with session_scope(sf) as s:
        rows = {assets.host_key(r.address): r for r in s.query(AssetRow).all()}
        new = rows["10.0.0.1"]
        assert new.source == "discovery" and new.criticality == "medium"
        assert new.hostname == "web01"
        assert new.first_seen_at.replace(tzinfo=UTC) == t1
        assert new.last_seen_at.replace(tzinfo=UTC) == t2
        old = s.get(AssetRow, manual_id)
        assert (old.source, old.criticality, old.owner) == ("manual", "critical", "Петров")
        assert old.hostname == "db01" and old.first_seen_at is not None


def test_seen_hosts_only_really_discovered():
    out = RunOutcome()
    out.coverage.mark("10.0.0.1", "discovery", cv.COMPLETED)
    out.coverage.mark("10.0.0.2", "discovery", cv.UNREACHABLE)     # -Pn без портов
    out.coverage.mark("10.0.0.3", "auth_inventory", cv.NO_CREDENTIALS)
    out.hosts = [HostOs("10.0.0.2"), HostOs("10.0.0.3")]
    out.services = [ServiceInfo(host="10.0.0.3", port=22, protocol="tcp")]
    out.inventory = [HostInventory(host="10.0.0.4")]
    # 10.0.0.3 без учётки, но с открытым портом — актив; 10.0.0.2 — нет
    assert seen_hosts(out) == ["10.0.0.1", "10.0.0.3", "10.0.0.4"]


def test_api_hosts_latest_and_host_latest_endpoint(api):  # noqa: F811
    eid = api.engagement("10.0.0.0/24")
    op = api.user("op", "operator")
    run_id = api_run(api, eid, op, ["10.0.0.1"]).json()["id"]
    hosts = api.c.get(f"/engagements/{eid}/hosts", headers=op).json()
    h = next(x for x in hosts if x["host"] == "10.0.0.1")
    assert h["checked_run_id"] == run_id and h["latest_run_ids"] == [run_id]
    assert h["latest_total"] >= 1
    r = api.c.get(f"/engagements/{eid}/hosts/10.0.0.1/latest", headers=op)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["checked_run_id"] == run_id and body["findings"]
    assert {f["host"] for f in body["findings"]} == {"10.0.0.1"}
    issues = [f for f in body["findings"] if f["severity"] != "info"]
    assert len(issues) == h["latest_total"]
    assert api.c.get(f"/engagements/{eid}/hosts/nope/latest", headers=op).status_code == 422
    empty = api.c.get(f"/engagements/{eid}/hosts/10.0.0.200/latest", headers=op).json()
    assert empty["findings"] == [] and empty["checked_run_id"] is None
    # найденный прогоном хост — актив
    got = api.c.get(f"/engagements/{eid}/assets", headers=api.admin).json()
    assert [a["address"] for a in got] == ["10.0.0.1"] and got[0]["source"] == "discovery"
