"""Постраничные списки: находки и прогоны фильтруются, сортируются и режутся
на страницы в БД; без параметров API отвечает как раньше."""
from __future__ import annotations

import time

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from scanner.api.main import create_app
from scanner.api.settings import ApiSettings
from scanner.core import repository as repo
from scanner.core.db import FindingRow, ScanRun, session_scope
from scanner.core.models import Finding, FindingType, Severity
from scanner.core.orchestrator import inline_executor
from scanner.reporting.remediation import RemediationResolver
from tests.conftest import PG_URL
from tests.test_migrations_pg import pg_factory  # noqa: F401 — фикстура

PASSWORD = "correct-horse-battery"
SEVS = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]


def _findings(hosts: int = 6, per_host: int = 5) -> list[Finding]:
    out = []
    for h in range(1, hosts + 1):
        for i in range(per_host):
            sev = SEVS[i % len(SEVS)]
            out.append(Finding(
                module="vuln" if i % 2 == 0 else "config_audit", host=f"10.0.0.{h}",
                port=22 + i, finding_type=FindingType.VULN, severity=sev,
                title=f"Уязвимость {h}-{i} OpenSSH", vuln_id=f"CVE-2024-{h:02d}{i:02d}",
                cve_ids=[f"CVE-2024-{h:02d}{i:02d}"],
                bdu_ids=[f"BDU:2024-{h:02d}{i:03d}"] if i % 3 == 0 else [],
                cvss={"critical": 9.8, "high": 7.5, "medium": 5.0, "low": 2.0}.get(str(sev))))
    return out


def _seed(factory, findings, *, runs: int = 1) -> tuple[int, list[int]]:
    with session_scope(factory) as s:
        eid = repo.create_engagement(s, name="Ромашка")
        repo.add_allowlist_entry(s, engagement_id=eid, cidr="10.0.0.0/24")
        ids = []
        for n in range(runs):
            rid = repo.create_scan_run(s, engagement_id=eid, modules=["vuln"],
                                       targets=["10.0.0.0/24"], name=f"прогон {n + 1}")
            repo.set_scan_run_status(s, rid, "done" if n % 2 == 0 else "failed")
            ids.append(rid)
        repo.save_findings(s, engagement_id=eid, scan_run_id=ids[-1], findings=findings,
                           statuses={findings[0].dedup_key(): "new"})
    return eid, ids


def _client(factory):
    settings = ApiSettings(secret="z" * 40, bootstrap_admin="root",
                           bootstrap_password=PASSWORD, run_heartbeat_seconds=0,
                           scheduler_tick_seconds=0, feeds_tick_seconds=0,
                           notify_tick_seconds=0)
    app = create_app(session_factory=factory, settings=settings, registry={},
                     executor=inline_executor(),
                     resolver_factory=lambda f: RemediationResolver())
    return TestClient(app)


def _login(c):
    r = c.post("/auth/token", json={"username": "root", "password": PASSWORD})
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


def _admin_can_view(c, h):
    # у admin нет view_report: заводим аудитора
    c.post("/users", headers=h, json={"username": "aud", "password": PASSWORD,
                                      "roles": ["auditor"]})
    r = c.post("/auth/token", json={"username": "aud", "password": PASSWORD})
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


@pytest.fixture
def env(sqlite_factory):
    findings = _findings()
    eid, runs = _seed(sqlite_factory, findings, runs=3)
    with _client(sqlite_factory) as c:
        h = _admin_can_view(c, _login(c))
        yield c, h, eid, runs[-1], findings


def test_without_params_returns_everything_as_before(env):
    c, h, _, rid, findings = env
    r = c.get(f"/runs/{rid}/findings", headers=h)
    assert r.status_code == 200 and len(r.json()) == len(findings) == 30
    assert r.headers["X-Total-Count"] == "30"
    assert [f["id"] for f in r.json()] == sorted(f["id"] for f in r.json())
    # прежний одиночный ?module= работает
    vuln = c.get(f"/runs/{rid}/findings?module=vuln", headers=h).json()
    assert vuln and {f["module"] for f in vuln} == {"vuln"}


def test_pages_cover_the_filtered_set_without_overlap(env):
    c, h, _, rid, _ = env
    seen, offset = [], 0
    while True:
        r = c.get(f"/runs/{rid}/findings", headers=h,
                  params={"limit": 7, "offset": offset, "sort": "severity",
                          "include_info": "false"})
        assert r.headers["X-Total-Count"] == "24"
        page = r.json()
        if not page:
            break
        seen += page
        offset += 7
    assert len(seen) == 24 and len({f["id"] for f in seen}) == 24
    ranks = [SEVS[::-1].index(Severity(f["severity"])) for f in seen]
    assert ranks == sorted(ranks, reverse=True)     # сначала опасные


def test_filters_combine_and_count(env):
    c, h, _, rid, _ = env
    def get(**p):
        r = c.get(f"/runs/{rid}/findings", headers=h, params={"limit": 100, **p})
        assert r.status_code == 200, r.text
        return r.json(), int(r.headers["X-Total-Count"])
    rows, n = get(severity=["critical", "high"])
    assert n == 12 and {f["severity"] for f in rows} == {"critical", "high"}
    rows, n = get(severity="critical", module="vuln")
    assert n == 6
    rows, n = get(host="10.0.0.3")
    assert n == 5 and {f["host"] for f in rows} == {"10.0.0.3"}
    rows, n = get(q="CVE-2024-0402")
    assert n == 1 and rows[0]["host"] == "10.0.0.4"
    rows, n = get(q="10.0.0.2:23")
    assert n == 1 and rows[0]["port"] == 23
    rows, n = get(bdu_only="true")
    assert n == 12 and all(f["bdu_ids"] for f in rows)
    rows, n = get(status="new")
    assert n == 1
    rows, n = get(q="openssh", sort="host", order="desc", limit=3)
    assert n == 30 and len(rows) == 3 and rows[0]["host"] == "10.0.0.6"
    assert c.get(f"/runs/{rid}/findings?host=not-an-ip", headers=h).status_code == 422
    assert c.get(f"/runs/{rid}/findings?sort=evil", headers=h).status_code == 422
    assert c.get(f"/runs/{rid}/findings?limit=5000", headers=h).status_code == 422


def test_false_positive_modes_and_priority_sort(env, sqlite_factory):
    c, h, _, rid, _ = env
    with session_scope(sqlite_factory) as s:
        row = s.scalars(select(FindingRow).where(FindingRow.scan_run_id == rid,
                                                 FindingRow.severity == "critical")).first()
        repo.mark_false_positive(s, row, reason="стенд", marked_by=None)
        fp_id = row.id
    ex = c.get(f"/runs/{rid}/findings?false_positives=exclude&limit=100", headers=h)
    assert ex.headers["X-Total-Count"] == "29" and fp_id not in {f["id"] for f in ex.json()}
    only = c.get(f"/runs/{rid}/findings?false_positives=only", headers=h).json()
    assert [f["id"] for f in only] == [fp_id] and only[0]["false_positive"]

    pr = c.get(f"/runs/{rid}/findings", headers=h,
               params={"sort": "priority", "limit": 5, "include_info": "false",
                       "false_positives": "exclude"}).json()
    assert [f["priority"]["rank"] for f in pr] == [1, 2, 3, 4, 5]
    nxt = c.get(f"/runs/{rid}/findings", headers=h,
                params={"sort": "priority", "limit": 5, "offset": 5, "include_info": "false",
                        "false_positives": "exclude"}).json()
    assert nxt[0]["priority"]["rank"] == 6


def test_slow_priorities_served_stale_while_refreshing(env, sqlite_factory, monkeypatch):
    """Большой прогон: после отметки «ложное» запрос не ждёт пересчёта рангов —
    отдаётся прежний расчёт, новый считается в фоне и подменяет его."""
    from scanner.api import routes_findings as rf

    _, _, eid, rid, _ = env
    monkeypatch.setattr(rf, "PRIORITY_SLOW_SECONDS", 0.0)   # любой расчёт — «долгий»
    with session_scope(sqlite_factory) as s:
        marks = repo.false_positive_marks(s, eid)
        first = rf.run_priorities(s, rid, eid, marks)
        top = min(first, key=lambda k: first[k].rank)
        row = s.scalars(select(FindingRow).where(FindingRow.scan_run_id == rid,
                                                 FindingRow.dedup_key == top)).first()
        repo.mark_false_positive(s, row, reason="стенд", marked_by=None)
    with session_scope(sqlite_factory) as s:
        marks = repo.false_positive_marks(s, eid)
        assert rf.run_priorities(s, rid, eid, marks) is first      # сразу, без пересчёта
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            fresh = rf.run_priorities(s, rid, eid, marks)
            if fresh is not first:
                break
            time.sleep(0.05)
    assert fresh is not first and top not in fresh
    assert sorted(a.rank for a in fresh.values()) == list(range(1, len(fresh) + 1))


def test_summary_counts(env, sqlite_factory):
    c, h, _eid, rid, _ = env
    s = c.get(f"/runs/{rid}/findings/summary", headers=h).json()
    assert s["counts"] == {"info": 6, "low": 6, "medium": 6, "high": 6, "critical": 6}
    assert s["open"] == 24 and s["hosts"] == 6 and s["new"] == 1
    assert s["modules"] == ["config_audit", "vuln"] and s["false_positives"] == 0
    assert 0 < s["bdu_share"] < 1
    assert s["host_counts"][0]["total"] == 4
    # закрытые относительно прошлого успешного прогона
    assert s["previous_run_id"] is not None and s["fixed"] == 0


def test_runs_pagination_and_compat(env, sqlite_factory):
    c, h, eid, _, _ = env
    with session_scope(sqlite_factory) as s:
        for n in range(20):
            rid = repo.create_scan_run(s, engagement_id=eid, modules=["vuln"],
                                       name=f"ночной {n}")
            repo.set_scan_run_status(s, rid, "done")
    allr = c.get(f"/engagements/{eid}/runs", headers=h)
    assert len(allr.json()) == 23 and allr.headers["X-Total-Count"] == "23"
    assert [r["id"] for r in allr.json()] == sorted(r["id"] for r in allr.json())
    page = c.get(f"/engagements/{eid}/runs?limit=10&offset=10", headers=h)
    ids = [r["id"] for r in page.json()]
    assert page.headers["X-Total-Count"] == "23" and ids == sorted(ids, reverse=True)
    failed = c.get(f"/engagements/{eid}/runs?status=failed&limit=10", headers=h)
    assert failed.headers["X-Total-Count"] == "1"
    named = c.get(f"/engagements/{eid}/runs", headers=h, params={"q": "ночной 1", "limit": 50})
    assert int(named.headers["X-Total-Count"]) == 11      # «ночной 1», «ночной 10…19»


@pytest.mark.skipif(not PG_URL, reason="SCANNER_TEST_DATABASE_URL not set")
def test_pagination_on_postgres(pg_factory):  # noqa: F811
    findings = _findings()
    eid, runs = _seed(pg_factory, findings, runs=2)
    rid = runs[-1]
    with _client(pg_factory) as c:
        h = _admin_can_view(c, _login(c))
        r = c.get(f"/runs/{rid}/findings", headers=h,
                  params={"limit": 4, "sort": "host", "q": "openssh", "bdu_only": "true"})
        assert r.status_code == 200, r.text
        assert r.headers["X-Total-Count"] == "12" and r.json()[0]["host"] == "10.0.0.1"
        assert c.get(f"/runs/{rid}/findings?q=10.0.0.5:24",
                     headers=h).headers["X-Total-Count"] == "1"
        s = c.get(f"/runs/{rid}/findings/summary", headers=h).json()
        assert s["open"] == 24 and s["hosts"] == 6
        assert c.get(f"/engagements/{eid}/runs?limit=1&status=done",
                     headers=h).headers["X-Total-Count"] == "1"


# ---------- нагрузка ----------
@pytest.mark.skipif(not PG_URL, reason="SCANNER_TEST_DATABASE_URL not set")
def test_large_run_page_is_fast_on_postgres(pg_factory):  # noqa: F811
    """1000 хостов × 50 находок = 50 000 строк: страница и сводка — из БД.

    Полный нагрузочный замер (1 млн строк) — scripts/load_test.py."""
    with session_scope(pg_factory) as s:
        eid = repo.create_engagement(s, name="нагрузка")
        rid = repo.create_scan_run(s, engagement_id=eid, modules=["vuln"])
        repo.set_scan_run_status(s, rid, "done")
    from scripts.load_test import bulk_insert
    bulk_insert(pg_factory, eid, rid, hosts=1000, per_host=50)
    with _client(pg_factory) as c:
        h = _admin_can_view(c, _login(c))
        t = time.perf_counter()
        r = c.get(f"/runs/{rid}/findings", headers=h,
                  params={"limit": 50, "sort": "severity", "severity": "critical"})
        page_s = time.perf_counter() - t
        assert r.status_code == 200 and len(r.json()) == 50
        assert int(r.headers["X-Total-Count"]) == 10000
        t = time.perf_counter()
        assert c.get(f"/runs/{rid}/findings/summary", headers=h).json()["hosts"] == 1000
        summary_s = time.perf_counter() - t
    with session_scope(pg_factory) as s:
        assert s.get(ScanRun, rid) is not None
    # первый запрос включает расчёт приоритетов всего прогона (кэшируется)
    assert page_s < 30 and summary_s < 5, (page_s, summary_s)
