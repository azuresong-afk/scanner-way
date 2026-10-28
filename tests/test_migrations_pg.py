"""Миграции Alembic и round-trip на реальном PostgreSQL.

Запускается только при заданном SCANNER_TEST_DATABASE_URL (пустая база), иначе
пропускается — локально и в CI без Postgres тесты не требуют БД.
"""
from __future__ import annotations

from pathlib import Path

import pytest
from sqlalchemy import create_engine, inspect, text

from tests.conftest import PG_URL

pytestmark = pytest.mark.skipif(not PG_URL, reason="SCANNER_TEST_DATABASE_URL not set")

ROOT = Path(__file__).resolve().parents[1]


def _alembic_cfg():
    from alembic.config import Config
    cfg = Config(str(ROOT / "alembic.ini"))
    cfg.set_main_option("script_location", str(ROOT / "alembic"))
    cfg.set_main_option("sqlalchemy.url", PG_URL)
    return cfg


@pytest.fixture
def pg_factory():
    from alembic import command
    from scanner.core.db import make_engine, make_session_factory
    cfg = _alembic_cfg()
    command.upgrade(cfg, "head")
    engine = make_engine(PG_URL)
    yield make_session_factory(engine)
    engine.dispose()
    command.downgrade(cfg, "base")


def test_migrations_create_schema(pg_factory):
    engine = create_engine(PG_URL)
    tables = set(inspect(engine).get_table_names())
    assert {"engagements", "targets_allowlist", "scan_runs", "host_results",
            "service_results", "findings", "audit_log", "reference_bdu_entry",
            "reference_nvd_cve", "reference_nvd_cpe_match", "alembic_version"} <= tables
    engine.dispose()


def test_pg_round_trip_and_append_only_audit(pg_factory):
    from scanner.core import repository as repo
    from scanner.core.audit import DbAuditSink
    from scanner.core.db import session_scope
    from scanner.core.models import Finding, FindingType, ServiceInfo, Severity

    with session_scope(pg_factory) as s:
        eid = repo.create_engagement(s, name="pg")
        repo.add_allowlist_entry(s, engagement_id=eid, cidr="10.1.0.0/16")
        rid = repo.create_scan_run(s, engagement_id=eid, modules=["vuln"])
        repo.save_services(s, scan_run_id=rid,
                           services=[ServiceInfo("10.1.2.3", 22, "tcp", "ssh")])
        f = Finding(module="vuln", host="10.1.2.3", finding_type=FindingType.VULN,
                    title="t", port=22, vuln_id="CVE-2013-5946",
                    cve_ids=["CVE-2013-5946"], bdu_ids=["BDU:2014-00002"],
                    severity=Severity.HIGH, cvss=7.5)
        repo.save_findings(s, engagement_id=eid, scan_run_id=rid, findings=[f])
    with session_scope(pg_factory) as s:
        got = repo.get_findings(s, rid)
        assert got[0].dedup_key() == f.dedup_key()
        assert got[0].bdu_ids == ["BDU:2014-00002"] and got[0].cvss == 7.5
        assert repo.get_services(s, rid)[0].host == "10.1.2.3"
        assert repo.load_allowlist_gate(s, eid).is_allowed("10.1.200.1")

    DbAuditSink(pg_factory).record(subject="scanner", action="deny",
                                   target="8.8.8.8", result="not_in_allowlist",
                                   details={"why": "test"})
    with pg_factory() as s:
        with pytest.raises(Exception, match="append-only"):
            s.execute(text("UPDATE audit_log SET result = 'ok'"))
        s.rollback()
        with pytest.raises(Exception, match="append-only"):
            s.execute(text("DELETE FROM audit_log"))
        s.rollback()
        assert s.scalar(text("SELECT details->>'why' FROM audit_log")) == "test"
