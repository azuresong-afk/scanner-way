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
            "reference_nvd_cve", "reference_nvd_cpe_match", "scan_schedules",
            "false_positives", "assets", "asset_tags", "asset_groups",
            "asset_group_members", "distro_advisory",
            "alembic_version"} <= tables
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


def test_pg_credentials_and_packages_round_trip(pg_factory):
    from scanner.core import repository as repo
    from scanner.core.credentials import CredentialVault
    from scanner.core.db import session_scope
    from scanner.core.models import HostInventory, InstalledPackage

    vault = CredentialVault("k" * 32)
    with session_scope(pg_factory) as s:
        eid = repo.create_engagement(s, name="pg")
        repo.add_allowlist_entry(s, engagement_id=eid, cidr="10.1.0.0/16")
        cid = repo.create_host_credential(s, vault, engagement_id=eid, name="a",
                                          auth="password", username="audit",
                                          password="pw-123", targets=["10.1.2.0/24"])
        rid = repo.create_scan_run(s, engagement_id=eid, modules=["auth_inventory"],
                                   credential_ids=[cid])
        repo.save_inventory(s, scan_run_id=rid, inventories=[HostInventory(
            "10.1.2.3", os_name="Debian GNU/Linux 12 (bookworm)",
            packages=[InstalledPackage("bash", "5.2.15-2+b2", "dpkg", "amd64")])])
    with session_scope(pg_factory) as s:
        assert repo.get_scan_run(s, rid).credential_ids == [cid]
        creds = repo.load_host_credentials(s, vault, eid, [cid])
        assert creds[0].password == "pw-123" and creds[0].targets == ("10.1.2.0/24",)
        assert [(h, p.name) for h, p in repo.get_packages(s, rid)] == [("10.1.2.3", "bash")]
        hosts = repo.engagement_hosts(s, eid)
        assert hosts[0]["os_guess"] == "Debian GNU/Linux 12 (bookworm)"
        assert (hosts[0]["packages_run_id"], hosts[0]["package_count"]) == (rid, 1)
        assert "pw-123" not in s.scalar(text("SELECT secret_enc FROM host_credentials"))


def test_pg_assets_round_trip(pg_factory):
    from scanner.core import assets as svc
    from scanner.core import repository as repo
    from scanner.core.db import session_scope

    with session_scope(pg_factory) as s:
        eid = repo.create_engagement(s, name="pg-assets")
        g = svc.create_group(s, eid, "DMZ")
        a = svc.create_asset(s, eid, address="10.0.0.5", owner="ИТ", tags=["Prod"],
                             group_ids=[g.id], criticality="high")
        with pytest.raises(svc.DuplicateError):
            svc.create_asset(s, eid, address="10.0.0.5")
        views = svc.asset_views(s, eid, svc.list_assets(s, eid, tag="prod", group_id=g.id))
        assert [(v["address"], v["criticality"]) for v in views] == [("10.0.0.5", "high")]
        assert svc.group_hosts(s, g.id) == {"10.0.0.5"}
        svc.delete_asset(s, a)
        assert svc.group_views(s, eid)[0]["asset_count"] == 0


def test_pg_distro_advisory_round_trip(pg_factory):
    from scanner.feeds.advisories.base import FIXED, OPEN, Advisory
    from scanner.feeds.advisories.store import SqlAdvisoryStore

    store = SqlAdvisoryStore(create_engine(PG_URL), batch_size=2)
    rows = [Advisory("debian", "bookworm", "openssl", "CVE-2024-0727", FIXED,
                     "3.0.13-1~deb12u1", "DSA-5678-1"),
            Advisory("debian", "bookworm", "openssl", "CVE-2099-1111", OPEN),
            Advisory("debian", "bookworm", "openssh", "CVE-2024-6387", FIXED,
                     "1:9.2p1-2+deb12u3")]
    assert store.replace_release("debian", "bookworm", rows) == 3
    assert store.replace_release("debian", "bookworm", rows) == 3   # замена, не дубли
    got = store.for_packages("debian", "bookworm", ["openssl", "openssh"])
    assert sorted(a.cve for a in got["openssl"]) == ["CVE-2024-0727", "CVE-2099-1111"]
    assert store.releases() == {("debian", "bookworm")}
    store.engine.dispose()
