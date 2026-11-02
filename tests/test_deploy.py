"""Production-развёртывание: проверка секретов перед стартом и проверки
работоспособности API (/health, /health/ready)."""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine

from scanner.api.main import create_app
from scanner.api.settings import ApiSettings
from scanner.core.health import check_database, expected_revision, is_ready
from scanner.core.orchestrator import inline_executor
from scanner.core.preflight import check_env, main
from scanner.reporting.remediation import RemediationResolver
from tests.conftest import PG_URL
from tests.test_migrations_pg import pg_factory  # noqa: F401 — фикстура

GOOD = {"SCANNER_API_SECRET": "s" * 48, "POSTGRES_PASSWORD": "db-pass-1",
        "SCANNER_API_BOOTSTRAP_PASSWORD": "admin-pass-123",
        "SCANNER_CREDENTIALS_KEY": "k" * 24}


# ---------- preflight ----------
def test_good_env_passes():
    assert check_env(GOOD) == ([], [])
    assert main({**GOOD, "SCANNER_ENV": "production"}) == 0


def test_placeholders_and_weak_values_are_reported():
    env = {"SCANNER_API_SECRET": "CHANGE_ME_token_signing_secret_min_32_chars",
           "POSTGRES_PASSWORD": "CHANGE_ME_db_password",
           "SCANNER_API_BOOTSTRAP_PASSWORD": "CHANGE_ME_admin_password_min_12",
           "SCANNER_CREDENTIALS_KEY": "short", "WEB_CONCURRENCY": "4"}
    problems, _ = check_env(env)
    text = "\n".join(problems)
    for name in ("SCANNER_API_SECRET", "POSTGRES_PASSWORD", "SCANNER_API_BOOTSTRAP_PASSWORD",
                 "SCANNER_CREDENTIALS_KEY", "WEB_CONCURRENCY"):
        assert name in text
    assert "короче 32" in check_env({**GOOD, "SCANNER_API_SECRET": "x" * 10})[0][0]
    assert check_env({**GOOD, "SCANNER_API_SECRET": ""})[0]


def test_production_refuses_to_start_dev_only_warns(capsys):
    bad = {**GOOD, "SCANNER_API_SECRET": "CHANGE_ME"}
    assert main({**bad, "SCANNER_ENV": "production"}) == 1
    assert "старт остановлен" in capsys.readouterr().err
    assert main(bad) == 0
    assert "ВНИМАНИЕ" in capsys.readouterr().err


def test_missing_credentials_key_is_a_warning():
    env = dict(GOOD)
    del env["SCANNER_CREDENTIALS_KEY"]
    problems, warnings = check_env(env)
    assert problems == [] and "SCANNER_CREDENTIALS_KEY" in warnings[0]


# ---------- готовность ----------
def test_expected_revision_is_alembic_head():
    from pathlib import Path
    files = sorted(Path(__file__).resolve().parents[1].glob("alembic/versions/[0-9]*_*.py"))
    assert expected_revision() == files[-1].name[:4]


def test_is_ready_rules():
    ok = {"database": "ok", "migration": "0017", "expected": "0017"}
    assert is_ready(ok, {"runs": True})
    assert not is_ready({**ok, "migration": "0016"}, {"runs": True})
    assert not is_ready({"database": "error"}, {"runs": True})
    assert not is_ready(ok, {"runs": True, "scheduler": False})


def test_check_database_reports_unreachable_db():
    engine = create_engine("postgresql+psycopg://u:p@127.0.0.1:1/x",
                           connect_args={"connect_timeout": 1})
    out = check_database(engine)
    assert out["database"] == "error" and "OperationalError" in out["error"]


def _app(factory, **kw):
    settings = ApiSettings(secret="z" * 40, run_heartbeat_seconds=0, **kw)
    return create_app(session_factory=factory, settings=settings, registry={},
                      executor=inline_executor(),
                      resolver_factory=lambda f: RemediationResolver())


def test_ready_endpoint_without_migration_check(sqlite_factory):
    with TestClient(_app(sqlite_factory, ready_check_migrations=False,
                         scheduler_tick_seconds=0, feeds_tick_seconds=0,
                         notify_tick_seconds=0)) as c:
        assert c.get("/health").json() == {"status": "ok"}
        r = c.get("/health/ready")
        assert r.status_code == 200 and r.json()["database"] == "ok"


def test_ready_is_503_when_schema_is_not_migrated(sqlite_factory):
    # схема SQLite создана без Alembic: таблицы alembic_version нет
    with TestClient(_app(sqlite_factory, scheduler_tick_seconds=0, feeds_tick_seconds=0,
                         notify_tick_seconds=0)) as c:
        r = c.get("/health/ready")
        assert r.status_code == 503
        assert r.json()["migration"] is None and r.json()["expected"] == expected_revision()


@pytest.mark.skipif(not PG_URL, reason="SCANNER_TEST_DATABASE_URL not set")
def test_ready_on_migrated_postgres(pg_factory):  # noqa: F811
    with TestClient(_app(pg_factory, scheduler_tick_seconds=0, feeds_tick_seconds=0,
                         notify_tick_seconds=0)) as c:
        r = c.get("/health/ready")
        assert r.status_code == 200, r.text
        assert r.json()["migration"] == r.json()["expected"] == expected_revision()
