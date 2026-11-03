"""Регрессия: тесты и откат миграций не могут разрушить рабочую БД.

Сценарий из лабораторной проверки: SCANNER_TEST_DATABASE_URL по ошибке указывал
на рабочую базу, PG-тесты применили и откатили миграции — данные пропали.
"""
from __future__ import annotations

import secrets
from pathlib import Path

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url

from scanner.core import dbsafety
from scanner.core.dbsafety import UnsafeDatabaseError
from tests import conftest

ROOT = Path(__file__).resolve().parents[1]
# порт 1 на localhost: подключение невозможно — проверка обязана отказать без него
NO_SERVER = "postgresql+psycopg://u:p@127.0.0.1:1/scanner"


def test_production_name_rejected_without_connecting():
    assert dbsafety.is_disposable(NO_SERVER) is False
    with pytest.raises(UnsafeDatabaseError, match="не является временной тестовой"):
        dbsafety.assert_disposable(NO_SERVER)


def test_cannot_create_temp_db_fails_before_changes():
    with pytest.raises(UnsafeDatabaseError, match="CREATE DATABASE"):
        dbsafety.create_temp_database(NO_SERVER)


def test_drop_refuses_unmarked_database():
    with pytest.raises(UnsafeDatabaseError):
        dbsafety.drop_temp_database(NO_SERVER, NO_SERVER)


pg_only = pytest.mark.skipif(not conftest.PG_SERVER_URL,
                             reason="SCANNER_TEST_DATABASE_URL not set")


@pg_only
def test_tests_never_use_database_from_env():
    """PG_URL — отдельная временная база, а не база из SCANNER_TEST_DATABASE_URL."""
    assert conftest.PG_URL
    assert make_url(conftest.PG_URL).database != make_url(conftest.PG_SERVER_URL).database
    assert make_url(conftest.PG_URL).database.startswith(dbsafety.TEMP_DB_PREFIX)
    assert dbsafety.is_disposable(conftest.PG_URL)


@pytest.fixture
def victim_db():
    """«Рабочая» база с данными (без пометки тестовой)."""
    server = conftest.PG_SERVER_URL
    name = "scanner_guard_victim_" + secrets.token_hex(4)
    admin = create_engine(make_url(server), isolation_level="AUTOCOMMIT")
    with admin.connect() as c:
        c.execute(text(f'CREATE DATABASE "{name}"'))
    url = make_url(server).set(database=name).render_as_string(hide_password=False)
    yield url
    with admin.connect() as c:
        c.execute(text(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)'))
    admin.dispose()


def _cfg(url: str):
    from alembic.config import Config
    cfg = Config(str(ROOT / "alembic.ini"))
    cfg.set_main_option("script_location", str(ROOT / "alembic"))
    cfg.set_main_option("sqlalchemy.url", url)
    return cfg


@pg_only
def test_downgrade_refused_on_unmarked_database(victim_db, monkeypatch):
    from alembic import command
    monkeypatch.delenv(dbsafety.ALLOW_DOWNGRADE_ENV, raising=False)
    command.upgrade(_cfg(victim_db), "head")
    engine = create_engine(victim_db)
    with engine.begin() as c:
        c.execute(text("INSERT INTO engagements(name) VALUES ('боевой договор')"))

    assert dbsafety.is_disposable(victim_db) is False
    with pytest.raises(UnsafeDatabaseError, match="Откат миграций отменён"):
        command.downgrade(_cfg(victim_db), "base")
    with pytest.raises(UnsafeDatabaseError):
        command.downgrade(_cfg(victim_db), "-1")

    # откат отменён в той же транзакции: схема и данные на месте
    with engine.connect() as c:
        assert c.scalar(text("SELECT count(*) FROM engagements")) == 1
        heads = c.scalar(text("SELECT version_num FROM alembic_version"))
    engine.dispose()
    from scanner.core.health import expected_revision
    assert heads == expected_revision()


@pg_only
def test_prefix_without_mark_is_not_disposable():
    server = conftest.PG_SERVER_URL
    name = dbsafety.TEMP_DB_PREFIX + "nomark" + secrets.token_hex(3)
    admin = create_engine(make_url(server), isolation_level="AUTOCOMMIT")
    try:
        with admin.connect() as c:
            c.execute(text(f'CREATE DATABASE "{name}"'))
        url = make_url(server).set(database=name)
        assert dbsafety.is_disposable(url) is False
        with pytest.raises(UnsafeDatabaseError):
            dbsafety.drop_temp_database(server, url)
    finally:
        with admin.connect() as c:
            c.execute(text(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)'))
        admin.dispose()


@pg_only
def test_explicit_override_allows_operator_downgrade(victim_db, monkeypatch):
    from alembic import command
    command.upgrade(_cfg(victim_db), "head")
    monkeypatch.setenv(dbsafety.ALLOW_DOWNGRADE_ENV, "1")
    command.downgrade(_cfg(victim_db), "-1")
