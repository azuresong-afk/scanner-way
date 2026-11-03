"""Общие фикстуры БД: SQLite в памяти (по умолчанию) и опционально Postgres.

Postgres-тесты запускаются, только если задан SCANNER_TEST_DATABASE_URL
(например, в CI с сервисом postgres:16). Тесты применяют и откатывают все
миграции, поэтому в базе из этого адреса они НЕ работают: при старте сессии по
нему создаётся отдельная пустая временная база (scanner_test_tmp_…, помечена
комментарием), PG_URL указывает на неё, а в конце она удаляется. Нет права
CREATE DATABASE — сессия завершается с ошибкой до любых изменений
(scanner.core.dbsafety). Даже направленные на рабочую БД, тесты её не трогают.
"""
from __future__ import annotations

import os

import pytest
from sqlalchemy import create_engine, event
from sqlalchemy.pool import StaticPool

from scanner.core.db import Base, make_session_factory

# Адрес сервера из окружения (только для CREATE/DROP DATABASE) и адрес
# временной базы, в которой работают тесты. PG_URL заполняется в
# pytest_configure — до импорта тестовых модулей (они берут его при импорте).
PG_SERVER_URL = os.environ.get("SCANNER_TEST_DATABASE_URL")
PG_URL: str | None = None


def pytest_configure(config):
    config.addinivalue_line(
        "markers", "e2e: сквозной сценарий на живом стеке Docker (scripts/e2e.sh)")
    global PG_URL
    if PG_SERVER_URL and PG_URL is None and not hasattr(config, "workerinput"):
        from scanner.core.dbsafety import UnsafeDatabaseError, create_temp_database
        try:
            PG_URL = create_temp_database(PG_SERVER_URL)
        except UnsafeDatabaseError as e:
            pytest.exit(f"PostgreSQL-тесты не запущены: {e}", returncode=3)


def pytest_unconfigure(config):
    global PG_URL
    if PG_SERVER_URL and PG_URL:
        from scanner.core.dbsafety import drop_temp_database
        try:
            drop_temp_database(PG_SERVER_URL, PG_URL)
        finally:
            PG_URL = None


@pytest.fixture
def sqlite_factory():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False},
                           poolclass=StaticPool)

    @event.listens_for(engine, "connect")
    def _fk_on(dbapi_conn, _):
        dbapi_conn.execute("PRAGMA foreign_keys=ON")

    Base.metadata.create_all(engine)
    yield make_session_factory(engine)
    engine.dispose()


@pytest.fixture(autouse=True)
def _fresh_priority_cache():
    """Кэш приоритетов живёт в процессе API и ключуется id прогона; у тестов
    каждая БД своя, а id прогонов повторяются — кэш сбрасывается между тестами."""
    from scanner.api.routes_findings import clear_priority_cache
    clear_priority_cache()
    yield
