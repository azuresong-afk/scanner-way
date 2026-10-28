"""Общие фикстуры БД: SQLite в памяти (по умолчанию) и опционально Postgres.

Postgres-тесты запускаются, только если задан SCANNER_TEST_DATABASE_URL
(например, в CI с сервисом postgres:16). База должна быть пустой: тест сам
применяет миграции Alembic и откатывает их в конце.
"""
from __future__ import annotations

import os

import pytest
from sqlalchemy import create_engine, event
from sqlalchemy.pool import StaticPool

from scanner.core.db import Base, make_session_factory

PG_URL = os.environ.get("SCANNER_TEST_DATABASE_URL")


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
