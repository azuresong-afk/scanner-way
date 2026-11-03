"""Окружение Alembic. Только online-режим против PostgreSQL."""
from __future__ import annotations

import os
from logging.config import fileConfig

from sqlalchemy import create_engine, pool

from alembic import context

config = context.config
if config.config_file_name is not None:
    fileConfig(config.config_file_name)


def _url() -> str:
    url = config.get_main_option("sqlalchemy.url") or os.environ.get("SCANNER_DATABASE_URL")
    if url:
        return url
    from scanner.core.config import settings
    return settings.database_url


def _guard_downgrade(ctx, step, heads, run_args) -> None:  # noqa: ARG001
    """Откат миграции удаляет таблицы с данными: разрешён только во временной
    тестовой базе или при явном SCANNER_ALLOW_DOWNGRADE=1 (см.
    scanner.core.dbsafety). Вызывается после шага, но до фиксации транзакции —
    исключение откатывает всё (DDL в PostgreSQL транзакционный)."""
    if step.is_upgrade:
        return
    from scanner.core.dbsafety import (
        ALLOW_DOWNGRADE_ENV,
        UnsafeDatabaseError,
        downgrade_allowed,
    )
    if not downgrade_allowed(ctx.connection):
        raise UnsafeDatabaseError(
            "Откат миграций отменён: база не помечена как временная тестовая. "
            "Откат удаляет таблицы с данными; если он действительно нужен, сделайте "
            f"резервную копию и запустите с {ALLOW_DOWNGRADE_ENV}=1.")


def run_migrations_online() -> None:
    engine = create_engine(_url(), poolclass=pool.NullPool)
    with engine.connect() as connection:
        context.configure(connection=connection, on_version_apply=_guard_downgrade)
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    raise SystemExit("offline mode is not supported; run against a database")
run_migrations_online()
