"""Защита рабочей БД от разрушительных операций тестов и отката миграций.

Тесты PostgreSQL применяют и откатывают все миграции (`alembic downgrade base`),
то есть удаляют все таблицы. Если по ошибке направить их на рабочую БД
(SCANNER_TEST_DATABASE_URL = адрес боевой базы), данные будут уничтожены.

Поэтому:
  * тесты никогда не работают в базе из SCANNER_TEST_DATABASE_URL — по этому
    адресу они только создают отдельную временную базу
    (`scanner_test_tmp_<случайно>`, с пометкой-комментарием) и в конце её
    удаляют. Нет права CREATE DATABASE — тесты завершаются с ошибкой до любых
    изменений (см. tests/conftest.py);
  * откат миграций (`downgrade`) Alembic выполняет только в базе с такой
    пометкой либо при явном SCANNER_ALLOW_DOWNGRADE=1 (осознанный откат
    оператором после резервной копии). Иначе откат отменяется в той же
    транзакции и Alembic завершается с ошибкой (см. alembic/env.py).
"""
from __future__ import annotations

import os
import secrets

from sqlalchemy import create_engine, text
from sqlalchemy.engine import URL, make_url

TEMP_DB_PREFIX = "scanner_test_tmp_"
TEST_DB_MARK = "scanner-disposable-test-database"
ALLOW_DOWNGRADE_ENV = "SCANNER_ALLOW_DOWNGRADE"


class UnsafeDatabaseError(RuntimeError):
    """Операция разрушила бы данные в базе, не помеченной как тестовая."""


def _db_name(url: str | URL) -> str:
    return make_url(url).database or ""


def database_mark(url: str | URL) -> str | None:
    """Комментарий текущей базы (pg_database) — пометка тестовой базы."""
    engine = create_engine(url)
    try:
        with engine.connect() as c:
            return c.scalar(text(
                "SELECT shobj_description(oid, 'pg_database') FROM pg_database "
                "WHERE datname = current_database()"))
    finally:
        engine.dispose()


def is_disposable(url: str | URL, *, mark: str | None = None) -> bool:
    """База создана тестами: имя с префиксом и пометка-комментарий.

    Сначала проверяется имя (без подключения): рабочая база отбраковывается
    сразу. mark — уже прочитанная пометка (иначе читается из базы)."""
    if not _db_name(url).startswith(TEMP_DB_PREFIX):
        return False
    if mark is None:
        mark = database_mark(url)
    return mark == TEST_DB_MARK


def assert_disposable(url: str | URL, action: str = "изменение схемы") -> None:
    """UnsafeDatabaseError, если база не временная тестовая (до любых изменений)."""
    if not is_disposable(url):
        raise UnsafeDatabaseError(
            f"{action} отменено: база «{_db_name(url)}» не является временной тестовой "
            f"(нужно имя {TEMP_DB_PREFIX}… и пометка {TEST_DB_MARK}). Тесты PostgreSQL "
            "создают такую базу сами по адресу SCANNER_TEST_DATABASE_URL и не "
            "трогают базу, указанную в адресе.")


def downgrade_allowed(connection) -> bool:
    """Можно ли откатывать миграции в базе этого подключения (alembic/env.py)."""
    if os.environ.get(ALLOW_DOWNGRADE_ENV, "").strip().lower() in ("1", "true", "yes"):
        return True
    name = connection.scalar(text("SELECT current_database()")) or ""
    if not name.startswith(TEMP_DB_PREFIX):
        return False
    mark = connection.scalar(text(
        "SELECT shobj_description(oid, 'pg_database') FROM pg_database "
        "WHERE datname = current_database()"))
    return mark == TEST_DB_MARK


def create_temp_database(server_url: str | URL) -> str:
    """Создаёт пустую временную базу на том же сервере и возвращает её адрес.

    В базе из server_url ничего не меняется: подключение к ней нужно только,
    чтобы выполнить CREATE DATABASE. UnsafeDatabaseError — нет прав/сервера."""
    base = make_url(server_url)
    name = TEMP_DB_PREFIX + secrets.token_hex(6)
    engine = create_engine(base, isolation_level="AUTOCOMMIT")
    try:
        with engine.connect() as c:
            c.execute(text(f'CREATE DATABASE "{name}"'))
            c.execute(text(f"COMMENT ON DATABASE \"{name}\" IS '{TEST_DB_MARK}'"))
    except Exception as e:  # noqa: BLE001 — любая ошибка = тестов не будет
        raise UnsafeDatabaseError(
            "не удалось создать временную тестовую базу по адресу "
            "SCANNER_TEST_DATABASE_URL (нужно право CREATE DATABASE): "
            f"{type(e).__name__}: {e}") from e
    finally:
        engine.dispose()
    return base.set(database=name).render_as_string(hide_password=False)


def drop_temp_database(server_url: str | URL, temp_url: str | URL) -> None:
    """Удаляет временную базу (только помеченную как тестовая)."""
    assert_disposable(temp_url, "удаление базы")
    name = _db_name(temp_url)
    engine = create_engine(make_url(server_url), isolation_level="AUTOCOMMIT")
    try:
        with engine.connect() as c:
            c.execute(text(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)'))
    finally:
        engine.dispose()
