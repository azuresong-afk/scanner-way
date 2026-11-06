"""Подключение к СУБД по учётной записи договора — только чтение (db_audit).

Один интерфейс `DbSession` над четырьмя драйверами:

* PostgreSQL и Postgres Pro — psycopg 3 (``sslmode=prefer``: TLS, если сервер
  его поддерживает);
* MySQL и MariaDB — PyMySQL (режим TLS PREFERRED по умолчанию);
* Microsoft SQL Server — pymssql (FreeTDS; шифрование — по настройке FreeTDS,
  по умолчанию «request»);
* Oracle Database — python-oracledb в тонком режиме (без Oracle Client).

Безопасность:
- сессия переводится в режим «только чтение» средствами СУБД, где это есть
  (PostgreSQL ``default_transaction_read_only``, MySQL/MariaDB
  ``SET SESSION TRANSACTION READ ONLY``, Oracle ``SET TRANSACTION READ ONLY``);
  модуль выполняет только фиксированные SELECT/SHOW из своего кода, без
  подстановки входных данных;
- у каждого запроса таймаут, у выборки — лимит строк и длины значений;
- пароль учётки передаётся драйверу параметром и не попадает в тексты ошибок:
  `_clean` вырезает его из сообщений драйвера на всякий случай;
- адрес — только литеральный IP, уже прошедший allowlist оркестратора.

Драйверы импортируются лениво: без драйвера модуль сообщает «драйвер не
установлен», остальные СУБД проверяются.
"""
from __future__ import annotations

import contextlib
import os
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Protocol

from scanner.core.credentials import (
    DEFAULT_DB_NAMES,
    PROTOCOL_MSSQL,
    PROTOCOL_MYSQL,
    PROTOCOL_ORACLE,
    PROTOCOL_POSTGRESQL,
    HostCredential,
)

APP_NAME = "scanner-db-audit"
MAX_VALUE_LEN = 4000


class DbError(RuntimeError):
    """Ошибка подключения или запроса (текст — без секретов)."""


class DbAuthFailed(DbError):
    """СУБД отклонила логин/пароль (или вход с адреса сканера запрещён)."""


class DbUnreachable(DbError):
    """Порт СУБД закрыт, хост не ответил, истёк таймаут подключения."""


class DbDriverMissing(DbError):
    """Драйвер СУБД не установлен в образе сканера."""


class DbQueryError(DbError):
    """Запрос не выполнен (нет прав на представление, нет таблицы и т. п.)."""


@dataclass(slots=True)
class DbOptions:
    connect_timeout_sec: float = 10.0
    query_timeout_sec: float = 30.0
    max_rows: int = 5000


def options_from_env() -> DbOptions:
    def num(name: str, default: float) -> float:
        try:
            return float(os.environ.get(name, "") or default)
        except ValueError:
            return default
    return DbOptions(connect_timeout_sec=num("SCANNER_DBAUDIT_CONNECT_TIMEOUT", 10.0),
                     query_timeout_sec=num("SCANNER_DBAUDIT_QUERY_TIMEOUT", 30.0))


class DbSession(Protocol):
    protocol: str

    def query(self, sql: str) -> list[tuple[Any, ...]]: ...

    def close(self) -> None: ...


Connector = Callable[[str, HostCredential, DbOptions], DbSession]


def _clean(e: BaseException, cred: HostCredential) -> str:
    text = " ".join(str(e).split())[:400]
    if cred.password:
        text = text.replace(cred.password, "***")
    return text


def _value(v: Any) -> Any:
    if v is None or isinstance(v, (bool, int, float)):
        return v
    if isinstance(v, (bytes, bytearray, memoryview)):
        v = bytes(v).decode("utf-8", "replace")
    s = str(v)
    return s[:MAX_VALUE_LEN]


def _timed_out(text: str) -> bool:
    t = text.lower()
    return "timeout" in t or "timed out" in t or "таймаут" in t


class _CursorSession:
    """Общая часть: выполнить запрос, вернуть до max_rows строк значений."""

    protocol = ""

    def __init__(self, conn: Any, cred: HostCredential, options: DbOptions,
                 errors: tuple[type[BaseException], ...]):
        self._conn = conn
        self._cred = cred
        self._options = options
        self._errors = errors

    def query(self, sql: str) -> list[tuple[Any, ...]]:
        try:
            cur = self._conn.cursor()
            try:
                cur.execute(sql)
                rows = cur.fetchmany(self._options.max_rows) if cur.description else []
            finally:
                with contextlib.suppress(Exception):
                    cur.close()
        except self._errors as e:
            self._after_error()
            raise DbQueryError(_clean(e, self._cred)) from None
        return [tuple(_value(v) for v in row) for row in rows]

    def _after_error(self) -> None:
        """После ошибки запроса сессия должна остаться пригодной."""

    def close(self) -> None:
        with contextlib.suppress(Exception):     # закрытие не должно ронять прогон
            self._conn.close()


# ---------- PostgreSQL / Postgres Pro ----------

class _PgSession(_CursorSession):
    protocol = PROTOCOL_POSTGRESQL


def _connect_pg(host: str, cred: HostCredential, o: DbOptions) -> DbSession:
    try:
        import psycopg
    except ImportError as e:  # pragma: no cover — psycopg в зависимостях сканера
        raise DbDriverMissing("драйвер PostgreSQL (psycopg) не установлен") from e
    ms = int(o.query_timeout_sec * 1000)
    try:
        conn = psycopg.connect(
            host=host, port=cred.port, user=cred.username, password=cred.password or "",
            dbname=cred.db_name or DEFAULT_DB_NAMES[PROTOCOL_POSTGRESQL],
            connect_timeout=max(1, int(o.connect_timeout_sec)), sslmode="prefer",
            application_name=APP_NAME, autocommit=True,
            options=f"-c default_transaction_read_only=on -c statement_timeout={ms}")
    except psycopg.OperationalError as e:
        text = _clean(e, cred)
        low = text.lower()
        if getattr(e, "sqlstate", None) in ("28P01", "28000") or \
                "authentication failed" in low or "pg_hba.conf" in low or \
                "password" in low and "authentication" in low:
            raise DbAuthFailed(text) from None
        if "does not exist" in low:          # нет базы для входа
            raise DbError(text) from None
        raise DbUnreachable(text) from None
    except psycopg.Error as e:
        raise DbError(_clean(e, cred)) from None
    return _PgSession(conn, cred, o, (psycopg.Error,))


# ---------- MySQL / MariaDB ----------

class _MySession(_CursorSession):
    protocol = PROTOCOL_MYSQL


def _connect_mysql(host: str, cred: HostCredential, o: DbOptions) -> DbSession:
    try:
        import pymysql
    except ImportError as e:
        raise DbDriverMissing("драйвер MySQL/MariaDB (PyMySQL) не установлен") from e
    try:
        conn = pymysql.connect(
            host=host, port=cred.port, user=cred.username, password=cred.password or "",
            database=cred.db_name or None, connect_timeout=max(1, int(o.connect_timeout_sec)),
            read_timeout=max(1, int(o.query_timeout_sec)),
            write_timeout=max(1, int(o.query_timeout_sec)),
            program_name=APP_NAME, autocommit=True, local_infile=False)
    except pymysql.err.OperationalError as e:
        code = e.args[0] if e.args else None
        text = _clean(e, cred)
        if code in (1044, 1045, 1130, 1698):     # доступ запрещён / хост не допущен
            raise DbAuthFailed(text) from None
        raise DbUnreachable(text) from None
    except pymysql.err.MySQLError as e:
        raise DbError(_clean(e, cred)) from None
    s = _MySession(conn, cred, o, (pymysql.err.MySQLError,))
    for stmt in ("SET SESSION TRANSACTION READ ONLY",):
        try:
            s.query(stmt)
        except DbQueryError:
            pass
    return s


# ---------- Microsoft SQL Server ----------

class _MsSession(_CursorSession):
    protocol = PROTOCOL_MSSQL


def _connect_mssql(host: str, cred: HostCredential, o: DbOptions) -> DbSession:
    try:
        import pymssql
    except ImportError as e:
        raise DbDriverMissing("драйвер MS SQL Server (pymssql) не установлен") from e
    try:
        conn = pymssql.connect(
            server=host, port=str(cred.port), user=cred.username,
            password=cred.password or "",
            database=cred.db_name or DEFAULT_DB_NAMES[PROTOCOL_MSSQL],
            login_timeout=max(1, int(o.connect_timeout_sec)),
            timeout=max(1, int(o.query_timeout_sec)), appname=APP_NAME, autocommit=True)
    except pymssql.Error as e:
        text = _clean(e, cred)
        if "18456" in text or "login failed" in text.lower():
            raise DbAuthFailed(text) from None
        raise DbUnreachable(text) from None
    return _MsSession(conn, cred, o, (pymssql.Error,))


# ---------- Oracle ----------

class _OraSession(_CursorSession):
    protocol = PROTOCOL_ORACLE

    def _after_error(self) -> None:
        with contextlib.suppress(Exception):   # оставить сессию «только чтение»
            self._conn.rollback()
            cur = self._conn.cursor()
            cur.execute("SET TRANSACTION READ ONLY")
            cur.close()


def _connect_oracle(host: str, cred: HostCredential, o: DbOptions) -> DbSession:
    try:
        import oracledb
    except ImportError as e:
        raise DbDriverMissing("драйвер Oracle (python-oracledb) не установлен") from e
    try:
        conn = oracledb.connect(
            user=cred.username, password=cred.password or "", host=host, port=cred.port,
            service_name=cred.db_name, tcp_connect_timeout=o.connect_timeout_sec)
        conn.call_timeout = int(o.query_timeout_sec * 1000)
        conn.module = APP_NAME
    except oracledb.Error as e:
        text = _clean(e, cred)
        if "ORA-01017" in text or "ORA-28000" in text or "ORA-01045" in text:
            raise DbAuthFailed(text) from None
        if "ORA-12514" in text or "DPY-6001" in text:      # сервис не найден
            raise DbError(text) from None
        raise DbUnreachable(text) from None
    s = _OraSession(conn, cred, o, (oracledb.Error,))
    try:
        s.query("SET TRANSACTION READ ONLY")
    except DbQueryError:
        pass
    return s


_CONNECTORS: dict[str, Connector] = {
    PROTOCOL_POSTGRESQL: _connect_pg,
    PROTOCOL_MYSQL: _connect_mysql,
    PROTOCOL_MSSQL: _connect_mssql,
    PROTOCOL_ORACLE: _connect_oracle,
}


def connect(host: str, cred: HostCredential, options: DbOptions) -> DbSession:
    """Подключиться к СУБД хоста по учётке. DbAuthFailed / DbUnreachable /
    DbDriverMissing / DbError — с понятным текстом без секретов."""
    fn = _CONNECTORS.get(cred.protocol)
    if fn is None:
        raise DbError(f"протокол {cred.protocol!r} не относится к СУБД")
    try:
        return fn(host, cred, options)
    except DbError:
        raise
    except (OSError, TimeoutError) as e:
        raise DbUnreachable(_clean(e, cred)) from None


def is_timeout(e: BaseException) -> bool:
    return _timed_out(str(e))
