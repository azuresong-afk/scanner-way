"""Журнал аудита действий сканера (append-only).

`DbAuditSink` пишет в таблицу `audit_log`; неизменяемость записей дополнительно
обеспечена триггером в БД (Alembic-миграция 0002). `StdoutAuditSink` — для
локальной отладки без БД.
"""
from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any, Protocol

from sqlalchemy.orm import Session, sessionmaker

from scanner.core.db import AuditLogRow

AuditDetails = str | dict[str, Any] | None


class AuditSink(Protocol):
    def record(self, *, subject: str, action: str, target: str,
               result: str, details: AuditDetails = None) -> None: ...


class StdoutAuditSink:
    """Аудит в stdout (отладка без БД)."""

    def record(self, *, subject: str, action: str, target: str,
               result: str, details: AuditDetails = None) -> None:
        ts = datetime.now(UTC).isoformat()
        print(f"[AUDIT] {ts} subject={subject} action={action} "
              f"target={target} result={result} details={details}")


def normalize_details(details: AuditDetails) -> dict[str, Any] | None:
    """details для JSONB: dict как есть, JSON-строка разбирается, прочее — в message."""
    if details is None or isinstance(details, dict):
        return details
    try:
        parsed = json.loads(details)
    except ValueError:
        return {"message": details}
    return parsed if isinstance(parsed, dict) else {"message": details}


class DbAuditSink:
    """Аудит в таблицу audit_log.

    Каждая запись коммитится в отдельной короткой транзакции: запись аудита не
    должна теряться при откате бизнес-транзакции (например, отказ allowlist при
    упавшем прогоне). Ошибка записи аудита пробрасывается — действие без следа в
    журнале выполняться не должно.
    """

    def __init__(self, session_factory: sessionmaker[Session]):
        self._factory = session_factory

    def record(self, *, subject: str, action: str, target: str,
               result: str, details: AuditDetails = None) -> None:
        with self._factory() as session, session.begin():
            session.add(AuditLogRow(subject=subject, action=action, target=target,
                                    result=result, details=normalize_details(details),
                                    ts=datetime.now(UTC)))
