"""Журнал аудита действий (append-only на уровне приложения)."""
from __future__ import annotations

from datetime import datetime
from typing import Protocol


class AuditSink(Protocol):
    def record(self, *, subject: str, action: str, target: str,
               result: str, details: str | None = None) -> None: ...


class StdoutAuditSink:
    """Заглушка аудита для каркаса; в проде — запись в таблицу audit_log."""

    def record(self, *, subject: str, action: str, target: str,
               result: str, details: str | None = None) -> None:
        ts = datetime.utcnow().isoformat()
        print(f"[AUDIT] {ts} subject={subject} action={action} "
              f"target={target} result={result} details={details}")
