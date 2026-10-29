"""Выгрузка журнала аудита в CSV/JSON (только чтение).

Журнал неизменяемый: модуль строит запрос SELECT и сериализует строки, ничего в
`audit_log` не пишет и не меняет. Отметку о самой выгрузке (`audit_export`)
делает вызывающий код через обычный `AuditSink`.
"""
from __future__ import annotations

import csv
import io
import json
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from sqlalchemy import Select, select

from scanner.core.db import AuditLogRow

# Потолок одной выгрузки: файл собирается в памяти процесса API. Больше — пусть
# сужают диапазон времени или набор действий.
MAX_EXPORT_ROWS = 100_000

CSV_COLUMNS = ("id", "ts", "subject", "action", "target", "result", "details")


class ExportFormat(StrEnum):
    CSV = "csv"
    JSON = "json"


CONTENT_TYPES = {
    ExportFormat.CSV: "text/csv; charset=utf-8",
    ExportFormat.JSON: "application/json",
}


def as_utc(ts: datetime | None) -> datetime | None:
    """Время без зоны считаем UTC (так его пишет DbAuditSink)."""
    if ts is None:
        return None
    return ts.replace(tzinfo=UTC) if ts.tzinfo is None else ts.astimezone(UTC)


@dataclass(frozen=True)
class AuditFilter:
    """Фильтр журнала: набор действий (ИЛИ), субъект, полуинтервал [since, until)."""
    actions: Sequence[str] = field(default_factory=tuple)
    subject: str | None = None
    since: datetime | None = None
    until: datetime | None = None

    def __post_init__(self):
        object.__setattr__(self, "actions", tuple(sorted({a for a in self.actions if a})))
        object.__setattr__(self, "since", as_utc(self.since))
        object.__setattr__(self, "until", as_utc(self.until))
        if self.since and self.until and self.since >= self.until:
            raise ValueError("начало диапазона должно быть раньше конца")

    def apply(self, q: Select) -> Select:
        if self.actions:
            q = q.where(AuditLogRow.action.in_(self.actions))
        if self.subject:
            q = q.where(AuditLogRow.subject == self.subject)
        if self.since:
            q = q.where(AuditLogRow.ts >= self.since)
        if self.until:
            q = q.where(AuditLogRow.ts < self.until)
        return q

    def describe(self) -> dict[str, Any]:
        """Фильтр в JSON-виде: для шапки выгрузки и записи в журнал."""
        return {"actions": list(self.actions), "subject": self.subject,
                "since": self.since.isoformat() if self.since else None,
                "until": self.until.isoformat() if self.until else None}


def export_query(flt: AuditFilter) -> Select:
    """Записи в хронологическом порядке (как читают журнал при разборе инцидента).

    На одну строку больше потолка — чтобы отличить «ровно потолок» от «больше»."""
    return (flt.apply(select(AuditLogRow)).order_by(AuditLogRow.ts, AuditLogRow.id)
            .limit(MAX_EXPORT_ROWS + 1))


def row_dict(row: AuditLogRow) -> dict[str, Any]:
    ts = as_utc(row.ts)
    return {"id": row.id, "ts": ts.isoformat() if ts else None, "subject": row.subject,
            "action": row.action, "target": row.target, "result": row.result,
            "details": row.details}


def _csv_cell(value: Any) -> str:
    """Ячейка CSV. Значения из журнала могут прийти со сканируемых хостов, поэтому
    формулы (=, +, -, @, таб, CR) экранируются апострофом — защита от CSV-инъекций
    при открытии файла в Excel/LibreOffice."""
    if value is None:
        return ""
    if isinstance(value, dict | list):
        value = json.dumps(value, ensure_ascii=False, sort_keys=True)
    text = str(value)
    if text and text[0] in "=+-@\t\r":
        text = "'" + text
    return text


def to_csv(rows: Iterable[AuditLogRow]) -> bytes:
    """CSV с BOM: Excel без него показывает кириллицу кракозябрами."""
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\r\n")
    w.writerow(CSV_COLUMNS)
    for row in rows:
        d = row_dict(row)
        w.writerow([_csv_cell(d[c]) for c in CSV_COLUMNS])
    return ("﻿" + buf.getvalue()).encode("utf-8")


def to_json(rows: Sequence[AuditLogRow], *, flt: AuditFilter, exported_by: str,
            exported_at: datetime) -> bytes:
    doc = {"exported_at": exported_at.isoformat(), "exported_by": exported_by,
           "filters": flt.describe(), "count": len(rows),
           "events": [row_dict(r) for r in rows]}
    return json.dumps(doc, ensure_ascii=False, indent=1).encode("utf-8")


def filename(fmt: ExportFormat, now: datetime) -> str:
    return f"audit-{now.strftime('%Y%m%dT%H%M%SZ')}.{fmt.value}"
