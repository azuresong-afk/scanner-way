"""Просмотр и выгрузка журнала аудита (append-only, только чтение)."""
from __future__ import annotations

from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, Response
from sqlalchemy import select

from scanner.api.deps import AuditDep, Principal, SessionDep, require
from scanner.api.rbac import Perm
from scanner.api.schemas import AuditOut
from scanner.core import audit_export as ax
from scanner.core.db import AuditLogRow

router = APIRouter(tags=["audit"])

ActionsQ = Annotated[list[str] | None, Query(
    alias="action", description="Тип действия; параметр можно повторять (логическое ИЛИ)")]
SinceQ = Annotated[datetime | None, Query(description="Начало диапазона, включительно (ISO 8601)")]
UntilQ = Annotated[datetime | None, Query(description="Конец диапазона, не включительно (ISO 8601)")]


def _filter(actions: list[str] | None, subject: str | None,
            since: datetime | None, until: datetime | None) -> ax.AuditFilter:
    try:
        return ax.AuditFilter(actions=actions or (), subject=subject or None,
                              since=since, until=until)
    except ValueError as e:
        raise HTTPException(422, str(e)) from e


@router.get("/audit", response_model=list[AuditOut])
def list_audit(user: Annotated[Principal, Depends(require(Perm.VIEW_AUDIT))],
               session: SessionDep, audit: AuditDep,
               limit: Annotated[int, Query(ge=1, le=1000)] = 100,
               before_id: Annotated[int | None, Query(ge=1)] = None,
               subject: str | None = None, actions: ActionsQ = None,
               since: SinceQ = None, until: UntilQ = None,
               ) -> list[AuditLogRow]:
    """Записи от новых к старым; страница дальше — before_id=<id последней>."""
    flt = _filter(actions, subject, since, until)
    q = flt.apply(select(AuditLogRow)).order_by(AuditLogRow.id.desc()).limit(limit)
    if before_id is not None:
        q = q.where(AuditLogRow.id < before_id)
    rows = list(session.scalars(q))
    audit.record(subject=user.subject, action="audit_view", target="audit_log",
                 result="ok", details={**flt.describe(), "before_id": before_id,
                                       "returned": len(rows)})
    return rows


@router.get("/audit/actions", response_model=list[str])
def audit_actions(user: Annotated[Principal, Depends(require(Perm.VIEW_AUDIT))],
                  session: SessionDep) -> list[str]:
    """Типы действий, которые встречаются в журнале (для фильтров выгрузки)."""
    return list(session.scalars(select(AuditLogRow.action).distinct().order_by(AuditLogRow.action)))


@router.get("/audit/export", response_class=Response, responses={
    200: {"content": {"text/csv": {}, "application/json": {}},
          "description": "Файл выгрузки (attachment)"},
    413: {"description": f"Больше {ax.MAX_EXPORT_ROWS} записей — сузьте фильтр"}})
def export_audit(user: Annotated[Principal, Depends(require(Perm.VIEW_AUDIT))],
                 session: SessionDep, audit: AuditDep,
                 format: ax.ExportFormat = ax.ExportFormat.CSV,
                 subject: str | None = None, actions: ActionsQ = None,
                 since: SinceQ = None, until: UntilQ = None) -> Response:
    """Выгрузка событий журнала в CSV или JSON, от старых к новым.

    Доступна тем же ролям, что и просмотр журнала (право view_audit). Сам факт
    выгрузки фиксируется в журнале действием `audit_export`.
    """
    flt = _filter(actions, subject, since, until)
    rows = list(session.scalars(ax.export_query(flt)))
    now = datetime.now(UTC)
    if len(rows) > ax.MAX_EXPORT_ROWS:
        audit.record(subject=user.subject, action="audit_export", target="audit_log",
                     result="too_large", details={**flt.describe(), "format": format.value})
        raise HTTPException(413,
                            f"под фильтр попадает больше {ax.MAX_EXPORT_ROWS} записей — "
                            "сузьте диапазон времени или набор действий")
    if format is ax.ExportFormat.CSV:
        body = ax.to_csv(rows)
    else:
        body = ax.to_json(rows, flt=flt, exported_by=user.subject, exported_at=now)
    audit.record(subject=user.subject, action="audit_export", target="audit_log",
                 result="ok", details={**flt.describe(), "format": format.value,
                                       "returned": len(rows)})
    return Response(content=body, media_type=ax.CONTENT_TYPES[format], headers={
        "Content-Disposition": f'attachment; filename="{ax.filename(format, now)}"',
        "X-Audit-Count": str(len(rows))})

