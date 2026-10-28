"""Просмотр журнала аудита (append-only, только чтение)."""
from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Query
from sqlalchemy import select

from scanner.api.deps import AuditDep, Principal, SessionDep, require
from scanner.api.rbac import Perm
from scanner.api.schemas import AuditOut
from scanner.core.db import AuditLogRow

router = APIRouter(tags=["audit"])


@router.get("/audit", response_model=list[AuditOut])
def list_audit(user: Annotated[Principal, Depends(require(Perm.VIEW_AUDIT))],
               session: SessionDep, audit: AuditDep,
               limit: Annotated[int, Query(ge=1, le=1000)] = 100,
               before_id: Annotated[int | None, Query(ge=1)] = None,
               subject: str | None = None, action: str | None = None,
               ) -> list[AuditLogRow]:
    """Записи от новых к старым; страница дальше — before_id=<id последней>."""
    q = select(AuditLogRow).order_by(AuditLogRow.id.desc()).limit(limit)
    if before_id is not None:
        q = q.where(AuditLogRow.id < before_id)
    if subject:
        q = q.where(AuditLogRow.subject == subject)
    if action:
        q = q.where(AuditLogRow.action == action)
    rows = list(session.scalars(q))
    audit.record(subject=user.subject, action="audit_view", target="audit_log",
                 result="ok", details={"subject": subject, "action": action,
                                       "before_id": before_id, "returned": len(rows)})
    return rows
