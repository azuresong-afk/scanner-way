"""Наборы проверки учёток договора (аудит паролей на согласованных учётках).

Все операции — только с правом cred_audit. Секреты принимаются на вход и сразу
шифруются; ни один ответ API и ни одна запись аудита их не содержат (наружу —
имя, сервисы, число записей и маскированные логины). Встроенных словарей нет:
набор целиком задаёт оператор под конкретный договор, с лимитом записей.
"""
from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status

from scanner.api.deps import AuditDep, Principal, SessionDep, require
from scanner.api.rbac import Perm
from scanner.api.routes_engagements import get_engagement
from scanner.api.schemas import CredSetIn, CredSetOut
from scanner.core import repository as repo
from scanner.core.credentials import CredentialError
from scanner.core.db import CredAuditSetRow

router = APIRouter(prefix="/engagements", tags=["cred-sets"])

# Выдаётся только с правом cred_audit — как и сам модуль аудита учётных данных.
CredAuditUser = Annotated[Principal, Depends(require(Perm.CRED_AUDIT))]


def _out(vault, row: CredAuditSetRow) -> CredSetOut:
    return CredSetOut(
        id=row.id, engagement_id=row.engagement_id, name=row.name,
        services=list(row.services or []), entry_count=row.entry_count,
        masked_usernames=repo.cred_set_masked_usernames(vault, row),
        created_by=row.created_by, created_at=row.created_at)


@router.get("/{engagement_id}/cred-sets", response_model=list[CredSetOut])
def list_cred_sets(engagement_id: int, _: CredAuditUser, request: Request,
                   session: SessionDep) -> list[CredSetOut]:
    get_engagement(session, engagement_id)
    vault = request.app.state.runs.vault
    rows = repo.list_cred_audit_sets(session, engagement_id)
    if vault is None:
        # Без ключа секреты не расшифровать — отдаём метаданные без логинов.
        return [CredSetOut(id=r.id, engagement_id=r.engagement_id, name=r.name,
                           services=list(r.services or []), entry_count=r.entry_count,
                           masked_usernames=[], created_by=r.created_by,
                           created_at=r.created_at) for r in rows]
    return [_out(vault, r) for r in rows]


@router.post("/{engagement_id}/cred-sets", response_model=CredSetOut, status_code=201)
def create_cred_set(engagement_id: int, body: CredSetIn, request: Request,
                    user: CredAuditUser, session: SessionDep,
                    audit: AuditDep) -> CredSetOut:
    get_engagement(session, engagement_id)
    vault = request.app.state.runs.vault
    if vault is None:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, {
            "code": "credentials_key_missing",
            "message": "не задан ключ шифрования учётных записей: "
                       "SCANNER_CREDENTIALS_KEY (или SCANNER_API_SECRET) в .env"})
    entries = [(e.username, e.secret) for e in body.entries]
    try:
        sid = repo.create_cred_audit_set(session, vault, engagement_id=engagement_id,
                                         name=body.name, entries=entries,
                                         services=body.services, created_by=user.id)
    except CredentialError as e:
        audit.record(subject=user.subject, action="cred_set_create",
                     target=f"engagement:{engagement_id}", result="rejected",
                     details={"name": body.name, "reason": str(e)[:300]})
        raise HTTPException(422, str(e)) from e
    session.commit()
    row = session.get(CredAuditSetRow, sid)
    # В аудит — только метаданные набора; логины и секреты не пишутся.
    audit.record(subject=user.subject, action="cred_set_create",
                 target=f"engagement:{engagement_id}", result="ok",
                 details={"cred_set_id": sid, "name": row.name,
                          "services": list(row.services or []),
                          "entry_count": row.entry_count})
    return _out(vault, row)


@router.delete("/{engagement_id}/cred-sets/{set_id}", status_code=204)
def delete_cred_set(engagement_id: int, set_id: int, user: CredAuditUser,
                    session: SessionDep, audit: AuditDep) -> Response:
    row = repo.get_cred_audit_set(session, engagement_id, set_id)
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "cred set not found")
    details = {"cred_set_id": row.id, "name": row.name, "entry_count": row.entry_count}
    session.delete(row)
    session.commit()
    audit.record(subject=user.subject, action="cred_set_delete",
                 target=f"engagement:{engagement_id}", result="ok", details=details)
    return Response(status_code=204)
