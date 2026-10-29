"""Учётные записи активов договора (для инвентаризации по учётной записи).

Все операции — только с правом host_credentials. Секреты принимаются на вход
и сразу шифруются; ни один ответ API и ни одна запись аудита их не содержат.
"""
from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status

from scanner.api.deps import AuditDep, Principal, SessionDep, require
from scanner.api.rbac import Perm
from scanner.api.routes_engagements import get_engagement
from scanner.api.schemas import CredentialIn, CredentialOut
from scanner.core import repository as repo
from scanner.core.credentials import CredentialError
from scanner.core.db import HostCredentialRow

router = APIRouter(prefix="/engagements", tags=["credentials"])

CredUser = Annotated[Principal, Depends(require(Perm.HOST_CREDENTIALS))]


@router.get("/{engagement_id}/credentials", response_model=list[CredentialOut])
def list_credentials(engagement_id: int, _: CredUser,
                     session: SessionDep) -> list[HostCredentialRow]:
    get_engagement(session, engagement_id)
    return repo.list_host_credentials(session, engagement_id)


@router.post("/{engagement_id}/credentials", response_model=CredentialOut,
             status_code=201)
def create_credential(engagement_id: int, body: CredentialIn, request: Request,
                      user: CredUser, session: SessionDep,
                      audit: AuditDep) -> HostCredentialRow:
    get_engagement(session, engagement_id)
    vault = request.app.state.runs.vault
    if vault is None:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, {
            "code": "credentials_key_missing",
            "message": "не задан ключ шифрования учётных записей: "
                       "SCANNER_CREDENTIALS_KEY (или SCANNER_API_SECRET) в .env"})
    try:
        cid = repo.create_host_credential(
            session, vault, engagement_id=engagement_id, name=body.name, auth=body.auth,
            username=body.username, port=body.port, targets=body.targets,
            password=body.password if body.auth == "password" else None,
            private_key=body.private_key if body.auth == "key" else None,
            passphrase=body.passphrase if body.auth == "key" else None,
            created_by=user.id)
    except CredentialError as e:
        audit.record(subject=user.subject, action="credential_create",
                     target=f"engagement:{engagement_id}", result="rejected",
                     details={"name": body.name, "user": body.username,
                              "auth": body.auth, "reason": str(e)[:300]})
        raise HTTPException(422, str(e)) from e
    session.commit()
    row = session.get(HostCredentialRow, cid)
    audit.record(subject=user.subject, action="credential_create",
                 target=f"engagement:{engagement_id}", result="ok",
                 details={"credential_id": cid, "name": row.name, "user": row.username,
                          "port": row.port, "auth": row.auth,
                          "targets": list(row.targets or []),
                          "key_fingerprint": row.key_fingerprint})
    return row


@router.delete("/{engagement_id}/credentials/{credential_id}", status_code=204)
def delete_credential(engagement_id: int, credential_id: int, user: CredUser,
                      session: SessionDep, audit: AuditDep) -> Response:
    row = session.get(HostCredentialRow, credential_id)
    if row is None or row.engagement_id != engagement_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "credential not found")
    details = {"credential_id": row.id, "name": row.name, "user": row.username}
    session.delete(row)
    session.commit()
    audit.record(subject=user.subject, action="credential_delete",
                 target=f"engagement:{engagement_id}", result="ok", details=details)
    return Response(status_code=204)
