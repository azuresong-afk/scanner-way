"""Договоры (engagements) и их allowlist."""
from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Response, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from scanner.api.deps import AuditDep, Principal, SessionDep, require
from scanner.api.rbac import Perm
from scanner.api.schemas import (
    AllowlistIn,
    AllowlistOut,
    EngagementIn,
    EngagementOut,
    EngagementUpdate,
)
from scanner.core import repository as repo
from scanner.core.db import AllowlistEntry, Engagement, ScanRun

router = APIRouter(prefix="/engagements", tags=["engagements"])


def get_engagement(session: Session, engagement_id: int) -> Engagement:
    e = session.get(Engagement, engagement_id)
    if e is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "engagement not found")
    return e


@router.get("", response_model=list[EngagementOut])
def list_engagements(_: Annotated[Principal, Depends(require(Perm.VIEW_ENGAGEMENTS))],
                     session: SessionDep) -> list[Engagement]:
    return list(session.scalars(select(Engagement).order_by(Engagement.id)))


@router.post("", response_model=EngagementOut, status_code=201)
def create_engagement(body: EngagementIn,
                      user: Annotated[Principal, Depends(require(Perm.MANAGE_ENGAGEMENTS))],
                      session: SessionDep,
                      audit: AuditDep) -> Engagement:
    eid = repo.create_engagement(session, name=body.name, client=body.client,
                                 contract_ref=body.contract_ref, created_by=user.id)
    session.commit()
    audit.record(subject=user.subject, action="engagement_create",
                 target=f"engagement:{eid}", result="ok", details=body.model_dump())
    return get_engagement(session, eid)


@router.get("/{engagement_id}", response_model=EngagementOut)
def read_engagement(engagement_id: int,
                    _: Annotated[Principal, Depends(require(Perm.VIEW_ENGAGEMENTS))],
                    session: SessionDep) -> Engagement:
    return get_engagement(session, engagement_id)


@router.patch("/{engagement_id}", response_model=EngagementOut)
def update_engagement(engagement_id: int, body: EngagementUpdate,
                      user: Annotated[Principal, Depends(require(Perm.MANAGE_ENGAGEMENTS))],
                      session: SessionDep,
                      audit: AuditDep) -> Engagement:
    e = get_engagement(session, engagement_id)
    changed = body.model_dump(exclude_unset=True)
    if changed.get("name") is None:
        changed.pop("name", None)          # имя обязательно, null не принимаем
    for k, v in changed.items():
        setattr(e, k, v)
    session.commit()
    audit.record(subject=user.subject, action="engagement_update",
                 target=f"engagement:{e.id}", result="ok", details=changed)
    return e


@router.delete("/{engagement_id}", status_code=204)
def delete_engagement(engagement_id: int,
                      user: Annotated[Principal, Depends(require(Perm.MANAGE_ENGAGEMENTS))],
                      session: SessionDep,
                      audit: AuditDep) -> Response:
    e = get_engagement(session, engagement_id)
    # Каскад снёс бы прогоны и находки — историю договора удалять через API нельзя.
    if session.scalar(select(ScanRun.id).where(ScanRun.engagement_id == e.id).limit(1)):
        audit.record(subject=user.subject, action="engagement_delete",
                     target=f"engagement:{e.id}", result="rejected_has_runs")
        raise HTTPException(status.HTTP_409_CONFLICT,
                            "engagement has scan runs and cannot be deleted")
    session.delete(e)
    session.commit()
    audit.record(subject=user.subject, action="engagement_delete",
                 target=f"engagement:{engagement_id}", result="ok",
                 details={"name": e.name})
    return Response(status_code=204)


# ---- allowlist ----
@router.get("/{engagement_id}/allowlist", response_model=list[AllowlistOut])
def list_allowlist(engagement_id: int,
                   _: Annotated[Principal, Depends(require(Perm.VIEW_ENGAGEMENTS))],
                   session: SessionDep) -> list[AllowlistEntry]:
    get_engagement(session, engagement_id)
    return list(session.scalars(select(AllowlistEntry)
                                .where(AllowlistEntry.engagement_id == engagement_id)
                                .order_by(AllowlistEntry.id)))


@router.post("/{engagement_id}/allowlist", response_model=AllowlistOut, status_code=201)
def add_allowlist(engagement_id: int, body: AllowlistIn,
                  user: Annotated[Principal, Depends(require(Perm.MANAGE_ALLOWLIST))],
                  session: SessionDep,
                  audit: AuditDep) -> AllowlistEntry:
    get_engagement(session, engagement_id)
    try:
        entry_id = repo.add_allowlist_entry(session, engagement_id=engagement_id,
                                            cidr=body.cidr, note=body.note,
                                            added_by=user.id)
    except ValueError as e:
        raise HTTPException(422,
                            f"invalid CIDR: {body.cidr}") from e
    session.commit()
    entry = session.get(AllowlistEntry, entry_id)
    audit.record(subject=user.subject, action="allowlist_add",
                 target=f"engagement:{engagement_id}", result="ok",
                 details={"entry_id": entry_id, "cidr": str(entry.cidr), "note": body.note})
    return entry


@router.delete("/{engagement_id}/allowlist/{entry_id}", status_code=204)
def delete_allowlist(engagement_id: int, entry_id: int,
                     user: Annotated[Principal, Depends(require(Perm.MANAGE_ALLOWLIST))],
                     session: SessionDep,
                     audit: AuditDep) -> Response:
    entry = session.get(AllowlistEntry, entry_id)
    if entry is None or entry.engagement_id != engagement_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "allowlist entry not found")
    cidr = str(entry.cidr)
    session.delete(entry)
    session.commit()
    audit.record(subject=user.subject, action="allowlist_remove",
                 target=f"engagement:{engagement_id}", result="ok",
                 details={"entry_id": entry_id, "cidr": cidr})
    return Response(status_code=204)
