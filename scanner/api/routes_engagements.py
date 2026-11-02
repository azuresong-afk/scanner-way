"""Договоры (engagements) и их allowlist."""
from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Response, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from scanner.api.deps import AuditDep, Principal, SessionDep, require
from scanner.api.rbac import Perm
from scanner.api.schemas import (
    AllowlistBulkIn,
    AllowlistBulkOut,
    AllowlistIn,
    AllowlistOut,
    AllowlistPartialOut,
    AllowlistSkippedOut,
    EngagementIn,
    EngagementOut,
    EngagementUpdate,
)
from scanner.core import repository as repo
from scanner.core.db import AllowlistEntry, Engagement, ScanRun
from scanner.core.targetspec import parse_target

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
    except repo.AllowlistDuplicate as dup:
        message = (f"{dup.cidr} уже есть в allowlist" if dup.exact else
                   f"{dup.cidr} уже входит в подсеть {dup.existing_cidr} из allowlist")
        raise HTTPException(status.HTTP_409_CONFLICT, {
            "message": message, "code": "allowlist_duplicate",
            "cidr": dup.cidr, "existing_id": dup.existing_id,
            "existing_cidr": dup.existing_cidr,
        }) from dup
    except ValueError as e:
        raise HTTPException(422,
                            f"invalid CIDR: {body.cidr}") from e
    session.commit()
    entry = session.get(AllowlistEntry, entry_id)
    audit.record(subject=user.subject, action="allowlist_add",
                 target=f"engagement:{engagement_id}", result="ok",
                 details={"entry_id": entry_id, "cidr": str(entry.cidr), "note": body.note})
    return entry


@router.post("/{engagement_id}/allowlist/bulk", response_model=AllowlistBulkOut, status_code=201)
def add_allowlist_bulk(engagement_id: int, body: AllowlistBulkIn,
                       user: Annotated[Principal, Depends(require(Perm.MANAGE_ALLOWLIST))],
                       session: SessionDep,
                       audit: AuditDep) -> AllowlistBulkOut:
    """Добавить сразу несколько целей: адреса, подсети, диапазоны «начало-конец».

    Всё или ничего по формату: хоть одна нераспознанная запись — 422 и ничего не
    занесено. Дубли (цель уже целиком в allowlist) пропускаются и перечисляются.
    """
    get_engagement(session, engagement_id)
    invalid = []
    for item in body.items:
        try:
            if item.strip():
                parse_target(item)
        except ValueError:
            invalid.append(item.strip())
    if invalid:
        raise HTTPException(422, {
            "message": "Не IP-адрес, подсеть или диапазон: " + ", ".join(invalid[:10])
                       + ("…" if len(invalid) > 10 else ""),
            "code": "allowlist_invalid", "invalid": invalid[:100]})
    res = repo.add_allowlist_specs(session, engagement_id=engagement_id, specs=body.items,
                                   note=body.note, added_by=user.id)
    session.commit()
    added = [session.get(AllowlistEntry, i) for i in res.added_ids]
    if added:
        audit.record(subject=user.subject, action="allowlist_add",
                     target=f"engagement:{engagement_id}", result="ok",
                     details={"entry_ids": res.added_ids,
                              "cidrs": [str(e.cidr) for e in added][:500],
                              "ranges": sorted({e.range_spec for e in added if e.range_spec}),
                              "skipped": len(res.skipped), "note": body.note})
    return AllowlistBulkOut(
        added=[AllowlistOut.model_validate(e) for e in added],
        skipped=[AllowlistSkippedOut(item=i, reason=r, existing_cidr=c) for i, r, c in res.skipped],
        partial=[AllowlistPartialOut(item=i, covered_parts=n) for i, n in res.partial])


@router.delete("/{engagement_id}/allowlist/{entry_id}", status_code=204)
def delete_allowlist(engagement_id: int, entry_id: int,
                     user: Annotated[Principal, Depends(require(Perm.MANAGE_ALLOWLIST))],
                     session: SessionDep,
                     audit: AuditDep,
                     whole_range: bool = False) -> Response:
    """Удалить запись. whole_range=true — вместе со всеми подсетями её диапазона."""
    entry = session.get(AllowlistEntry, entry_id)
    if entry is None or entry.engagement_id != engagement_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "allowlist entry not found")
    cidr = str(entry.cidr)
    range_spec = entry.range_spec
    if whole_range and range_spec:
        cidrs = repo.remove_allowlist_range(session, engagement_id, range_spec)
        details = {"entry_id": entry_id, "range": range_spec, "cidrs": cidrs}
    else:
        session.delete(entry)
        details = {"entry_id": entry_id, "cidr": cidr}
    session.commit()
    audit.record(subject=user.subject, action="allowlist_remove",
                 target=f"engagement:{engagement_id}", result="ok", details=details)
    return Response(status_code=204)
