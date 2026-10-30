"""Активы договора: владельцы, критичность, теги, группы (R7).

Чтение — view_engagements, изменение — manage_engagements; каждое изменение
пишется в журнал аудита.
"""
from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Response, status

from scanner.api.deps import AuditDep, Principal, SessionDep, require
from scanner.api.rbac import Perm
from scanner.api.routes_engagements import get_engagement
from scanner.api.schemas import (
    AssetBulkIn,
    AssetGroupIn,
    AssetGroupOut,
    AssetIn,
    AssetOut,
    AssetTagOut,
    AssetUpdate,
)
from scanner.core import assets as svc

router = APIRouter(prefix="/engagements", tags=["assets"])

Reader = Annotated[Principal, Depends(require(Perm.VIEW_ENGAGEMENTS))]
Writer = Annotated[Principal, Depends(require(Perm.MANAGE_ENGAGEMENTS))]


def _bad(e: svc.AssetError) -> HTTPException:
    code = status.HTTP_409_CONFLICT if isinstance(e, svc.DuplicateError) else 422
    return HTTPException(code, str(e))


def _asset(session, engagement_id: int, asset_id: int):
    row = svc.get_asset(session, engagement_id, asset_id)
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "asset not found")
    return row


def _group(session, engagement_id: int, group_id: int):
    g = svc.get_group(session, engagement_id, group_id)
    if g is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "asset group not found")
    return g


def _view(session, engagement_id: int, row) -> dict:
    return svc.asset_views(session, engagement_id, [row])[0]


@router.get("/{engagement_id}/assets", response_model=list[AssetOut])
def list_assets(engagement_id: int, _: Reader, session: SessionDep,
                tag: str | None = None, group_id: int | None = None,
                criticality: str | None = None, owner: str | None = None,
                q: str | None = None) -> list[dict]:
    get_engagement(session, engagement_id)
    if criticality is not None and criticality not in svc.CRITICALITY:
        raise HTTPException(422, f"criticality: one of {', '.join(svc.CRITICALITY)}")
    rows = svc.list_assets(session, engagement_id, tag=tag, group_id=group_id,
                           criticality=criticality, owner=owner, q=q)
    return svc.asset_views(session, engagement_id, rows)


@router.post("/{engagement_id}/assets", response_model=AssetOut, status_code=201)
def create_asset(engagement_id: int, body: AssetIn, user: Writer, session: SessionDep,
                 audit: AuditDep) -> dict:
    get_engagement(session, engagement_id)
    try:
        row = svc.create_asset(session, engagement_id, created_by=user.id,
                               **body.model_dump())
    except svc.AssetError as e:
        raise _bad(e) from e
    session.commit()
    audit.record(subject=user.subject, action="asset_create",
                 target=f"engagement:{engagement_id}", result="ok",
                 details={"asset_id": row.id, "address": svc.host_key(row.address),
                          "criticality": row.criticality})
    return _view(session, engagement_id, row)


@router.post("/{engagement_id}/assets/import-discovered", response_model=list[AssetOut],
             status_code=201)
def import_discovered(engagement_id: int, user: Writer, session: SessionDep,
                      audit: AuditDep) -> list[dict]:
    """Завести активы для всех найденных прогонами хостов, которых ещё нет в реестре."""
    get_engagement(session, engagement_id)
    rows = svc.import_discovered(session, engagement_id, created_by=user.id)
    session.commit()
    audit.record(subject=user.subject, action="asset_import",
                 target=f"engagement:{engagement_id}", result="ok",
                 details={"created": len(rows)})
    return svc.asset_views(session, engagement_id, rows)


@router.post("/{engagement_id}/assets/bulk", response_model=list[AssetOut])
def bulk_assets(engagement_id: int, body: AssetBulkIn, user: Writer, session: SessionDep,
                audit: AuditDep) -> list[dict]:
    """Массовое назначение тегов, групп, критичности и владельца."""
    get_engagement(session, engagement_id)
    rows = [svc.get_asset(session, engagement_id, i) for i in dict.fromkeys(body.asset_ids)]
    missing = [i for i, r in zip(dict.fromkeys(body.asset_ids), rows, strict=True) if r is None]
    if missing:
        raise HTTPException(status.HTTP_404_NOT_FOUND, f"assets not found: {missing}")
    try:
        svc.bulk_update(session, engagement_id, rows, **body.model_dump(exclude={"asset_ids"}))
    except svc.AssetError as e:
        raise _bad(e) from e
    session.commit()
    audit.record(subject=user.subject, action="asset_bulk_update",
                 target=f"engagement:{engagement_id}", result="ok",
                 details={"assets": len(rows),
                          **body.model_dump(exclude={"asset_ids"}, exclude_defaults=True)})
    return svc.asset_views(session, engagement_id, rows)


@router.get("/{engagement_id}/assets/{asset_id}", response_model=AssetOut)
def read_asset(engagement_id: int, asset_id: int, _: Reader, session: SessionDep) -> dict:
    return _view(session, engagement_id, _asset(session, engagement_id, asset_id))


@router.patch("/{engagement_id}/assets/{asset_id}", response_model=AssetOut)
def update_asset(engagement_id: int, asset_id: int, body: AssetUpdate, user: Writer,
                 session: SessionDep, audit: AuditDep) -> dict:
    row = _asset(session, engagement_id, asset_id)
    changes = body.model_dump(exclude_unset=True)
    for required in ("address", "criticality"):
        if required in changes and changes[required] is None:
            raise HTTPException(422, f"{required} cannot be null")
    for lst in ("tags", "group_ids"):
        if lst in changes and changes[lst] is None:
            changes[lst] = []
    try:
        svc.update_asset(session, row, changes)
    except svc.AssetError as e:
        raise _bad(e) from e
    session.commit()
    audit.record(subject=user.subject, action="asset_update",
                 target=f"engagement:{engagement_id}", result="ok",
                 details={"asset_id": asset_id, "fields": sorted(changes)})
    return _view(session, engagement_id, row)


@router.delete("/{engagement_id}/assets/{asset_id}", status_code=204)
def delete_asset(engagement_id: int, asset_id: int, user: Writer, session: SessionDep,
                 audit: AuditDep) -> Response:
    row = _asset(session, engagement_id, asset_id)
    details = {"asset_id": row.id, "address": svc.host_key(row.address)}
    svc.delete_asset(session, row)
    session.commit()
    audit.record(subject=user.subject, action="asset_delete",
                 target=f"engagement:{engagement_id}", result="ok", details=details)
    return Response(status_code=204)


@router.get("/{engagement_id}/asset-tags", response_model=list[AssetTagOut])
def list_tags(engagement_id: int, _: Reader, session: SessionDep) -> list[AssetTagOut]:
    get_engagement(session, engagement_id)
    return [AssetTagOut(tag=t, count=n) for t, n in svc.tag_counts(session, engagement_id)]


@router.get("/{engagement_id}/asset-groups", response_model=list[AssetGroupOut])
def list_groups(engagement_id: int, _: Reader, session: SessionDep) -> list[dict]:
    get_engagement(session, engagement_id)
    return svc.group_views(session, engagement_id)


@router.post("/{engagement_id}/asset-groups", response_model=AssetGroupOut, status_code=201)
def create_group(engagement_id: int, body: AssetGroupIn, user: Writer, session: SessionDep,
                 audit: AuditDep) -> dict:
    get_engagement(session, engagement_id)
    try:
        g = svc.create_group(session, engagement_id, body.name)
    except svc.AssetError as e:
        raise _bad(e) from e
    session.commit()
    audit.record(subject=user.subject, action="asset_group_create",
                 target=f"engagement:{engagement_id}", result="ok",
                 details={"group_id": g.id, "name": g.name})
    return next(v for v in svc.group_views(session, engagement_id) if v["id"] == g.id)


@router.patch("/{engagement_id}/asset-groups/{group_id}", response_model=AssetGroupOut)
def rename_group(engagement_id: int, group_id: int, body: AssetGroupIn, user: Writer,
                 session: SessionDep, audit: AuditDep) -> dict:
    g = _group(session, engagement_id, group_id)
    old = g.name
    try:
        svc.rename_group(session, g, body.name)
    except svc.AssetError as e:
        raise _bad(e) from e
    session.commit()
    audit.record(subject=user.subject, action="asset_group_rename",
                 target=f"engagement:{engagement_id}", result="ok",
                 details={"group_id": g.id, "from": old, "to": g.name})
    return next(v for v in svc.group_views(session, engagement_id) if v["id"] == g.id)


@router.delete("/{engagement_id}/asset-groups/{group_id}", status_code=204)
def delete_group(engagement_id: int, group_id: int, user: Writer, session: SessionDep,
                 audit: AuditDep) -> Response:
    g = _group(session, engagement_id, group_id)
    details = {"group_id": g.id, "name": g.name}
    session.delete(g)
    session.commit()
    audit.record(subject=user.subject, action="asset_group_delete",
                 target=f"engagement:{engagement_id}", result="ok", details=details)
    return Response(status_code=204)
