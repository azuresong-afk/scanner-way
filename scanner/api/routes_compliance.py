"""Профили соответствия ФСТЭК №117/21/239 и CIS (R5).

Справочник профилей и сводка соответствия прогона — view_report; выбор
профилей договора (уровень, адаптация набора мер, «в отчёт») —
manage_engagements; пересчёт прогона после обновления профилей — run_scan.
Каждое изменение и пересчёт — в журнале аудита.
"""
from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Response, status

from scanner.api.deps import AuditDep, Principal, SessionDep, require
from scanner.api.rbac import Perm
from scanner.api.routes_engagements import get_engagement
from scanner.api.schemas import ComplianceProfileIn, ComplianceProfileOut
from scanner.compliance import store
from scanner.compliance.catalog import Profile, default_catalog
from scanner.core import repository as repo

router = APIRouter(tags=["compliance"])

FINISHED = {"done", "failed", "stopped"}


def _profile(profile_id: str) -> Profile:
    try:
        return default_catalog().profile(profile_id)
    except KeyError as e:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "compliance profile not found") from e


def _out(row) -> dict:
    return {"profile": row.profile, "level": row.level, "excluded": list(row.excluded or ()),
            "added": list(row.added or ()), "in_report": row.in_report,
            "updated_at": row.updated_at}


@router.get("/compliance/profiles")
def list_catalog(_: Annotated[Principal, Depends(require(Perm.VIEW_REPORT))]) -> list[dict]:
    """Профили с мерами и их привязкой к проверкам (для выбора и адаптации)."""
    cat = default_catalog()
    out = []
    for p in cat.profiles.values():
        d = p.to_dict()
        d["checks"] = {c.id: {"title": c.title, "platform": c.platform}
                       for c in cat.checks.values()
                       if any(c.id in ctl.checks for ctl in p.controls)}
        out.append(d)
    return out


@router.get("/engagements/{engagement_id}/compliance-profiles",
            response_model=list[ComplianceProfileOut])
def engagement_profiles(engagement_id: int,
                        _: Annotated[Principal, Depends(require(Perm.VIEW_ENGAGEMENTS))],
                        session: SessionDep) -> list[dict]:
    get_engagement(session, engagement_id)
    return [_out(r) for r in store.list_profiles(session, engagement_id)]


@router.put("/engagements/{engagement_id}/compliance-profiles/{profile_id}",
            response_model=ComplianceProfileOut)
def put_engagement_profile(engagement_id: int, profile_id: str, body: ComplianceProfileIn,
                           user: Annotated[Principal,
                                           Depends(require(Perm.MANAGE_ENGAGEMENTS))],
                           session: SessionDep, audit: AuditDep) -> dict:
    get_engagement(session, engagement_id)
    p = _profile(profile_id)
    try:
        row = store.upsert_profile(session, engagement_id, p, level=body.level,
                                   excluded=body.excluded, added=body.added,
                                   in_report=body.in_report, user_id=user.id)
    except ValueError as e:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, str(e)) from e
    session.commit()
    audit.record(subject=user.subject, action="compliance_profile_set",
                 target=f"engagement:{engagement_id}", result="ok",
                 details={"profile": p.id, "level": row.level, "excluded": row.excluded,
                          "added": row.added, "in_report": row.in_report})
    return _out(row)


@router.delete("/engagements/{engagement_id}/compliance-profiles/{profile_id}",
               status_code=204)
def delete_engagement_profile(engagement_id: int, profile_id: str,
                              user: Annotated[Principal,
                                              Depends(require(Perm.MANAGE_ENGAGEMENTS))],
                              session: SessionDep, audit: AuditDep) -> Response:
    get_engagement(session, engagement_id)
    row = store.get_profile_row(session, engagement_id, profile_id)
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "compliance profile not selected")
    session.delete(row)
    session.commit()
    audit.record(subject=user.subject, action="compliance_profile_delete",
                 target=f"engagement:{engagement_id}", result="ok",
                 details={"profile": profile_id})
    return Response(status_code=204)


def _run(session, run_id: int):
    run = repo.get_scan_run(session, run_id)
    if run is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "scan run not found")
    return run


@router.get("/runs/{run_id}/compliance")
def run_compliance(run_id: int,
                   _: Annotated[Principal, Depends(require(Perm.VIEW_REPORT))],
                   session: SessionDep, profile: str = "fstec-117",
                   level: str | None = None, group_id: int | None = None) -> dict:
    """Сводка соответствия прогона профилю: процент, разбивка по хостам и
    группам активов, провалы с рекомендациями, меры «проверяется вручную».
    level — уровень вместо сохранённого в договоре; group_id — только хосты группы."""
    run = _run(session, run_id)
    p = _profile(profile)
    if level is not None and level not in p.levels:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT,
                            f"{p.level_label}: допустимо {', '.join(p.levels) or '—'}")
    hosts = None
    if group_id is not None:
        from scanner.core import assets as asset_svc
        if asset_svc.get_group(session, run.engagement_id, group_id) is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "asset group not found")
        hosts = asset_svc.group_hosts(session, group_id)
    out = store.run_summary(session, run_id, run.engagement_id, p, level=level, hosts=hosts)
    out["has_results"] = store.has_results(session, run_id)
    out["run_status"] = run.status
    return out


@router.post("/runs/{run_id}/compliance/recompute")
def recompute(run_id: int, user: Annotated[Principal, Depends(require(Perm.RUN_SCAN))],
              session: SessionDep, audit: AuditDep) -> dict:
    """Пересчитать соответствие прогона по сохранённым фактам и находкам."""
    run = _run(session, run_id)
    if run.status not in FINISHED:
        raise HTTPException(status.HTTP_409_CONFLICT, f"scan run is {run.status}")
    n = store.recompute(session, run_id)
    session.commit()
    audit.record(subject=user.subject, action="compliance_recompute",
                 target=f"scan_run:{run_id}", result="ok", details={"rows": n})
    return {"rows": n}
