"""Прогоны по расписанию: создание, изменение, включение/выключение, запуск сейчас."""
from __future__ import annotations

from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from scanner.api.deps import AuditDep, Principal, SessionDep, require
from scanner.api.rbac import Perm
from scanner.api.routes_engagements import get_engagement
from scanner.api.routes_runs import (
    _runs,
    check_run_options,
    check_targets,
    with_engine,
)
from scanner.api.scheduler import Scheduler, last_run_id, spec_of
from scanner.api.schemas import ScheduleIn, ScheduleOut, ScheduleToggle
from scanner.core.db import ScanSchedule
from scanner.core.naming import clean_name
from scanner.core.orchestrator import RunService, order_modules
from scanner.core.schedule import ScheduleError, ScheduleSpec, next_occurrence

router = APIRouter(tags=["schedules"])


def _scheduler(request: Request) -> Scheduler:
    return request.app.state.scheduler


def _get(session: Session, schedule_id: int) -> ScanSchedule:
    row = session.get(ScanSchedule, schedule_id)
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "schedule not found")
    return row


def _out(session: Session, row: ScanSchedule) -> ScheduleOut:
    out = ScheduleOut.model_validate(row)
    out.last_run_id = last_run_id(session, row.id)
    return out


def _now() -> datetime:
    return datetime.now(UTC)


def _apply(row: ScanSchedule, body: ScheduleIn, *, request: Request, user: Principal,
           audit, runs: RunService) -> None:
    """Проверяет тело как запуск прогона + расписание и переносит в row."""
    modules = order_modules(with_engine(body.modules, body.vuln_engine))
    check_run_options(row.engagement_id, modules=modules, rate_profile=body.rate_profile,
                      credential_ids=body.credential_ids, user=user, request=request,
                      audit=audit, runs=runs)
    check_targets(row.engagement_id, body.targets, user=user, audit=audit, runs=runs)
    tz = body.timezone or request.app.state.default_timezone
    spec = ScheduleSpec(kind=body.kind, timezone=tz,
                        time_of_day=body.time_of_day if body.kind != "once" else None,
                        weekdays=sorted(set(body.weekdays)) if body.kind == "weekly" else [],
                        month_day=body.month_day if body.kind == "monthly" else None,
                        run_at=body.run_at if body.kind == "once" else None)
    try:
        spec.validate()
    except ScheduleError as e:
        raise HTTPException(422, str(e)) from e
    nxt = next_occurrence(spec, _now()) if body.enabled else None
    if body.enabled and nxt is None:
        raise HTTPException(422, "время разового запуска уже прошло")
    row.name = clean_name(body.name)
    row.targets = [t.strip() for t in body.targets if t.strip()]
    row.modules = modules
    row.rate_profile = body.rate_profile
    row.credential_ids = list(dict.fromkeys(body.credential_ids))
    row.kind, row.timezone = spec.kind, spec.timezone
    row.time_of_day, row.weekdays = spec.time_of_day, spec.weekdays
    row.month_day, row.run_at = spec.month_day, spec.run_at
    row.enabled, row.next_run_at = body.enabled, nxt
    # расписание исполняется с правами того, кто его последним сохранил
    row.owner_id = user.id


def _details(row: ScanSchedule) -> dict:
    return {"engagement_id": row.engagement_id, "name": row.name, "kind": row.kind,
            "time_of_day": row.time_of_day, "weekdays": row.weekdays,
            "month_day": row.month_day,
            "run_at": row.run_at.isoformat() if row.run_at else None,
            "timezone": row.timezone, "modules": row.modules,
            "rate_profile": row.rate_profile, "credential_ids": row.credential_ids,
            "targets": row.targets[:100], "enabled": row.enabled}


@router.get("/engagements/{engagement_id}/schedules", response_model=list[ScheduleOut])
def list_schedules(engagement_id: int,
                   _: Annotated[Principal, Depends(require(Perm.VIEW_REPORT))],
                   session: SessionDep) -> list[ScheduleOut]:
    get_engagement(session, engagement_id)
    rows = session.scalars(select(ScanSchedule)
                           .where(ScanSchedule.engagement_id == engagement_id)
                           .order_by(ScanSchedule.id))
    return [_out(session, r) for r in rows]


@router.post("/engagements/{engagement_id}/schedules", response_model=ScheduleOut,
             status_code=201)
def create_schedule(engagement_id: int, body: ScheduleIn, request: Request,
                    user: Annotated[Principal, Depends(require(Perm.RUN_SCAN))],
                    session: SessionDep, audit: AuditDep,
                    runs: Annotated[RunService, Depends(_runs)]) -> ScheduleOut:
    get_engagement(session, engagement_id)
    row = ScanSchedule(engagement_id=engagement_id)
    _apply(row, body, request=request, user=user, audit=audit, runs=runs)
    session.add(row)
    session.flush()
    audit.record(subject=user.subject, action="schedule_create",
                 target=f"schedule:{row.id}", result="ok", details=_details(row))
    return _out(session, row)


@router.get("/schedules/{schedule_id}", response_model=ScheduleOut)
def read_schedule(schedule_id: int,
                  _: Annotated[Principal, Depends(require(Perm.VIEW_REPORT))],
                  session: SessionDep) -> ScheduleOut:
    return _out(session, _get(session, schedule_id))


@router.put("/schedules/{schedule_id}", response_model=ScheduleOut)
def update_schedule(schedule_id: int, body: ScheduleIn, request: Request,
                    user: Annotated[Principal, Depends(require(Perm.RUN_SCAN))],
                    session: SessionDep, audit: AuditDep,
                    runs: Annotated[RunService, Depends(_runs)]) -> ScheduleOut:
    row = _get(session, schedule_id)
    _apply(row, body, request=request, user=user, audit=audit, runs=runs)
    session.flush()
    audit.record(subject=user.subject, action="schedule_update",
                 target=f"schedule:{row.id}", result="ok", details=_details(row))
    return _out(session, row)


@router.patch("/schedules/{schedule_id}", response_model=ScheduleOut)
def toggle_schedule(schedule_id: int, body: ScheduleToggle, request: Request,
                    user: Annotated[Principal, Depends(require(Perm.RUN_SCAN))],
                    session: SessionDep, audit: AuditDep,
                    runs: Annotated[RunService, Depends(_runs)]) -> ScheduleOut:
    """Включить/выключить. Включение перепроверяет права и пересчитывает график."""
    row = _get(session, schedule_id)
    if body.enabled:
        check_run_options(row.engagement_id, modules=list(row.modules),
                          rate_profile=row.rate_profile,
                          credential_ids=list(row.credential_ids or []), user=user,
                          request=request, audit=audit, runs=runs)
        nxt = next_occurrence(spec_of(row), _now())
        if nxt is None:
            raise HTTPException(422, "время разового запуска уже прошло — "
                                     "измените дату в расписании")
        row.enabled, row.next_run_at, row.owner_id = True, nxt, user.id
    else:
        row.enabled, row.next_run_at = False, None
    session.flush()
    audit.record(subject=user.subject, action="schedule_update",
                 target=f"schedule:{row.id}", result="ok",
                 details={"enabled": row.enabled})
    return _out(session, row)


@router.delete("/schedules/{schedule_id}", status_code=204)
def delete_schedule(schedule_id: int,
                    user: Annotated[Principal, Depends(require(Perm.RUN_SCAN))],
                    session: SessionDep, audit: AuditDep) -> Response:
    row = _get(session, schedule_id)
    details = _details(row)
    session.delete(row)   # прогоны остаются, schedule_id у них обнуляется
    session.flush()
    audit.record(subject=user.subject, action="schedule_delete",
                 target=f"schedule:{schedule_id}", result="ok", details=details)
    return Response(status_code=204)


@router.post("/schedules/{schedule_id}/run", response_model=ScheduleOut)
def run_schedule_now(schedule_id: int, request: Request,
                     user: Annotated[Principal, Depends(require(Perm.RUN_SCAN))],
                     session: SessionDep, audit: AuditDep,
                     runs: Annotated[RunService, Depends(_runs)],
                     scheduler: Annotated[Scheduler, Depends(_scheduler)]) -> ScheduleOut:
    """Поставить прогон по расписанию прямо сейчас, не меняя график."""
    row = _get(session, schedule_id)
    check_run_options(row.engagement_id, modules=list(row.modules),
                      rate_profile=row.rate_profile,
                      credential_ids=list(row.credential_ids or []), user=user,
                      request=request, audit=audit, runs=runs)
    check_targets(row.engagement_id, list(row.targets), user=user, audit=audit, runs=runs)
    session.commit()   # отпустить транзакцию запроса до работы исполнителя
    result = scheduler.fire(schedule_id, force=True, as_user=user)
    if result == "skipped_overlap":
        raise HTTPException(status.HTTP_409_CONFLICT,
                            "предыдущий прогон этого расписания ещё не завершён")
    session.expire_all()
    row = _get(session, schedule_id)
    if result != "queued":
        raise HTTPException(422, row.last_result or "не удалось поставить прогон")
    return _out(session, row)
