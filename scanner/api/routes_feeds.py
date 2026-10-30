"""Справочники (БДУ, NVD, шаблоны Nuclei): статус, расписание автообновления, «обновить сейчас»."""
from __future__ import annotations

from datetime import UTC, datetime
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select

from scanner.api.deps import AuditDep, Principal, SessionDep, require
from scanner.api.rbac import Perm
from scanner.core.db import FeedSync
from scanner.core.schedule import ScheduleError, ScheduleSpec, next_occurrence
from scanner.feeds.scheduler import STALE_AFTER, FeedScheduler, spec_of

router = APIRouter(tags=["feeds"])


class FeedOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    source: str
    title: str = ""
    description: str = ""
    kind: str
    time_of_day: str
    weekdays: list[int]
    month_day: int | None
    timezone: str
    enabled: bool
    next_run_at: datetime | None
    last_run_at: datetime | None
    last_success_at: datetime | None
    last_result: str | None
    last_count: int | None
    message: str | None
    running: bool = False


class FeedScheduleIn(BaseModel):
    enabled: bool
    kind: Literal["daily", "weekly", "monthly"] = "daily"
    time_of_day: str = "03:00"
    weekdays: list[int] = Field(default_factory=list)
    month_day: int | None = None
    timezone: str | None = None


def _scheduler(request: Request) -> FeedScheduler:
    return request.app.state.feed_scheduler


def _out(sched: FeedScheduler, row: FeedSync) -> FeedOut:
    out = FeedOut.model_validate(row)
    src = sched.sources.get(row.source)
    if src is not None:
        out.title, out.description = src.title, src.description
    out.running = (row.running_since is not None and
                   datetime.now(UTC) - _aware(row.running_since) < STALE_AFTER)
    return out


def _aware(dt: datetime) -> datetime:
    return dt if dt.tzinfo else dt.replace(tzinfo=UTC)


def _get(session, sched: FeedScheduler, source: str) -> FeedSync:
    row = session.get(FeedSync, source)
    if row is None or source not in sched.sources:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "feed source not found")
    return row


@router.get("/feeds", response_model=list[FeedOut])
def list_feeds(_: Annotated[Principal, Depends(require(Perm.VIEW_ENGAGEMENTS))],
               session: SessionDep,
               sched: Annotated[FeedScheduler, Depends(_scheduler)]) -> list[FeedOut]:
    rows = session.scalars(select(FeedSync).order_by(FeedSync.source))
    return [_out(sched, r) for r in rows if r.source in sched.sources]


@router.put("/feeds/{source}", response_model=FeedOut)
def update_feed(source: str, body: FeedScheduleIn, request: Request,
                user: Annotated[Principal, Depends(require(Perm.MANAGE_ENGAGEMENTS))],
                session: SessionDep, audit: AuditDep,
                sched: Annotated[FeedScheduler, Depends(_scheduler)]) -> FeedOut:
    row = _get(session, sched, source)
    spec = ScheduleSpec(kind=body.kind, timezone=body.timezone or row.timezone,
                        time_of_day=body.time_of_day,
                        weekdays=sorted(set(body.weekdays)) if body.kind == "weekly" else [],
                        month_day=body.month_day if body.kind == "monthly" else None)
    try:
        spec.validate()
    except ScheduleError as e:
        raise HTTPException(422, str(e)) from e
    row.kind, row.timezone, row.time_of_day = spec.kind, spec.timezone, spec.time_of_day
    row.weekdays, row.month_day, row.enabled = spec.weekdays, spec.month_day, body.enabled
    row.next_run_at = next_occurrence(spec_of(row), datetime.now(UTC)) if body.enabled else None
    session.flush()
    audit.record(subject=user.subject, action="feed_schedule_update",
                 target=f"feed:{source}", result="ok",
                 details={"enabled": row.enabled, "kind": row.kind,
                          "time_of_day": row.time_of_day, "weekdays": row.weekdays,
                          "month_day": row.month_day, "timezone": row.timezone})
    return _out(sched, row)


@router.post("/feeds/{source}/run", response_model=FeedOut, status_code=202)
def run_feed_now(source: str,
                 user: Annotated[Principal, Depends(require(Perm.MANAGE_ENGAGEMENTS))],
                 session: SessionDep,
                 sched: Annotated[FeedScheduler, Depends(_scheduler)]) -> FeedOut:
    """Запустить обновление сейчас (в фоне); расписание не меняется."""
    _get(session, sched, source)
    session.commit()   # отпустить транзакцию запроса до работы исполнителя
    if not sched.submit_manual(source, user.subject):
        raise HTTPException(status.HTTP_409_CONFLICT, "этот справочник уже обновляется")
    session.expire_all()
    return _out(sched, _get(session, sched, source))
