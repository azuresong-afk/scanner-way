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
    # Прогресс текущей загрузки: этап, загружено/всего, %, скорость, ETA.
    progress: dict | None = None
    # Во время новой попытки message — итог ПРОШЛОЙ попытки, не текущая ошибка.
    message_is_previous: bool = False
    last_error_at: datetime | None = None
    records: int | None = None


class ReleaseIn(BaseModel):
    family: str = Field(min_length=2, max_length=32, pattern=r"^[a-z]+$")
    release: str = Field(min_length=1, max_length=32, pattern=r"^[A-Za-z0-9._-]+$")


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
    from scanner.feeds.readiness import progress_view
    out = FeedOut.model_validate(row)
    src = sched.sources.get(row.source)
    if src is not None:
        out.title, out.description = src.title, src.description
    out.running = (row.running_since is not None and
                   datetime.now(UTC) - _aware(row.running_since) < STALE_AFTER)
    out.progress = progress_view(row) if out.running else None
    out.message_is_previous = out.running
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


@router.get("/feeds/readiness")
def feeds_readiness(_: Annotated[Principal, Depends(require(Perm.VIEW_ENGAGEMENTS))],
                    session: SessionDep,
                    sched: Annotated[FeedScheduler, Depends(_scheduler)]) -> dict:
    """Мастер первоначальной настройки: готовность каждого источника (есть ли
    данные, идёт ли загрузка, что сделать) и выпуски ОС хостов без бюллетеней."""
    from scanner.feeds.readiness import readiness
    return readiness(session, sched.sources)


@router.post("/feeds/advisories/releases", response_model=FeedOut, status_code=202)
def load_release(body: ReleaseIn,
                 user: Annotated[Principal, Depends(require(Perm.MANAGE_ENGAGEMENTS))],
                 session: SessionDep, audit: AuditDep,
                 sched: Annotated[FeedScheduler, Depends(_scheduler)]) -> FeedOut:
    """Загрузить бюллетени одного выпуска ОС одним действием (например
    debian:trixie для хостов Debian 13) — согласие оператора на обращение к
    источнику вендора. Идёт в фоне, как «Обновить сейчас» бюллетеней."""
    from scanner.feeds.advisories import FAMILIES
    from scanner.feeds.sources import FeedError, FeedResult
    if body.family not in FAMILIES:
        raise HTTPException(422, f"unknown family: {body.family}; available: "
                                 f"{', '.join(sorted(FAMILIES))}")
    _get(session, sched, "advisories")
    target = (body.family, body.release)

    def loader(ctx):
        from pathlib import Path

        from scanner.core.config import settings
        from scanner.feeds.advisories.store import SqlAdvisoryStore
        from scanner.feeds.advisories.sync import sync_releases
        ctx.progress(f"Бюллетени {body.family}:{body.release}", 0, 1)
        directory = Path(settings.advisory_dir) if settings.advisory_dir else None
        results, _ = sync_releases(SqlAdvisoryStore(ctx.engine), [target],
                                   directory=directory, urls=settings.advisory_urls())
        ok = [r for r in results if r.error is None]
        if not ok:
            raise FeedError("; ".join(f"{r.family}:{r.release} — ошибка: {r.error}"
                                      for r in results) or "нет данных")
        return FeedResult(count=sum(r.count for r in ok),
                          message="; ".join(f"{r.family}:{r.release} — {r.count}"
                                            for r in ok))

    session.commit()
    if not sched.submit_manual("advisories", user.subject, loader=loader):
        raise HTTPException(status.HTTP_409_CONFLICT,
                            "бюллетени уже загружаются — дождитесь окончания")
    audit.record(subject=user.subject, action="advisory_release_load",
                 target=f"{body.family}:{body.release}", result="queued")
    session.expire_all()
    return _out(sched, _get(session, sched, "advisories"))


MAX_BDU_UPLOAD = 128 * 1024 * 1024


@router.post("/feeds/bdu/upload", response_model=FeedOut, status_code=202)
async def upload_bdu(request: Request,
                     user: Annotated[Principal, Depends(require(Perm.MANAGE_ENGAGEMENTS))],
                     session: SessionDep, audit: AuditDep,
                     sched: Annotated[FeedScheduler, Depends(_scheduler)]) -> FeedOut:
    """Загрузить выгрузку БДУ (vullist.xlsx с bdu.fstec.ru) из браузера: файл
    сохраняется по BDU_FSTEC_FEED_PATH и сразу загружается в справочник.
    Тело запроса — сам файл (application/octet-stream)."""
    import os
    import tempfile
    from pathlib import Path

    from scanner.core.config import settings
    _get(session, sched, "bdu")
    if settings.bdu_fstec_feed_url.strip():
        raise HTTPException(409, "задан BDU_FSTEC_FEED_URL — выгрузка скачивается по "
                                 "адресу; уберите его, чтобы загружать файл вручную")
    dest = Path(settings.bdu_fstec_feed_path)
    dest.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".bdu-upload-", dir=dest.parent)
    size = 0
    try:
        with os.fdopen(fd, "wb") as fh:
            async for chunk in request.stream():
                size += len(chunk)
                if size > MAX_BDU_UPLOAD:
                    raise HTTPException(413, "файл больше 128 МБ")
                fh.write(chunk)
        with open(tmp, "rb") as fh:
            if fh.read(2) != b"PK":
                raise HTTPException(422, "это не файл .xlsx (ожидается vullist.xlsx с "
                                         "bdu.fstec.ru)")
        os.replace(tmp, dest)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)
    audit.record(subject=user.subject, action="bdu_upload", target="feed:bdu",
                 result="ok", details={"bytes": size, "path": str(dest)})
    session.commit()
    sched.submit_manual("bdu", user.subject)
    session.expire_all()
    return _out(sched, _get(session, sched, "bdu"))


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
