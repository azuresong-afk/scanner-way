"""Планировщик автообновления справочников (БДУ, NVD, шаблоны Nuclei).

Живёт в процессе API фоновым потоком, как `scanner.api.scheduler` для прогонов:
раз в tick_seconds забирает источники (feed_sync), у которых наступил
next_run_at. Срабатывание «захватывается» условным UPDATE по старому
next_run_at, поэтому при нескольких процессах API один источник обновляется
один раз. Пока обновление идёт (`running_since`), второе того же источника не
стартует — ни по расписанию, ни по кнопке «Обновить сейчас». Метка старше
STALE_AFTER считается осиротевшей (процесс упал) и не блокирует.

Долгие загрузки идут в отдельных потоках пула и не блокируют API. Пропущенные за
время простоя срабатывания не догоняются: следующее — по расписанию от
текущего момента. Расчёт времени — scanner.core.schedule (общий с прогонами).
"""
from __future__ import annotations

import logging
import threading
from collections.abc import Mapping
from concurrent.futures import Executor, ThreadPoolExecutor
from datetime import UTC, datetime, timedelta

from sqlalchemy import or_, select, update
from sqlalchemy.orm import Session, sessionmaker

from scanner.core.audit import AuditSink
from scanner.core.db import FeedSync, session_scope
from scanner.core.schedule import ScheduleSpec, next_occurrence
from scanner.feeds.sources import SOURCES, FeedContext, FeedError, FeedSource

log = logging.getLogger(__name__)

STALE_AFTER = timedelta(hours=12)
MESSAGE_LIMIT = 1000


def spec_of(row: FeedSync) -> ScheduleSpec:
    return ScheduleSpec(kind=row.kind, timezone=row.timezone, time_of_day=row.time_of_day,
                        weekdays=list(row.weekdays or []), month_day=row.month_day)


def seed_feed_sync(session_factory: sessionmaker[Session], *, timezone: str = "UTC",
                   sources: Mapping[str, FeedSource] | None = None) -> None:
    """Заводит строки для источников, которых ещё нет. Расписание по умолчанию
    выключено: обращаться в интернет без ведома оператора сканер не должен."""
    with session_scope(session_factory) as s:
        have = set(s.scalars(select(FeedSync.source)))
        for src in (sources or SOURCES).values():
            if src.id not in have:
                s.add(FeedSync(source=src.id, kind=src.kind, time_of_day=src.time_of_day,
                               weekdays=list(src.weekdays), timezone=timezone,
                               enabled=False))


class FeedScheduler:
    def __init__(self, session_factory: sessionmaker[Session], audit: AuditSink, *,
                 sources: Mapping[str, FeedSource] | None = None,
                 executor: Executor | None = None, tick_seconds: float = 60.0):
        self.sessions = session_factory
        self.audit = audit
        self.sources = dict(sources if sources is not None else SOURCES)
        self.tick_seconds = tick_seconds
        self._own_executor = executor is None
        self.executor: Executor = executor or ThreadPoolExecutor(
            max_workers=2, thread_name_prefix="feed-sync")
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    # --- фоновый поток -----------------------------------------------------
    def start(self) -> None:
        if self.tick_seconds <= 0 or self._thread is not None:
            return
        self._thread = threading.Thread(target=self._loop, name="feed-scheduler",
                                        daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=5)
            self._thread = None
        if self._own_executor:
            self.executor.shutdown(wait=False, cancel_futures=True)

    def _loop(self) -> None:
        while not self._stop.wait(self.tick_seconds):
            try:
                self.tick()
            except Exception:  # БД недоступна и т.п. — попробуем на следующем тике
                log.exception("feed scheduler tick failed")

    # --- срабатывания ------------------------------------------------------
    def tick(self, now: datetime | None = None) -> list[str]:
        """Запускает источники, у которых наступило время. Возвращает их id."""
        now = (now or datetime.now(UTC)).astimezone(UTC)
        with session_scope(self.sessions) as s:
            due = list(s.scalars(select(FeedSync.source).where(
                FeedSync.enabled.is_(True), FeedSync.next_run_at.is_not(None),
                FeedSync.next_run_at <= now).order_by(FeedSync.next_run_at)))
        started = []
        for source in due:
            if self._claim_scheduled(source, now):
                self.executor.submit(self.execute, source, now, "feeds:scheduler")
                started.append(source)
        return started

    def _not_running(self, now: datetime):
        return or_(FeedSync.running_since.is_(None),
                   FeedSync.running_since < now - STALE_AFTER)

    def _claim_scheduled(self, source: str, now: datetime) -> bool:
        with session_scope(self.sessions) as s:
            row = s.get(FeedSync, source)
            if row is None or not row.enabled or row.next_run_at is None \
                    or source not in self.sources:
                return False
            nxt = next_occurrence(spec_of(row), now)
            return s.execute(
                update(FeedSync)
                .where(FeedSync.source == source,
                       FeedSync.next_run_at == row.next_run_at, self._not_running(now))
                .values(next_run_at=nxt, running_since=now)
                .execution_options(synchronize_session=False)).rowcount == 1

    def submit_manual(self, source: str, actor: str) -> bool:
        """«Обновить сейчас»: False — этот источник уже обновляется."""
        now = datetime.now(UTC)
        if source not in self.sources:
            raise KeyError(source)
        with session_scope(self.sessions) as s:
            claimed = s.execute(
                update(FeedSync).where(FeedSync.source == source, self._not_running(now))
                .values(running_since=now)
                .execution_options(synchronize_session=False)).rowcount == 1
        if claimed:
            self.executor.submit(self.execute, source, now, actor, True)
        return claimed

    # --- исполнение --------------------------------------------------------
    def execute(self, source: str, now: datetime, actor: str, manual: bool = False) -> str:
        """Загружает один источник (захват уже сделан) и пишет итог. Возвращает
        ok | unchanged | error."""
        loader = self.sources[source].loader
        with session_scope(self.sessions) as s:
            row = s.get(FeedSync, source)
            ctx = FeedContext(engine=self.sessions.kw["bind"], audit=self.audit, now=now,
                              last_success_at=row.last_success_at,
                              fingerprint=row.fingerprint, actor=actor)
        error = None
        try:
            result = loader(ctx)
            outcome = "unchanged" if result.unchanged else "ok"
            message = result.message
        except FeedError as e:
            outcome, error, message, result = "error", str(e), str(e), None
        except Exception as e:
            log.exception("feed %s failed", source)
            error = f"{type(e).__name__}: {e}"
            outcome, message, result = "error", error, None

        values: dict[str, object] = {"last_run_at": now, "last_result": outcome,
                                     "message": message[:MESSAGE_LIMIT],
                                     "running_since": None}
        if result is not None:
            values["last_success_at"] = now
            if result.count is not None:
                values["last_count"] = result.count
            if result.fingerprint is not None:
                values["fingerprint"] = result.fingerprint
        with session_scope(self.sessions) as s:
            s.execute(update(FeedSync).where(FeedSync.source == source).values(**values)
                      .execution_options(synchronize_session=False))
        self.audit.record(subject=actor, action="feed_sync", target=f"feed:{source}",
                          result=outcome, details={
                              "records": result.count if result else None,
                              "message": message[:300], "error": error,
                              "manual": manual or None})
        return outcome


