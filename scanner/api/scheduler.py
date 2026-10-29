"""Планировщик: ставит в очередь прогоны по расписаниям (scan_schedules).

Живёт в процессе API фоновым потоком и раз в tick_seconds забирает
расписания, у которых наступил next_run_at. Срабатывание «захватывается»
условным UPDATE по старому значению next_run_at, поэтому даже при нескольких
процессах API одно срабатывание ставит не больше одного прогона.

При каждом срабатывании заново проверяется, что владелец расписания активен и
у него всё ещё есть права на такой прогон (run_scan + права модулей); allowlist
договора, как и для ручного прогона, перечитывается при исполнении. Если
предыдущий прогон этого расписания ещё идёт, срабатывание пропускается.
Пропущенные за время простоя срабатывания не догоняются: после запуска API
прогон ставится один раз, а следующий — по расписанию от текущего момента.
"""
from __future__ import annotations

import logging
import threading
from datetime import UTC, datetime

from sqlalchemy import select, update
from sqlalchemy.orm import Session, sessionmaker

from scanner.api.deps import Principal
from scanner.api.rbac import Perm, user_permissions
from scanner.core.audit import AuditSink
from scanner.core.db import ScanRun, ScanSchedule, User, session_scope
from scanner.core.orchestrator import RunService
from scanner.core.schedule import ScheduleSpec, next_occurrence

log = logging.getLogger(__name__)

ACTIVE = ("pending", "running")


def spec_of(row: ScanSchedule) -> ScheduleSpec:
    return ScheduleSpec(kind=row.kind, timezone=row.timezone, time_of_day=row.time_of_day,
                        weekdays=list(row.weekdays or []), month_day=row.month_day,
                        run_at=row.run_at)


def last_run_id(session: Session, schedule_id: int) -> int | None:
    return session.scalar(select(ScanRun.id).where(ScanRun.schedule_id == schedule_id)
                          .order_by(ScanRun.id.desc()).limit(1))


def owner_principal(session: Session, owner_id: int | None) -> Principal | None:
    user = session.get(User, owner_id) if owner_id is not None else None
    if user is None or not user.is_active:
        return None
    return Principal(user.id, user.username, frozenset(user_permissions(session, user.id)))


class Scheduler:
    def __init__(self, session_factory: sessionmaker[Session], runs: RunService,
                 audit: AuditSink, *, tick_seconds: float = 30.0):
        self.sessions = session_factory
        self.runs = runs
        self.audit = audit
        self.tick_seconds = tick_seconds
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    # --- фоновый поток -----------------------------------------------------
    def start(self) -> None:
        if self.tick_seconds <= 0 or self._thread is not None:
            return
        self._thread = threading.Thread(target=self._loop, name="scan-scheduler",
                                        daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=5)
            self._thread = None

    def _loop(self) -> None:
        while not self._stop.wait(self.tick_seconds):
            try:
                self.tick()
            except Exception:  # БД недоступна и т.п. — попробуем на следующем тике
                log.exception("scheduler tick failed")

    # --- срабатывания ------------------------------------------------------
    def tick(self, now: datetime | None = None) -> dict[int, str]:
        """Ставит прогоны по наступившим расписаниям. Возвращает {id: результат}."""
        now = (now or datetime.now(UTC)).astimezone(UTC)
        with session_scope(self.sessions) as s:
            due = list(s.scalars(select(ScanSchedule.id).where(
                ScanSchedule.enabled.is_(True), ScanSchedule.next_run_at.is_not(None),
                ScanSchedule.next_run_at <= now).order_by(ScanSchedule.next_run_at)))
        results = {}
        for sid in due:
            result = self.fire(sid, now)
            if result is not None:
                results[sid] = result
        return results

    def _claim(self, schedule_id: int, now: datetime) -> ScanSchedule | None:
        """Сдвигает next_run_at на следующее срабатывание; None — уже забрал другой."""
        with session_scope(self.sessions) as s:
            row = s.get(ScanSchedule, schedule_id)
            if row is None or not row.enabled or row.next_run_at is None:
                return None
            nxt = next_occurrence(spec_of(row), now)
            claimed = s.execute(
                update(ScanSchedule)
                .where(ScanSchedule.id == schedule_id,
                       ScanSchedule.next_run_at == row.next_run_at)
                .values(next_run_at=nxt, last_run_at=now,
                        enabled=nxt is not None)).rowcount
            if claimed != 1:
                return None
            s.refresh(row)
            s.expunge(row)
            return row

    def fire(self, schedule_id: int, now: datetime | None = None, *,
             force: bool = False, as_user: Principal | None = None) -> str | None:
        """Одно срабатывание. force — «запустить сейчас» из API (без сдвига графика);
        as_user — от чьего имени (по умолчанию владелец расписания)."""
        now = (now or datetime.now(UTC)).astimezone(UTC)
        if force:
            with session_scope(self.sessions) as s:
                row = s.get(ScanSchedule, schedule_id)
                if row is None:
                    return None
                s.expunge(row)
        else:
            row = self._claim(schedule_id, now)
            if row is None:
                return None
        subject = as_user.subject if as_user else f"schedule:{schedule_id}"

        with session_scope(self.sessions) as s:
            owner = as_user or owner_principal(s, row.owner_id)
            prev = last_run_id(s, schedule_id)
            prev_status = s.get(ScanRun, prev).status if prev is not None else None
        result, run_id, error = "queued", None, None
        if owner is None or not owner.has(Perm.RUN_SCAN):
            result = "skipped_no_rights"
        else:
            from scanner.api.routes_runs import missing_permissions
            if missing_permissions(owner, row.modules, row.credential_ids):
                result = "skipped_no_rights"
        if result == "queued" and prev_status in ACTIVE:
            result = "skipped_overlap"
        if result == "queued":
            try:
                run_id = self.runs.submit(
                    engagement_id=row.engagement_id, modules=list(row.modules),
                    rate_profile=row.rate_profile, requested_targets=list(row.targets),
                    actor=subject, started_by=owner.id,
                    credential_ids=list(row.credential_ids or []), name=row.name,
                    schedule_id=schedule_id)
            except Exception as e:  # noqa: BLE001 — учётку удалили, модуль пропал и т.п.
                result, error = "error", f"{type(e).__name__}: {e}"[:300]

        with session_scope(self.sessions) as s:
            values: dict[str, object] = {
                "last_result": result if error is None else f"error: {error}"}
            if force:
                values["last_run_at"] = now
            if result == "skipped_no_rights" and as_user is None:
                # без прав владельца расписание бесполезно — выключаем
                values.update(enabled=False, next_run_at=None)
            s.execute(update(ScanSchedule).where(ScanSchedule.id == schedule_id)
                      .values(**values))
        self.audit.record(subject=subject, action="schedule_fire",
                          target=f"schedule:{schedule_id}",
                          result="ok" if result == "queued" else result,
                          details={"engagement_id": row.engagement_id,
                                   "scan_run_id": run_id, "owner_id": row.owner_id,
                                   "previous_run_status": prev_status, "error": error,
                                   "manual": force or None})
        return result
