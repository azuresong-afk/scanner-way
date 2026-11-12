"""Восстановление после сбоя: отметка «жив» и сторож осиротевших прогонов.

Процесс, который ведёт прогоны (pending в своей
очереди и running), раз в `heartbeat_seconds` обновляет у них `heartbeat_at`.
Сторож (`RunService.start()` — в API) при старте и затем периодически ищет
осиротевшие прогоны: их процесс умер (тот же хост, pid не существует или это
прошлый запуск контейнера) или отметка не обновлялась дольше `stale_seconds`.
Осиротевший running становится `interrupted` с понятной причиной (повторить —
`RunService.retry`), осиротевший pending ставится в очередь заново: сеть он
ещё не трогал. Повторное исполнение не плодит дублей (см. runner.persist).
"""
from __future__ import annotations

import logging
import os
import socket
import threading
import uuid
from collections.abc import Callable
from concurrent.futures import Executor
from datetime import UTC, datetime, timedelta

from sqlalchemy import func, select, update
from sqlalchemy.orm import Session, sessionmaker

from scanner.core import repository as repo
from scanner.core import run_events as ev
from scanner.core.audit import AuditSink
from scanner.core.db import FindingRow, ScanRun, session_scope

# Имя логгера — прежнее (до разделения модуля): настройки логирования и
# фильтры по нему продолжают работать.
log = logging.getLogger("scanner.core.orchestrator")

# Отметка «жив» и порог, после которого прогон без неё считается осиротевшим.
HEARTBEAT_SECONDS = 30
STALE_SECONDS = 180

MSG_INTERRUPTED = ("Прогон прерван: служба сканера была остановлена или "
                   "перезапущена во время выполнения. Результаты прогона не "
                   "сохранены — запустите его повторно (кнопка «Повторить»).")
MSG_INTERRUPTED_SAVED = ("Прогон прерван после сохранения находок: служба сканера "
                         "остановилась до его штатного завершения (расчёт "
                         "соответствия мог не выполниться). Находки доступны; "
                         "для полного результата повторите прогон.")
MSG_NODE_LOST = ("Прогон прерван: узел-сканер перестал выходить на связь во время "
                 "выполнения (выключен, перезапущен или потерял связь с центром). "
                 "Результаты не получены — запустите прогон повторно (кнопка «Повторить»).")
MSG_NO_TARGETS = ("Ни одна цель не прошла allowlist договора на момент запуска "
                  "(allowlist мог измениться после постановки прогона).")
MSG_NO_TARGETS_NODE = ("Ни одна цель не прошла allowlist: договора и сетей узла в центре "
                       "либо локальный allowlist узла (SCANNER_NODE_ALLOWLIST). Какие "
                       "цели и где отклонены — в журнале аудита, действие deny.")


def make_worker_id() -> str:
    """Кто ведёт прогон: хост, pid и метка запуска процесса."""
    return f"{socket.gethostname()}:{os.getpid()}:{uuid.uuid4().hex[:12]}"


def _aware(ts: datetime | None) -> datetime | None:
    if ts is None:
        return None
    return ts if ts.tzinfo is not None else ts.replace(tzinfo=UTC)


def owner_is_dead(worker_id: str | None, me: str) -> bool:
    """Процесс worker_id точно не существует (проверяемо только на своём хосте).

    В контейнере API после перезапуска снова pid 1, поэтому кроме pid
    сравнивается метка запуска: тот же pid с другой меткой — прошлый процесс.
    Прогоны с другого хоста (или без worker_id) оцениваются только по
    давности отметки «жив»."""
    if not worker_id:
        return False
    try:
        host, pid_s, boot = worker_id.rsplit(":", 2)
        pid = int(pid_s)
    except ValueError:
        return False
    my_host, my_pid, my_boot = me.rsplit(":", 2)
    if host != my_host:
        return False
    if pid == int(my_pid):
        return boot != my_boot
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return True
    except OSError:          # процесс есть, но чужой (EPERM)
        return False
    return False


class RecoveryMixin:
    """Часть RunService: очередь своего процесса, отметка «жив» и сторож."""

    sessions: sessionmaker[Session]
    audit: AuditSink
    executor: Executor
    worker_id: str
    heartbeat_seconds: float
    stale_seconds: float
    _owned: set[int]
    _lock: threading.Lock
    _hb_thread: threading.Thread | None
    _hb_stop: threading.Event
    _sweep: bool
    execute: Callable[[int, list[str]], str]
    _notify: Callable[[int], None]

    # --- отметка «жив» и сторож осиротевших прогонов -----------------------
    def _enqueue(self, run_id: int, targets: list[str]) -> None:
        with self._lock:
            self._owned.add(run_id)
        self._ensure_heartbeat()
        self.executor.submit(self._run_owned, run_id, targets)

    def _run_owned(self, run_id: int, targets: list[str]) -> str:
        try:
            return self.execute(run_id, targets)
        finally:
            with self._lock:
                self._owned.discard(run_id)

    def _ensure_heartbeat(self) -> None:
        if self.heartbeat_seconds <= 0:
            return
        with self._lock:
            if self._hb_thread is not None and self._hb_thread.is_alive():
                return
            self._hb_stop.clear()
            self._hb_thread = threading.Thread(target=self._heartbeat_loop,
                                               name="scan-run-heartbeat", daemon=True)
            self._hb_thread.start()

    def _heartbeat_loop(self) -> None:
        while not self._hb_stop.wait(self.heartbeat_seconds):
            self.heartbeat()
            if self._sweep:
                try:
                    self.recover_orphans()
                except Exception:   # БД недоступна — попробуем на следующем тике
                    log.exception("orphaned scan runs check failed")

    def heartbeat(self) -> None:
        """Обновить отметку «жив» у прогонов этого процесса."""
        with self._lock:
            owned = list(self._owned)
        if not owned:
            return
        try:
            with session_scope(self.sessions) as s:
                repo.touch_scan_runs(s, owned, self.worker_id)
        except Exception:
            log.exception("scan run heartbeat failed")

    def start(self) -> None:
        """Старт в API: разобрать прогоны, оставшиеся от прошлого процесса, и
        включить периодический сторож (вместе с отметкой «жив»)."""
        try:
            self.recover_orphans()
        except Exception:
            log.exception("orphaned scan runs check failed at startup")
        self._sweep = True
        self._ensure_heartbeat()

    def stop(self) -> None:
        self._sweep = False
        self._hb_stop.set()

    def recover_orphans(self, now: datetime | None = None) -> dict[str, list[int]]:
        """Осиротевшие running -> interrupted, осиротевшие pending -> в очередь.

        Каждое изменение — условным UPDATE по наблюдённым статусу и отметке:
        если владелец «ожил» и успел обновить прогон, сторож его не тронет."""
        now = now or datetime.now(UTC)
        self._expire_offline(now)
        stale_before = now - timedelta(seconds=self.stale_seconds)
        interrupted: list[int] = []
        requeued: list[tuple[int, list[str]]] = []
        with self._lock:
            owned = set(self._owned)
        with session_scope(self.sessions) as s:
            offline_nodes = repo.offline_node_ids(s)
            for run in repo.active_scan_runs(s):
                if run.id in owned:
                    continue
                # прогон узла: pending ждёт, пока узел его заберёт; прогон
                # автономного узла едет на носителе — его снимает срок задания
                if run.node_id is not None and (run.status == "pending"
                                                or run.node_id in offline_nodes):
                    continue
                seen = _aware(run.heartbeat_at or run.started_at or run.created_at)
                dead = owner_is_dead(run.worker_id, self.worker_id)
                if not dead and seen is not None and seen >= stale_before:
                    continue
                cond = [ScanRun.id == run.id, ScanRun.status == run.status,
                        ScanRun.heartbeat_at.is_(None) if run.heartbeat_at is None
                        else ScanRun.heartbeat_at == run.heartbeat_at]
                if run.status == "running":
                    saved = s.scalar(select(func.count(FindingRow.id)).where(
                        FindingRow.scan_run_id == run.id)) or 0
                    msg = MSG_INTERRUPTED_SAVED if saved else MSG_INTERRUPTED
                    if run.node_id is not None:
                        msg = MSG_NODE_LOST
                    res = s.execute(update(ScanRun).where(*cond).values(
                        status="interrupted", finished_at=now, error_message=msg)
                        .execution_options(synchronize_session=False))
                    if res.rowcount == 1:
                        interrupted.append(run.id)
                else:
                    res = s.execute(update(ScanRun).where(*cond).values(
                        worker_id=self.worker_id, heartbeat_at=now)
                        .execution_options(synchronize_session=False))
                    if res.rowcount == 1:
                        requeued.append((run.id, list(run.targets or [])))
        for run_id in interrupted:
            self.audit.record(subject="scanner", action="scan_finish",
                              target=f"scan_run:{run_id}", result="interrupted",
                              details={"reason": "executor_lost",
                                       "worker_id": self.worker_id})
            ev.safe_add(self.sessions, run_id, [ev.run_finish(
                "interrupted", message="исполнитель прогона перезапущен")])
            self._notify(run_id)
        for run_id, targets in requeued:
            self.audit.record(subject="scanner", action="scan_requeue",
                              target=f"scan_run:{run_id}", result="ok",
                              details={"reason": "executor_lost"})
            self._enqueue(run_id, targets)
        return {"interrupted": interrupted, "requeued": [r for r, _ in requeued]}

    def _expire_offline(self, now: datetime) -> None:
        """Автономные задания без результата дольше срока: прогон -> ошибка."""
        try:
            from scanner.nodes.offline_center import expire_jobs
            expired = expire_jobs(self.sessions, self.audit, now=now)
        except Exception:   # вторично к сторожу; повторится на следующем тике
            log.exception("offline jobs expiry check failed")
            return
        for run_id in expired:
            self._notify(run_id)
