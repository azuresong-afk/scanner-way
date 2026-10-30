"""Диспетчер событий: маршрутизация по каналам, очередь доставки с повторами, журнал.

Поток: событие → для каждого включённого канала `route` (подписка + фильтры) →
строки `notification_log` (pending) → доставка в пуле потоков. Неудача → `retry` с
нарастающей паузой (1, 5, 15, 60 минут), после MAX_ATTEMPTS — `failed`. Фоновый
поток раз в tick_seconds подхватывает просроченные повторы (в том числе после
перезапуска API). Каждый исход пишется в журнал доставки и в аудит.

Доставка «захватывается» условным UPDATE (аренда на LEASE), поэтому несколько
процессов API не отправят одно уведомление дважды. Диспетчер никогда не бросает
исключения в вызывающий код: сбой уведомлений не должен влиять на прогон.
"""
from __future__ import annotations

import logging
import threading
from collections.abc import Mapping
from concurrent.futures import Executor, ThreadPoolExecutor
from dataclasses import replace
from datetime import UTC, datetime, timedelta

from sqlalchemy import select, update
from sqlalchemy.orm import Session, sessionmaker

from scanner.core.audit import AuditSink
from scanner.core.credentials import CredentialVault, VaultUnavailable
from scanner.core.db import IntegrationChannelRow, NotificationLogRow, session_scope
from scanner.integrations.base import Delivery, DeliveryError, Transports
from scanner.integrations.builder import build_run_event
from scanner.integrations.channels import get_channel
from scanner.integrations.events import (
    FEED_STALE,
    NEW_CRITICAL,
    TEST,
    Event,
    Filters,
    route,
)

log = logging.getLogger(__name__)

MAX_ATTEMPTS = 5
BACKOFF_SECONDS = (60, 300, 900, 3600)       # пауза после 1-й, 2-й, … неудачи
LEASE = timedelta(minutes=10)
FEED_DEDUP_WINDOW = timedelta(hours=24)       # одно «справочник не обновился» в сутки
ERROR_LIMIT = 300
SUBJECT = "scanner:notifier"


def scrub(text: str, secrets: Mapping[str, str] | None) -> str:
    """Убирает значения секретов из текста ошибки; обрезает длину."""
    for v in (secrets or {}).values():
        if v and len(v) >= 4:
            text = text.replace(v, "***")
    return " ".join(text.split())[:ERROR_LIMIT]


class Dispatcher:
    def __init__(self, session_factory: sessionmaker[Session], audit: AuditSink, *,
                 vault: CredentialVault | None = None, public_url: str = "",
                 transports: Transports | None = None, executor: Executor | None = None,
                 tick_seconds: float = 30.0):
        self.sessions = session_factory
        self.audit = audit
        self.vault = vault
        self.public_url = public_url
        self.tx = transports or Transports()
        self.tick_seconds = tick_seconds
        self._own_executor = executor is None
        self.executor: Executor = executor or ThreadPoolExecutor(
            max_workers=2, thread_name_prefix="notify")
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    # ---- фоновый поток: повторы ----
    def start(self) -> None:
        if self.tick_seconds <= 0 or self._thread is not None:
            return
        self._thread = threading.Thread(target=self._loop, name="notify-dispatcher",
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
            except Exception:
                log.exception("notification dispatcher tick failed")

    def tick(self, now: datetime | None = None) -> int:
        """Ставит на доставку записи, у которых наступило время (новые и повторы)."""
        now = now or datetime.now(UTC)
        with session_scope(self.sessions) as s:
            due = list(s.scalars(
                select(NotificationLogRow.id).where(
                    NotificationLogRow.status.in_(("pending", "retry")),
                    NotificationLogRow.next_attempt_at.is_not(None),
                    NotificationLogRow.next_attempt_at <= now)
                .order_by(NotificationLogRow.next_attempt_at).limit(100)))
        for log_id in due:
            self.executor.submit(self.deliver, log_id, now=now)
        return len(due)

    # ---- точки входа: события ----
    def notify_run_finished(self, scan_run_id: int) -> None:
        """Прогон завершён: run_finished и (для новых критичных) new_critical."""
        try:
            with session_scope(self.sessions) as s:
                base = build_run_event(s, scan_run_id, self.public_url)
            self.emit(base)
            self.emit(replace(base, kind=NEW_CRITICAL))
        except Exception:
            log.exception("notification for scan_run %s failed", scan_run_id)

    def notify_feed_stale(self, source: str, title: str, message: str) -> None:
        try:
            self.emit(Event(kind=FEED_STALE, title=title, message=message, source=source))
        except Exception:
            log.exception("feed_stale notification failed")

    def emit(self, event: Event) -> list[int]:
        """Раскладывает событие по каналам. Возвращает id созданных доставок."""
        now = datetime.now(UTC)
        created: list[int] = []
        with session_scope(self.sessions) as s:
            channels = list(s.scalars(select(IntegrationChannelRow).where(
                IntegrationChannelRow.enabled.is_(True)).order_by(IntegrationChannelRow.id)))
            for ch in channels:
                created += self._enqueue(s, ch, event, now)
        for log_id in created:
            self.executor.submit(self.deliver, log_id)
        return created

    def _enqueue(self, s: Session, ch: IntegrationChannelRow, event: Event,
                 now: datetime) -> list[int]:
        impl = get_channel(ch.type)
        routed = route(event, list(ch.events or []), Filters.from_dict(ch.filters))
        if routed is None or routed.kind not in impl.supported_events | {TEST}:
            return []
        out: list[int] = []
        for d in impl.deliveries(routed, ch.config or {}):
            d = _with_window(d, routed)
            if d.dedup_key and self._duplicate(s, ch.id, d, now):
                continue
            row = NotificationLogRow(
                channel_id=ch.id, event=routed.kind, status="pending", attempts=0,
                next_attempt_at=now, payload=d.event.to_payload(),
                engagement_id=routed.engagement_id, scan_run_id=routed.scan_run_id,
                dedup_key=d.dedup_key)
            s.add(row)
            s.flush()
            out.append(row.id)
        return out

    @staticmethod
    def _duplicate(s: Session, channel_id: int, d: Delivery, now: datetime) -> bool:
        q = select(NotificationLogRow.id).where(
            NotificationLogRow.channel_id == channel_id,
            NotificationLogRow.dedup_key == d.dedup_key,
            NotificationLogRow.status != "failed")
        if d.dedup_window is not None:
            q = q.where(NotificationLogRow.created_at >= now - d.dedup_window)
        return s.scalar(q.limit(1)) is not None

    # ---- доставка ----
    def deliver(self, log_id: int, *, single_attempt: bool = False,
                now: datetime | None = None) -> str:
        """Одна попытка доставки. Возвращает итоговый статус записи."""
        now = now or datetime.now(UTC)
        with session_scope(self.sessions) as s:
            claimed = s.execute(
                update(NotificationLogRow)
                .where(NotificationLogRow.id == log_id,
                       NotificationLogRow.status.in_(("pending", "retry")),
                       NotificationLogRow.next_attempt_at <= now)
                .values(next_attempt_at=now + LEASE)
                .execution_options(synchronize_session=False)).rowcount == 1
            if not claimed:
                return "skipped"
            row = s.get(NotificationLogRow, log_id)
            ch = s.get(IntegrationChannelRow, row.channel_id)
            attempts = row.attempts + 1
            payload, event_kind = dict(row.payload or {}), row.event
            impl = get_channel(ch.type) if ch is not None else None
            cfg, secret_enc = (dict(ch.config or {}), ch.secret_enc) if ch else ({}, None)
            enabled = ch is not None and ch.enabled
            channel_id = row.channel_id

        secrets: dict[str, str] = {}
        error, retry, ref, note = None, True, None, None
        try:
            if impl is None or (not enabled and event_kind != TEST):
                raise DeliveryError("канал выключен или удалён", retry=False)
            if secret_enc:
                if self.vault is None:
                    raise DeliveryError("не задан ключ шифрования секретов каналов",
                                        retry=False)
                try:
                    secrets = self.vault.decrypt(secret_enc)
                except VaultUnavailable as e:
                    raise DeliveryError(str(e), retry=False) from None
            result = impl.send(Event.from_payload(payload), cfg, secrets, self.tx)
            ref, note = result.external_ref, result.note
        except DeliveryError as e:
            error, retry = scrub(str(e), secrets), e.retry
        except Exception as e:  # noqa: BLE001 — транспорт чужой, текст ошибки чистим
            error, retry = scrub(f"{type(e).__name__}: {e}", secrets), True
            log.warning("notification %s: unexpected %s", log_id, type(e).__name__)
        finally:
            secrets.clear()

        if error is None:
            status, nxt = "sent", None
        elif retry and attempts < MAX_ATTEMPTS and not single_attempt:
            status = "retry"
            nxt = now + timedelta(
                seconds=BACKOFF_SECONDS[min(attempts, len(BACKOFF_SECONDS)) - 1])
        else:
            status, nxt = "failed", None
        with session_scope(self.sessions) as s:
            s.execute(update(NotificationLogRow).where(NotificationLogRow.id == log_id)
                      .values(status=status, attempts=attempts, next_attempt_at=nxt,
                              last_error=error, external_ref=ref,
                              sent_at=datetime.now(UTC) if status == "sent" else None)
                      .execution_options(synchronize_session=False))
        self.audit.record(
            subject=SUBJECT, action="notification", target=f"channel:{channel_id}",
            result=status,
            details={"log_id": log_id, "event": event_kind, "attempt": attempts,
                     "error": error, "external_ref": ref, "note": note,
                     "scan_run_id": payload.get("scan_run_id")})
        return status

    def send_test(self, channel_id: int, actor: str) -> NotificationLogRow:
        """Проверочная отправка: одна попытка, результат сразу в журнале."""
        now = datetime.now(UTC)
        with session_scope(self.sessions) as s:
            ch = s.get(IntegrationChannelRow, channel_id)
            if ch is None:
                raise LookupError(channel_id)
            ev = Event(kind=TEST, title="Тестовое уведомление сканера",
                       message=f"Проверка канала «{ch.name}». Запросил: {actor}.")
            row = NotificationLogRow(channel_id=ch.id, event=TEST, status="pending",
                                     next_attempt_at=now, payload=ev.to_payload())
            s.add(row)
            s.flush()
            log_id = row.id
        self.deliver(log_id, single_attempt=True)
        with session_scope(self.sessions) as s:
            return s.get(NotificationLogRow, log_id)

    def retry(self, log_id: int) -> str:
        """Вручную повторить доставку со статусом failed."""
        with session_scope(self.sessions) as s:
            row = s.get(NotificationLogRow, log_id)
            if row is None or row.status != "failed":
                raise LookupError(log_id)
            row.status, row.attempts = "pending", 0
            row.next_attempt_at, row.last_error = datetime.now(UTC), None
        return self.deliver(log_id)


def _with_window(d: Delivery, ev: Event) -> Delivery:
    if ev.kind == FEED_STALE and d.dedup_key is None:
        return Delivery(d.event, dedup_key=f"feed:{ev.source}", dedup_window=FEED_DEDUP_WINDOW)
    return d
