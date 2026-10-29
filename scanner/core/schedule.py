"""Расписание прогонов: когда запускать следующий раз.

Виды расписания:
  * once    — один раз в указанный момент (run_at);
  * daily   — каждый день в time_of_day;
  * weekly  — в выбранные дни недели (0 — понедельник … 6 — воскресенье)
              в time_of_day;
  * monthly — в month_day каждого месяца в time_of_day (в коротком месяце —
              в его последний день).

Время суток задаётся в часовом поясе расписания (по умолчанию — поясе браузера
оператора), моменты запуска хранятся в UTC. Здесь только чистые вычисления;
исполнение — в scanner.api.scheduler.
"""
from __future__ import annotations

import calendar
import re
from dataclasses import dataclass, field
from datetime import UTC, date, datetime, time, timedelta
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

KINDS = ("once", "daily", "weekly", "monthly")
_TIME = re.compile(r"^([01]\d|2[0-3]):([0-5]\d)$")
# Дальше года вперёд искать нечего: любое периодическое расписание сработает раньше.
_HORIZON_DAYS = 400


class ScheduleError(ValueError):
    """Неверные параметры расписания (текст — для оператора)."""


def zone(name: str) -> ZoneInfo:
    try:
        return ZoneInfo(name)
    except (ZoneInfoNotFoundError, ValueError) as e:
        raise ScheduleError(f"неизвестный часовой пояс: {name}") from e


def parse_time(value: str) -> time:
    m = _TIME.match(value or "")
    if not m:
        raise ScheduleError("время запуска — в формате ЧЧ:ММ, например 03:30")
    return time(int(m.group(1)), int(m.group(2)))


@dataclass(slots=True)
class ScheduleSpec:
    kind: str
    timezone: str
    time_of_day: str | None = None
    weekdays: list[int] = field(default_factory=list)
    month_day: int | None = None
    run_at: datetime | None = None

    def validate(self) -> None:
        if self.kind not in KINDS:
            raise ScheduleError(f"неизвестный вид расписания: {self.kind}")
        zone(self.timezone)
        if self.kind == "once":
            if self.run_at is None:
                raise ScheduleError("для разового запуска укажите дату и время")
            return
        parse_time(self.time_of_day or "")
        if self.kind == "weekly" and (
                not self.weekdays or any(d not in range(7) for d in self.weekdays)):
            raise ScheduleError("выберите хотя бы один день недели")
        if self.kind == "monthly" and self.month_day not in range(1, 32):
            raise ScheduleError("день месяца — от 1 до 31")


def _aware(dt: datetime) -> datetime:
    return dt if dt.tzinfo is not None else dt.replace(tzinfo=UTC)


def _matches(spec: ScheduleSpec, d: date) -> bool:
    if spec.kind == "daily":
        return True
    if spec.kind == "weekly":
        return d.weekday() in spec.weekdays
    last = calendar.monthrange(d.year, d.month)[1]
    return d.day == min(spec.month_day or 1, last)


def next_occurrence(spec: ScheduleSpec, after: datetime) -> datetime | None:
    """Ближайший момент запуска строго позже `after` (UTC); None — больше не будет."""
    after = _aware(after).astimezone(UTC)
    if spec.kind == "once":
        if spec.run_at is None:
            return None
        at = _aware(spec.run_at).astimezone(UTC)
        return at if at > after else None
    tz = zone(spec.timezone)
    at_time = parse_time(spec.time_of_day or "")
    day = after.astimezone(tz).date()
    for _ in range(_HORIZON_DAYS):
        if _matches(spec, day):
            # Несуществующее при переходе на летнее время локальное время
            # zoneinfo сдвигает вперёд — запуск всё равно состоится.
            at = datetime.combine(day, at_time, tzinfo=tz).astimezone(UTC)
            if at > after:
                return at
        day += timedelta(days=1)
    return None
