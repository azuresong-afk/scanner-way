"""События уведомлений: структура, фильтры маршрутизации, сводка для сообщений.

В сообщения и журнал попадает только сводка (заголовок находки, хост, порт,
идентификаторы CVE/БДУ, уровень и приоритет) — без доказательств находки
(evidence) и без каких-либо секретов.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field, replace
from datetime import UTC, datetime
from typing import Any

from scanner.core.models import Severity

RUN_FINISHED = "run_finished"
NEW_CRITICAL = "new_critical"
FEED_STALE = "feed_stale"
TEST = "test"
EVENTS = (RUN_FINISHED, NEW_CRITICAL, FEED_STALE)
EVENT_TITLES = {RUN_FINISHED: "Прогон завершён",
                NEW_CRITICAL: "Новые критичные находки",
                FEED_STALE: "Справочник не обновился",
                TEST: "Тестовое уведомление"}

SEVERITIES = tuple(str(s) for s in Severity)                  # info … critical
PRIORITIES = ("low", "medium", "high", "critical")            # ярлыки R6
STATUS_TITLES = {"done": "завершён", "failed": "завершён с ошибкой",
                 "stopped": "остановлен"}

# В сообщении — не больше стольких находок, остальное «и ещё N».
MAX_ITEMS_IN_PAYLOAD = 50
TOP_ITEMS = 5


def rank_of(value: str | None, scale: tuple[str, ...]) -> int:
    return scale.index(value) if value in scale else -1


@dataclass(slots=True)
class Item:
    """Находка в сводке события."""
    dedup_key: str
    host: str
    port: int | None
    title: str
    severity: str
    status: str = "open"                       # new | regression | open
    vuln_id: str | None = None
    cve_ids: list[str] = field(default_factory=list)
    bdu_ids: list[str] = field(default_factory=list)
    priority: str | None = None                # ярлык R6: critical | high | medium | low
    score: float | None = None
    rank: int | None = None
    in_kev: bool = False
    owner: str | None = None
    groups: list[str] = field(default_factory=list)


@dataclass(slots=True)
class HostInfo:
    host: str
    owner: str | None = None
    groups: list[str] = field(default_factory=list)


@dataclass(slots=True)
class Event:
    kind: str
    title: str
    engagement_id: int | None = None
    engagement_name: str | None = None
    scan_run_id: int | None = None
    run_name: str | None = None
    run_status: str | None = None
    link: str | None = None
    message: str | None = None                 # feed_stale: что случилось
    source: str | None = None                  # feed_stale: идентификатор источника
    hosts: list[HostInfo] = field(default_factory=list)
    items: list[Item] = field(default_factory=list)
    fixed_total: int | None = None
    generated_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    # Сколько находок не вошло в items (обрезка при сохранении).
    items_omitted: int = 0
    # Хостов в области события (в сохранённой сводке сам список хостов не хранится).
    hosts_total: int = 0

    # ---- производные ----
    @property
    def counts(self) -> dict[str, int]:
        out = {s: 0 for s in reversed(SEVERITIES)}
        for i in self.items:
            out[i.severity] = out.get(i.severity, 0) + 1
        return out

    @property
    def new_total(self) -> int:
        return sum(1 for i in self.items if i.status in ("new", "regression"))

    def top_items(self, n: int = TOP_ITEMS) -> list[Item]:
        return sorted((i for i in self.items if i.severity != "info"), key=_order)[:n]

    # ---- сериализация ----
    def to_payload(self) -> dict[str, Any]:
        d = asdict(self)
        items = sorted(self.items, key=_order)
        d["items"] = [asdict(i) for i in items[:MAX_ITEMS_IN_PAYLOAD]]
        d["items_omitted"] = max(0, len(items) - MAX_ITEMS_IN_PAYLOAD) + self.items_omitted
        d["counts"] = self.counts
        # хосты нужны только для маршрутизации; в журнале — их число
        d["hosts_total"] = len(self.hosts) or self.hosts_total
        d["hosts"] = []
        return d

    @classmethod
    def from_payload(cls, d: dict[str, Any]) -> Event:
        d = dict(d)
        d.pop("counts", None)
        items = [Item(**i) for i in d.pop("items", [])]
        hosts = [HostInfo(**h) for h in d.pop("hosts", [])]
        return cls(**d, items=items, hosts=hosts)


def _order(i: Item) -> tuple:
    return (i.rank if i.rank is not None else 10**9,
            -rank_of(i.severity, SEVERITIES), i.host, i.port or 0, i.title)


# ---------- фильтры маршрутизации ----------

@dataclass(slots=True)
class Filters:
    """Фильтры канала. Пустое значение = не ограничивать."""
    min_severity: str | None = None
    min_priority: str | None = None
    groups: list[str] = field(default_factory=list)       # названия групп активов (R7)
    owners: list[str] = field(default_factory=list)       # владельцы активов (R7)
    engagements: list[int] = field(default_factory=list)  # договоры

    @classmethod
    def from_dict(cls, d: dict[str, Any] | None) -> Filters:
        d = d or {}
        return cls(min_severity=d.get("min_severity") or None,
                   min_priority=d.get("min_priority") or None,
                   groups=list(d.get("groups") or []), owners=list(d.get("owners") or []),
                   engagements=[int(x) for x in d.get("engagements") or []])

    def to_dict(self) -> dict[str, Any]:
        return {"min_severity": self.min_severity, "min_priority": self.min_priority,
                "groups": self.groups, "owners": self.owners,
                "engagements": self.engagements}

    @property
    def scoped(self) -> bool:
        return bool(self.groups or self.owners)

    def host_in_scope(self, owner: str | None, groups: list[str]) -> bool:
        if not self.scoped:
            return True
        want_g = {g.casefold() for g in self.groups}
        want_o = {o.casefold() for o in self.owners}
        return bool(want_g & {g.casefold() for g in groups}
                    or (owner and owner.casefold() in want_o))

    def passes_threshold(self, i: Item) -> bool:
        """«Критичная» находка. Пороги не заданы — критическая по уровню опасности
        либо по приоритету R6; заданы — должны выполняться все заданные."""
        if not (self.min_severity or self.min_priority):
            return i.severity == "critical" or i.priority == "critical"
        if self.min_severity and rank_of(i.severity, SEVERITIES) < rank_of(
                self.min_severity, SEVERITIES):
            return False
        return not (self.min_priority and rank_of(i.priority, PRIORITIES) < rank_of(
            self.min_priority, PRIORITIES))


def route(event: Event, subscribed: list[str], filters: Filters) -> Event | None:
    """Событие для конкретного канала с учётом подписки и фильтров; None — не слать."""
    if event.kind != TEST and event.kind not in subscribed:
        return None
    if event.kind == FEED_STALE or event.kind == TEST:
        return event
    if filters.engagements and event.engagement_id not in filters.engagements:
        return None
    host_ok = {h.host: filters.host_in_scope(h.owner, h.groups) for h in event.hosts}
    items = [i for i in event.items
             if host_ok.get(i.host, filters.host_in_scope(i.owner, i.groups))]
    hosts = [h for h in event.hosts if host_ok[h.host]]
    if filters.scoped and not hosts and not items:
        return None
    if event.kind == NEW_CRITICAL:
        items = [i for i in items if i.status in ("new", "regression")
                 and filters.passes_threshold(i)]
        if not items:
            return None
    return replace(event, items=items, hosts=hosts, hosts_total=len(hosts))
