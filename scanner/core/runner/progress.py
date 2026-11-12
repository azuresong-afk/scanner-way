"""Ход прогона для интерфейса: этап, хосты, процент и «осталось ≈ …»."""
from __future__ import annotations

import logging
import threading
from collections.abc import Callable, Iterable, Mapping
from datetime import UTC, datetime

# Имя логгера — прежнее (до разделения модуля): настройки логирования и
# фильтры по нему продолжают работать.
log = logging.getLogger("scanner.core.orchestrator")

# ========== Прогресс прогона ==========
STAGE_SAVING = "saving"      # после модулей: запись результатов, сравнение, нормативы
PROGRESS_MIN_INTERVAL = 2.0  # секунд между записями прогресса в БД
ETA_MIN_PERCENT = 5          # оценка «по общей скорости» — не раньше этого процента


def stage_history(progress_rows: Iterable[Mapping | None]) -> dict[str, float]:
    """Секунд на хост по этапам из снимков прогресса прошлых прогонов (новые
    первыми): для каждого модуля берётся самый свежий замер."""
    out: dict[str, float] = {}
    for p in progress_rows:
        if not p:
            continue
        n = p.get("hosts_total") or 0
        secs = p.get("stage_seconds") or {}
        if n <= 0 or not isinstance(secs, Mapping):
            continue
        for m, v in secs.items():
            if m not in out and isinstance(v, (int, float)) and v > 0:
                out[m] = float(v) / n
    return out


class RunProgress:
    """Ход прогона для интерфейса: текущий этап (модуль), сколько хостов он
    уже отработал из всех хостов прогона, и общий процент.

    Хост этапа считается готовым, когда модуль отметил его в покрытии
    (completed / unreachable / timeout / …). Процент — доля пар
    «этап × хост»: (этапов позади × хостов + готово на этапе) / (этапов ×
    хостов), до конца прогона не больше 99. Снимки уходят в ``sink`` не чаще
    ``min_interval`` секунд; смена этапа и его конец отправляются сразу.
    Ошибка ``sink`` поглощается — прогресс не влияет на итог прогона."""

    def __init__(self, sink: Callable[[dict], None], stages: list[str], hosts: int, *,
                 min_interval: float = PROGRESS_MIN_INTERVAL,
                 clock: Callable[[], float] | None = None,
                 history: Mapping[str, float] | None = None):
        import time
        self.sink = sink
        # Секунд на хост по этапам из прошлых прогонов проекта (stage_history).
        self.history = {m: float(v) for m, v in (history or {}).items() if v and v > 0}
        self.stages = list(stages)
        self.hosts = max(int(hosts), 0)
        self.min_interval = min_interval
        self.clock = clock or time.monotonic
        self._lock = threading.Lock()
        self._index = 0           # 0 — ещё не начат ни один этап
        self._stage: str | None = None
        self._done: set[str] = set()
        self._last = float("-inf")
        self._t0 = self.clock()
        self._stage_t0 = self._t0
        self._stage_secs: dict[str, float] = {}   # длительность завершённых этапов

    def snapshot(self) -> dict:
        k = max(len(self.stages), 1)
        n = self.hosts
        if self._stage == STAGE_SAVING:
            percent, done = 99, n
        elif n == 0:
            percent, done = int(100 * max(self._index - 1, 0) / k), 0
        else:
            done = min(len(self._done), n)
            percent = int(100 * ((max(self._index - 1, 0)) * n + done) / (k * n))
        now = self.clock()
        eta = self._eta(now, done)
        if eta is None and self._stage != STAGE_SAVING and percent >= ETA_MIN_PERCENT:
            # нет ни истории, ни замеров по этапам — по общей скорости прогона
            eta = (now - self._t0) * (100 - percent) / percent
        return {"stage": self._stage, "stage_index": min(self._index, len(self.stages)),
                "stages": len(self.stages), "hosts_done": done, "hosts_total": n,
                "percent": min(percent, 99),
                "elapsed_seconds": int(now - self._t0),
                "eta_seconds": None if eta is None else round(eta),
                "stage_seconds": {m: round(v, 1) for m, v in self._stage_secs.items()},
                "updated_at": datetime.now(UTC).isoformat(timespec="seconds")}

    def _eta(self, now: float, done: int) -> float | None:
        """Сколько примерно осталось, с.

        Текущий этап — по его собственной скорости (сек на готовый хост), пока
        готовых хостов мало — вперемешку с прошлыми прогонами; будущие этапы —
        по прошлым прогонам проекта (сек на хост × хостов), а без истории — по
        средней скорости уже пройденных этапов этого прогона. Ничего нет —
        None (тогда снимок берёт общую скорость прогона)."""
        n = self.hosts
        if self._stage is None or self._stage == STAGE_SAVING or n == 0:
            return None
        observed = [v / n for v in self._stage_secs.values()]
        avg = sum(observed) / len(observed) if observed else None
        el = max(now - self._stage_t0, 0.0)
        left = n - done
        hist = self.history.get(self._stage)
        prior = hist if hist is not None else avg
        if done > 0 and el > 0:
            live = el / done * left
            enough = max(2.0, n * 0.2)
            if prior is not None and done < enough:
                w = done / enough
                cur = w * live + (1 - w) * max(prior * n - el, 0.0)
            else:
                cur = live
        elif prior is not None:
            cur = max(prior * n - el, 0.0)
        else:
            return None
        total = cur
        for m in self.stages[self._index:]:
            per_host = self.history.get(m, avg)
            if per_host is None:
                return None
            total += per_host * n
        return total

    def _emit(self, force: bool) -> None:
        now = self.clock()
        if not force and now - self._last < self.min_interval:
            return
        self._last = now
        try:
            self.sink(self.snapshot())
        except Exception:
            log.exception("scan run progress update failed")

    def begin(self, module: str) -> None:
        with self._lock:
            self._index += 1
            self._stage = module
            self._stage_t0 = self.clock()
            self._done = set()
            self._emit(True)

    def mark(self, host: str, module: str) -> None:
        with self._lock:
            if module != self._stage or host in self._done:
                return
            self._done.add(host)
            self._emit(False)

    def end_stage(self, hosts: Iterable[str]) -> None:
        """Этап закончился: все хосты прогона для него отработаны."""
        with self._lock:
            self._done = set(hosts)
            if self._stage and self._stage != STAGE_SAVING:
                self._stage_secs[self._stage] = self.clock() - self._stage_t0
            self._emit(True)

    def saving(self) -> None:
        with self._lock:
            self._stage = STAGE_SAVING
            self._index = len(self.stages)
            self._emit(True)
