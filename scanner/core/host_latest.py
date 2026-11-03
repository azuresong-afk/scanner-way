"""Последнее известное состояние хоста — по всем прогонам договора.

Вкладка «Активы» без выбранного прогона показывает для каждого хоста его
последние известные уязвимости, чтобы не искать хост между прогонами. Состояние
собирается по модулям: для пары (хост, модуль) берутся находки последнего
прогона, где этот модуль хост действительно проверил (покрытие PR #65,
`completed`). Прогон, в котором хост был недоступен, не было учётки или истёк
таймаут, предыдущие данные не затирает: непроверенное не считается исправленным.

Пример: прогон №1 — Nuclei и инвентаризация по SSH нашли 12 уязвимостей; прогон
№2 — только Nuclei, SSH не ответил. Последние данные хоста = находки Nuclei из
№2 + находки инвентаризации из №1.

Модуль «проверил» хост, если в покрытии прогона статус `completed` или если
модуль оставил на хосте находку (у прогонов до миграции 0020 покрытие
оценивается `coverage.legacy_coverage`). Незавершённые прогоны (в очереди,
выполняются) не учитываются — их результаты ещё не сохранены.
"""
from __future__ import annotations

import ipaddress
from collections import defaultdict
from dataclasses import dataclass, field

from sqlalchemy import select
from sqlalchemy.orm import Session

from scanner.core import coverage as cv
from scanner.core import repository as repo
from scanner.core.db import FindingRow, RunCoverageRow, ScanRun

# Прогоны, результаты которых сохранены (см. orchestrator: результаты пишутся
# в конце прогона одной транзакцией).
_ACTIVE = ("pending", "running")


@dataclass(slots=True)
class HostLatest:
    host: str
    # модуль -> прогон, из которого берутся его находки
    module_runs: dict[str, int] = field(default_factory=dict)
    counts: dict[str, int] = field(default_factory=dict)    # по уровням, с info
    total: int = 0                                          # без info

    @property
    def run_ids(self) -> list[int]:
        """Прогоны, из которых собраны данные хоста, по возрастанию."""
        return sorted(set(self.module_runs.values()))

    @property
    def checked_run_id(self) -> int | None:
        """Последний прогон, в котором хост проверялся хоть одним модулем."""
        return max(self.module_runs.values()) if self.module_runs else None


def _key(host: object) -> str:
    return str(ipaddress.ip_address(str(host).split("/")[0]))


def module_runs(session: Session, engagement_id: int, host: str | None = None
                ) -> dict[str, dict[str, int]]:
    """{хост: {модуль: последний прогон, где модуль проверил хост}}."""
    runs = list(session.scalars(select(ScanRun).where(
        ScanRun.engagement_id == engagement_id, ScanRun.status.notin_(_ACTIVE))))
    if not runs:
        return {}
    ids = [r.id for r in runs]
    want = _key(host) if host is not None else None
    out: dict[str, dict[str, int]] = defaultdict(dict)

    def seen(h: object, module: str, run_id: int) -> None:
        k = _key(h)
        if want is not None and k != want:
            return
        if out[k].get(module, 0) < run_id:
            out[k][module] = run_id

    with_rows: set[int] = set()
    q = select(RunCoverageRow.scan_run_id, RunCoverageRow.host, RunCoverageRow.module,
               RunCoverageRow.status).where(RunCoverageRow.scan_run_id.in_(ids))
    for rid, h, module, status in session.execute(q):
        with_rows.add(rid)
        if status == cv.COMPLETED:
            seen(h, module, rid)
    # прогоны до миграции 0020 — оценка покрытия по хостам discovery и модулям
    for run in runs:
        if run.id not in with_rows:
            for e in repo.run_coverage(session, run).entries():
                if e.status == cv.COMPLETED:
                    seen(e.host, e.module, run.id)
    fq = select(FindingRow.scan_run_id, FindingRow.host, FindingRow.module).distinct() \
        .where(FindingRow.scan_run_id.in_(ids))
    if want is not None:
        fq = fq.where(FindingRow.host == want)
    for rid, h, module in session.execute(fq):
        seen(h, module, rid)
    return dict(out)


def _latest_rows(session: Session, engagement_id: int, host: str | None, columns):
    """Строки находок (выбранные колонки + run, host, module) из последних
    прогонов по модулям."""
    mr = module_runs(session, engagement_id, host)
    run_ids = sorted({rid for mods in mr.values() for rid in mods.values()})
    if not run_ids:
        return mr, []
    q = select(FindingRow.scan_run_id, FindingRow.host, FindingRow.module, *columns) \
        .where(FindingRow.scan_run_id.in_(run_ids))
    if host is not None:
        q = q.where(FindingRow.host == _key(host))
    rows = [r for r in session.execute(q)
            if mr.get(_key(r[1]), {}).get(r[2]) == r[0]]
    return mr, rows


def latest_counts(session: Session, engagement_id: int) -> dict[str, HostLatest]:
    """Счётчики последних известных находок по хостам (без ложных срабатываний)."""
    marks = set(repo.false_positive_marks(session, engagement_id))
    mr, rows = _latest_rows(session, engagement_id, None,
                            (FindingRow.severity, FindingRow.dedup_key))
    out = {h: HostLatest(host=h, module_runs=mods) for h, mods in mr.items()}
    for _rid, h, _module, severity, dedup in rows:
        if dedup in marks:
            continue
        lt = out[_key(h)]
        lt.counts[severity] = lt.counts.get(severity, 0) + 1
        if severity != "info":
            lt.total += 1
    return out


def latest_findings(session: Session, engagement_id: int, host: str
                    ) -> tuple[HostLatest, list[FindingRow]]:
    """Последние известные находки одного хоста (строки целиком, по id)."""
    key = _key(host)
    mr = module_runs(session, engagement_id, key)
    lt = HostLatest(host=key, module_runs=mr.get(key, {}))
    if not lt.module_runs:
        return lt, []
    rows = list(session.scalars(
        select(FindingRow).where(FindingRow.scan_run_id.in_(lt.run_ids),
                                 FindingRow.host == key).order_by(FindingRow.id)))
    rows = [r for r in rows if lt.module_runs.get(r.module) == r.scan_run_id]
    return lt, rows
