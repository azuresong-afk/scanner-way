"""Сравнение прогонов по dedup_key: open/fixed/new/regression.

С покрытием (scanner.core.coverage) сравнение честное: находка базового
прогона считается исправленной, только если её модуль в новом прогоне
действительно проверил хост; иначе она «не проверена» (unverified) — ни
исправлена, ни открыта. Повторное появление считается regression, только если
базовый прогон проверял этот хост этим модулем и находки там не было.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from scanner.core.models import Finding, Severity

if TYPE_CHECKING:
    from scanner.core.coverage import Coverage


@dataclass(slots=True)
class RunDiff:
    open: list[Finding] = field(default_factory=list)
    fixed: list[Finding] = field(default_factory=list)
    new: list[Finding] = field(default_factory=list)
    regression: list[Finding] = field(default_factory=list)
    # Находки базового прогона, которые в новом прогоне не проверялись (хост
    # недоступен, модуль не выполнялся, таймаут): статус неизвестен.
    unverified: list[Finding] = field(default_factory=list)


def diff_runs(previous: list[Finding], current: list[Finding],
              historically_fixed: set[str] | None = None, *,
              previous_coverage: Coverage | None = None,
              current_coverage: Coverage | None = None) -> RunDiff:
    """Считает тренды между двумя прогонами по dedup_key.

    historically_fixed — ключи, помеченные fixed в более ранних прогонах;
    их повторное появление в current = regression.
    previous_coverage/current_coverage — покрытие прогонов; без них сравнение
    как раньше (всё отсутствующее — исправлено).
    """
    historically_fixed = historically_fixed or set()
    prev = {f.dedup_key(): f for f in previous}
    cur = {f.dedup_key(): f for f in current}
    d = RunDiff()
    for k, f in cur.items():
        if k in prev:
            d.open.append(f)
        elif previous_coverage is not None and not previous_coverage.covered(f.host,
                                                                             f.module):
            # база этот хост этим модулем не проверяла: ни «повторно», ни
            # «новое» относительно неё утверждать нельзя
            (d.open if k in historically_fixed else d.new).append(f)
        elif k in historically_fixed:
            d.regression.append(f)
        else:
            d.new.append(f)
    for k, f in prev.items():
        if k not in cur:
            if current_coverage is not None and not current_coverage.covered(f.host,
                                                                             f.module):
                d.unverified.append(f)
            else:
                d.fixed.append(f)
    return d


def diff_by_module(previous: list[Finding], current: list[Finding],
                   historically_fixed: set[str] | None = None, *,
                   previous_coverage: Coverage | None = None,
                   current_coverage: Coverage | None = None) -> dict[str, RunDiff]:
    """diff_runs отдельно по каждому модулю (модуль входит в dedup_key,
    поэтому сумма по модулям совпадает со сводным diff)."""
    modules = sorted({f.module for f in previous} | {f.module for f in current})
    return {
        m: diff_runs([f for f in previous if f.module == m],
                     [f for f in current if f.module == m],
                     historically_fixed, previous_coverage=previous_coverage,
                     current_coverage=current_coverage)
        for m in modules
    }


def severity_counts(findings: list[Finding]) -> dict[Severity, int]:
    """Количество находок по уровням опасности (все уровни, включая нулевые)."""
    counts = {s: 0 for s in Severity}
    for f in findings:
        counts[f.severity] += 1
    return counts
