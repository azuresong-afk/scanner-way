"""Сравнение прогонов по dedup_key: open/fixed/new/regression."""
from __future__ import annotations

from dataclasses import dataclass, field

from scanner.core.models import Finding


@dataclass(slots=True)
class RunDiff:
    open: list[Finding] = field(default_factory=list)
    fixed: list[Finding] = field(default_factory=list)
    new: list[Finding] = field(default_factory=list)
    regression: list[Finding] = field(default_factory=list)


def diff_runs(previous: list[Finding], current: list[Finding],
              historically_fixed: set[str] | None = None) -> RunDiff:
    """Считает тренды между двумя прогонами по dedup_key.

    historically_fixed — ключи, помеченные fixed в более ранних прогонах;
    их повторное появление в current = regression.
    """
    historically_fixed = historically_fixed or set()
    prev = {f.dedup_key(): f for f in previous}
    cur = {f.dedup_key(): f for f in current}
    d = RunDiff()
    for k, f in cur.items():
        if k in prev:
            d.open.append(f)
        elif k in historically_fixed:
            d.regression.append(f)
        else:
            d.new.append(f)
    for k, f in prev.items():
        if k not in cur:
            d.fixed.append(f)
    return d
