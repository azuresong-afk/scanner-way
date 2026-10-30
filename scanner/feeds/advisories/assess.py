"""Решение по пакету и CVE: уязвим / закрыто бэкпортом / не затронут / нет данных.

Ошибка здесь стоит дорого в обе стороны: ложное «исправлено» прячет
уязвимость, ложное «уязвим» — то, что R2 убирает. Поэтому при сомнении
решение консервативное: находка остаётся (VULNERABLE или NO_DATA с оговоркой).
"""
from __future__ import annotations

import enum
import re
from collections.abc import Iterable
from dataclasses import dataclass

from scanner.feeds import vercmp
from scanner.feeds.advisories.base import FIXED, NOT_AFFECTED, OPEN, Advisory


class Verdict(enum.StrEnum):
    VULNERABLE = "vulnerable"        # версия < исправленной или исправления нет
    FIXED = "fixed"                  # версия ≥ исправленной: закрыто (бэкпортом)
    NOT_AFFECTED = "not_affected"    # вендор: пакет выпуска не затронут
    NO_DATA = "no_data"              # у вендора нет записи — как раньше, с оговоркой


@dataclass(frozen=True, slots=True)
class Decision:
    verdict: Verdict
    cve: str
    package: str                     # установленный пакет
    installed: str
    advisory: Advisory | None = None

    @property
    def closed(self) -> bool:
        return self.verdict in (Verdict.FIXED, Verdict.NOT_AFFECTED)


def _branch(manager: str, version: str) -> str:
    """Ветка версии: эпоха + первый числовой компонент апстрима (``1:18``)."""
    parse = vercmp.parse_dpkg if manager == "dpkg" else vercmp.parse_evr
    epoch, upstream, _ = parse(version)
    m = re.match(r"\d+", upstream)
    return f"{epoch}:{m.group(0) if m else upstream}"


def decide(entries: Iterable[Advisory], cve: str, *, package: str, installed: str,
           manager: str) -> Decision:
    """Записи вендора по пакету (бинарное и исходное имя) -> решение по одной CVE.

    Несколько исправленных версий (модульные потоки RHEL, повторные бюллетени):
    сравниваем с версиями той же ветки, что установлена, и берём наибольшую —
    консервативно, чтобы не объявить «исправлено» раньше времени.
    """
    rows = [e for e in entries if e.cve == cve]
    fixed = [e for e in rows if e.status == FIXED and e.fixed_version]
    if fixed:
        branch = _branch(manager, installed)
        same = [e for e in fixed if _branch(manager, e.fixed_version or "") == branch] or fixed
        top = same[0]
        for e in same[1:]:
            if vercmp.compare(manager, e.fixed_version or "", top.fixed_version or "") > 0:
                top = e
        ok = vercmp.compare(manager, installed, top.fixed_version or "") >= 0
        return Decision(Verdict.FIXED if ok else Verdict.VULNERABLE, cve, package,
                        installed, top)
    if any(e.status == NOT_AFFECTED for e in rows):
        return Decision(Verdict.NOT_AFFECTED, cve, package, installed,
                        next(e for e in rows if e.status == NOT_AFFECTED))
    if any(e.status == OPEN for e in rows):
        return Decision(Verdict.VULNERABLE, cve, package, installed,
                        next(e for e in rows if e.status == OPEN))
    return Decision(Verdict.NO_DATA, cve, package, installed)


def combine(decisions: list[Decision]) -> Verdict:
    """Итог для находки по решениям (пакеты группы × CVE находки): уязвим, если
    уязвим хоть один; закрыто — только если закрыто всё; иначе нет данных."""
    if not decisions:
        return Verdict.NO_DATA
    if any(d.verdict is Verdict.VULNERABLE for d in decisions):
        return Verdict.VULNERABLE
    if all(d.closed for d in decisions):
        return (Verdict.NOT_AFFECTED if all(d.verdict is Verdict.NOT_AFFECTED
                                            for d in decisions) else Verdict.FIXED)
    return Verdict.NO_DATA
