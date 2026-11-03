"""Запись портов для сканирования: «22, 80, 443, 8000-8100».

Разделители — запятая, точка с запятой или пробел; диапазон — через дефис
(пробелы вокруг «-» допустимы, длинное и короткое тире тоже понимаются).
Результат — отсортированные непересекающиеся диапазоны, из которых собирается
аргумент nmap `-p` / `--exclude-ports`. Только цифры и дефисы: в argv nmap не
попадёт ни опция, ни протокольный префикс (`U:`), ни имя сервиса.
"""
from __future__ import annotations

import re
from collections.abc import Iterable, Sequence

PORT_MIN, PORT_MAX = 1, 65535

_SPLIT = re.compile(r"[,;\s]+")
_ITEM = re.compile(r"^(\d{1,5})(?:-(\d{1,5}))?$")
# «22 - 25» и тире → «22-25», чтобы пробелы вокруг дефиса не делили запись
_DASH = re.compile(r"\s*[-‐-―]\s*")

PortRanges = list[tuple[int, int]]


class PortSpecError(ValueError):
    """Запись портов не разобрана: текст ошибки — для пользователя."""


def parse_ports(text: str) -> PortRanges:
    """«22, 80, 8000-8100» → [(22, 22), (80, 80), (8000, 8100)] (слитые, по порядку)."""
    raw = _DASH.sub("-", (text or "").strip())
    if not raw:
        return []
    ranges: PortRanges = []
    for item in _SPLIT.split(raw):
        if not item:
            continue
        m = _ITEM.match(item)
        if m is None:
            raise PortSpecError(f"не порт и не диапазон: «{item}»")
        lo = int(m.group(1))
        hi = int(m.group(2)) if m.group(2) else lo
        for p in (lo, hi):
            if not PORT_MIN <= p <= PORT_MAX:
                raise PortSpecError(f"порт вне диапазона {PORT_MIN}–{PORT_MAX}: {p}")
        if hi < lo:
            raise PortSpecError(f"конец диапазона меньше начала: «{item}»")
        ranges.append((lo, hi))
    return merge(ranges)


def merge(ranges: Iterable[tuple[int, int]]) -> PortRanges:
    out: PortRanges = []
    for lo, hi in sorted(ranges):
        if out and lo <= out[-1][1] + 1:
            out[-1] = (out[-1][0], max(out[-1][1], hi))
        else:
            out.append((lo, hi))
    return out


def subtract(ranges: Sequence[tuple[int, int]],
             excluded: Sequence[tuple[int, int]]) -> PortRanges:
    """Порты из ranges, кроме excluded."""
    out: PortRanges = []
    for lo, hi in merge(ranges):
        cur = lo
        for xlo, xhi in merge(excluded):
            if xhi < cur or xlo > hi:
                continue
            if xlo > cur:
                out.append((cur, xlo - 1))
            cur = max(cur, xhi + 1)
            if cur > hi:
                break
        if cur <= hi:
            out.append((cur, hi))
    return out


def count(ranges: Iterable[tuple[int, int]]) -> int:
    return sum(hi - lo + 1 for lo, hi in ranges)


def to_text(ranges: Iterable[tuple[int, int]]) -> str:
    """[(22, 22), (8000, 8100)] → «22,8000-8100» (формат nmap -p)."""
    return ",".join(str(lo) if lo == hi else f"{lo}-{hi}" for lo, hi in ranges)


def contains(ranges: Iterable[tuple[int, int]], port: int) -> bool:
    return any(lo <= port <= hi for lo, hi in ranges)
