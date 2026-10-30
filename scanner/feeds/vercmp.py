"""Сравнение версий пакетов по правилам менеджеров пакетов: dpkg и rpm.

Нужно для учёта бэкпортов (R2): бюллетень дистрибутива говорит «исправлено в
``1.1.1n-0+deb11u5``», и решение «уязвим / закрыто» принимается сравнением
ТОЧНОЙ версии установленного пакета с этой границей — так, как сравнивает сам
менеджер пакетов. Сравнение строк или версий апстрима здесь даёт ошибки:
``1.1.1n-0+deb11u10 > 1.1.1n-0+deb11u9``, ``2.0~rc1 < 2.0``, ``1.0^git1 > 1.0``.

dpkg (Debian, Ubuntu, Astra Linux) — ``[epoch:]upstream[-revision]``, алгоритм
verrevcmp из dpkg (lib/dpkg/version.c): чередование нецифровых и цифровых
участков; в нецифровых буквы раньше прочих символов, ``~`` раньше всего, даже
конца строки.

rpm (RHEL и аналоги, РЕД ОС, ALT) — ``[epoch:]version[-release]`` (EVR),
алгоритм rpmvercmp из rpm (rpmio/rpmvercmp.c), включая ``~`` (pre-release,
раньше всего) и ``^`` (post-release snapshot: позже конца строки, но раньше
любого продолжения).
"""
from __future__ import annotations

import re

_DIGITS = re.compile(r"\d+")


# ---------- dpkg ----------

def _dpkg_order(c: str) -> int:
    if c == "~":
        return -1
    if c.isdigit():
        return 0
    if c.isalpha():
        return ord(c)
    return ord(c) + 256


def _verrevcmp(a: str, b: str) -> int:
    i = j = 0
    while i < len(a) or j < len(b):
        first_diff = 0
        while (i < len(a) and not a[i].isdigit()) or (j < len(b) and not b[j].isdigit()):
            ac = _dpkg_order(a[i]) if i < len(a) else 0
            bc = _dpkg_order(b[j]) if j < len(b) else 0
            if ac != bc:
                return ac - bc
            i += 1
            j += 1
        while i < len(a) and a[i] == "0":
            i += 1
        while j < len(b) and b[j] == "0":
            j += 1
        while i < len(a) and a[i].isdigit() and j < len(b) and b[j].isdigit():
            if not first_diff:
                first_diff = ord(a[i]) - ord(b[j])
            i += 1
            j += 1
        if i < len(a) and a[i].isdigit():
            return 1
        if j < len(b) and b[j].isdigit():
            return -1
        if first_diff:
            return first_diff
    return 0


def parse_dpkg(version: str) -> tuple[int, str, str]:
    """``1:9.2p1-2+deb12u3`` -> (1, '9.2p1', '2+deb12u3'). Без ревизии — ''."""
    v = version.strip()
    epoch = 0
    if ":" in v:
        e, rest = v.split(":", 1)
        if e.isdigit():
            epoch, v = int(e), rest
    upstream, sep, revision = v.rpartition("-")
    if not sep:
        upstream, revision = v, ""
    return epoch, upstream, revision


def dpkg_compare(a: str, b: str) -> int:
    """<0, 0, >0 — как ``dpkg --compare-versions a lt|eq|gt b``."""
    ea, ua, ra = parse_dpkg(a)
    eb, ub, rb = parse_dpkg(b)
    if ea != eb:
        return -1 if ea < eb else 1
    r = _verrevcmp(ua, ub)
    if r:
        return -1 if r < 0 else 1
    r = _verrevcmp(ra, rb)
    return 0 if r == 0 else (-1 if r < 0 else 1)


# ---------- rpm ----------

def _rpmvercmp(a: str, b: str) -> int:
    if a == b:
        return 0
    i = j = 0
    while i < len(a) or j < len(b):
        # Разделители (всё, кроме букв/цифр и ~ ^) пропускаются.
        while i < len(a) and not (a[i].isalnum() and a[i].isascii()) and a[i] not in "~^":
            i += 1
        while j < len(b) and not (b[j].isalnum() and b[j].isascii()) and b[j] not in "~^":
            j += 1
        # ~ — раньше всего, даже конца строки
        if (i < len(a) and a[i] == "~") or (j < len(b) and b[j] == "~"):
            if i >= len(a) or a[i] != "~":
                return 1
            if j >= len(b) or b[j] != "~":
                return -1
            i += 1
            j += 1
            continue
        # ^ — позже конца строки, но раньше любого продолжения
        if (i < len(a) and a[i] == "^") or (j < len(b) and b[j] == "^"):
            if i >= len(a):
                return -1
            if j >= len(b):
                return 1
            if a[i] != "^":
                return 1
            if b[j] != "^":
                return -1
            i += 1
            j += 1
            continue
        if i >= len(a) or j >= len(b):
            break
        if a[i].isdigit():
            si, sj = i, j
            while i < len(a) and a[i].isdigit():
                i += 1
            while j < len(b) and b[j].isdigit():
                j += 1
            seg_a, seg_b = a[si:i], b[sj:j]
            if not seg_b:
                return 1             # число новее буквенного сегмента
            seg_a, seg_b = seg_a.lstrip("0"), seg_b.lstrip("0")
            if len(seg_a) != len(seg_b):
                return 1 if len(seg_a) > len(seg_b) else -1
        else:
            si, sj = i, j
            while i < len(a) and a[i].isalpha() and a[i].isascii():
                i += 1
            while j < len(b) and b[j].isalpha() and b[j].isascii():
                j += 1
            seg_a, seg_b = a[si:i], b[sj:j]
            if not seg_b:
                return -1
        if seg_a != seg_b:
            return 1 if seg_a > seg_b else -1
    if i >= len(a) and j >= len(b):
        return 0
    return -1 if i >= len(a) else 1


def parse_evr(version: str) -> tuple[int, str, str]:
    """``1:3.0.7-27.el9`` -> (1, '3.0.7', '27.el9'). ``(none):`` — эпоха 0."""
    v = version.strip()
    epoch = 0
    if ":" in v:
        e, rest = v.split(":", 1)
        if e.isdigit():
            epoch, v = int(e), rest
        elif e == "(none)":
            v = rest
    ver, sep, rel = v.rpartition("-")
    if not sep:
        ver, rel = v, ""
    return epoch, ver, rel


def rpm_compare(a: str, b: str) -> int:
    """<0, 0, >0 — как ``rpmdev-vercmp a b`` (EVR). Нет релиза у одной из
    сторон — релизы не сравниваются (как rpm для зависимостей без релиза)."""
    ea, va, ra = parse_evr(a)
    eb, vb, rb = parse_evr(b)
    if ea != eb:
        return -1 if ea < eb else 1
    r = _rpmvercmp(va, vb)
    if r or not ra or not rb:
        return r
    return _rpmvercmp(ra, rb)


# ---------- общее ----------

def compare(manager: str, a: str, b: str) -> int:
    """Сравнение версий по правилам менеджера пакетов (dpkg | rpm)."""
    if manager == "dpkg":
        return dpkg_compare(a, b)
    if manager == "rpm":
        return rpm_compare(a, b)
    raise ValueError(f"сравнение версий для менеджера {manager!r} не поддержано")


def strip_zero_epoch(version: str) -> str:
    """``0:1.2-3`` -> ``1.2-3`` (для показа; эпоха 0 равна её отсутствию)."""
    return version.removeprefix("0:")
