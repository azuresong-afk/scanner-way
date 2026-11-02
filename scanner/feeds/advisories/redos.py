"""РЕД ОС: бюллетени безопасности вендора в формате OVAL (rpminfo).

Вендор публикует один файл на все выпуски:
https://redos.red-soft.ru/support/secure/redos.xml (адрес по умолчанию; свой —
ADVISORY_URL_REDOS, закрытый контур — файл ``redos.xml`` или ``redos-7.3.xml``
в ADVISORY_DIR). Выпуск каждой записи определяется по платформе определения
(``<platform>RED OS 7.3</platform>``, комментарий критерия «РЕД ОС 8 …»), а
если её нет — по метке сборки в версии исправления (``.el7`` — 7.3,
``.red80`` — 8). Не определился — запись относится ко всем выпускам задания:
сравнение rpm тогда консервативно (чужая метка сборки не даёт ложного «исправлено»).
Выпуск хоста — ``7.3``, ``8`` (``8.0`` -> ``8``).
"""
from __future__ import annotations

import re
from collections.abc import Iterable, Iterator
from typing import IO

from scanner.feeds.advisories.base import Advisory, FamilySpec
from scanner.feeds.advisories.oval import parse_oval_releases

_PLATFORM_RE = re.compile(r"(?:red\s*os|ред\s*ос|redos)\D{0,20}?(\d+(?:\.\d+)?)", re.IGNORECASE)
_DIST_RE = re.compile(r"\.(el7|red(\d)(\d))", re.IGNORECASE)


def release_of(version_id: str | None, codename: str | None) -> str | None:
    m = re.match(r"\d+(\.\d+)?", (version_id or "").strip())
    if not m:
        return None
    v = m.group(0)
    return v.removesuffix(".0")


def _norm(v: str) -> str:
    return v.removesuffix(".0")


def map_release(releases: list[str], platforms: list[str], fixed: str) -> list[str]:
    named = {_norm(m) for p in platforms for m in _PLATFORM_RE.findall(p)}
    if named:
        # «РЕД ОС 7» в платформе покрывает 7.3
        hit = [r for r in releases if r in named or r.split(".")[0] in named]
        return hit
    m = _DIST_RE.search(fixed)
    if m:
        if m.group(1).lower() == "el7":
            hit = [r for r in releases if r.startswith("7")]
        else:
            hit = [r for r in releases if r.split(".")[0] == m.group(2)]
        return hit                      # метка сборки другого выпуска — не наша запись
    return list(releases)


def parse_redos(stream: IO[bytes], family: str, releases: Iterable[str]) -> Iterator[Advisory]:
    return parse_oval_releases(stream, family, releases, map_release)


SPEC = FamilySpec(
    family="redos", label="РЕД ОС", manager="rpm", parser=parse_redos,
    default_url="https://redos.red-soft.ru/support/secure/redos.xml",
    host_families=("redos",), release_of=release_of,
    note="OVAL бюллетеней РЕД ОС (redos.xml — все выпуски)")
