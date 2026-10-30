"""Общие типы бюллетеней дистрибутивов: запись, семейство данных, выпуск."""
from __future__ import annotations

import re
from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass
from typing import IO

FIXED = "fixed"
NOT_AFFECTED = "not_affected"
OPEN = "open"
STATUSES = (FIXED, NOT_AFFECTED, OPEN)


@dataclass(frozen=True, slots=True)
class Advisory:
    """(семейство, выпуск, пакет, CVE) → первая исправленная версия | статус."""
    family: str
    release: str
    package: str
    cve: str
    status: str = FIXED
    fixed_version: str | None = None
    advisory_id: str | None = None


# Разбор потока источника для набора выпусков -> записи.
Parser = Callable[[IO[bytes], str, Iterable[str]], Iterator[Advisory]]


@dataclass(frozen=True, slots=True)
class FamilySpec:
    """Семейство данных вендора (одно на файл в этом пакете)."""
    family: str                    # ключ данных: debian | ubuntu | rhel | alt | astra | redos
    label: str                     # подпись в находках и отчётах
    manager: str                   # dpkg | rpm — по правилам какого менеджера сравнивать
    parser: Parser
    # Адрес выгрузки по умолчанию; {release} подставляется. Пусто — открытого
    # источника нет: оператор кладёт файл в ADVISORY_DIR или задаёт адрес сам.
    default_url: str = ""
    # Семейства osfamily, которые пользуются этими данными (RHEL-совместимые).
    host_families: tuple[str, ...] = ()
    # VERSION_ID / VERSION_CODENAME из os-release -> выпуск в данных вендора.
    release_of: Callable[[str | None, str | None], str | None] = lambda v, c: v
    note: str = ""


_ID_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")


def is_cve(value: str) -> bool:
    return bool(_ID_RE.match(value))


def major(version_id: str | None) -> str | None:
    """``9.3`` -> ``9``, ``8`` -> ``8``."""
    m = re.match(r"\d+", (version_id or "").strip())
    return m.group(0) if m else None
