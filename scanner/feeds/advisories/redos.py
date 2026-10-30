"""РЕД ОС: бюллетени безопасности вендора в формате OVAL (rpminfo).

Открытого машиночитаемого адреса по умолчанию нет: оператор кладёт файл OVAL
в ADVISORY_DIR (``redos-7.3.xml``) или задаёт ADVISORY_URL_REDOS. Пока данных
нет, находки РЕД ОС остаются по версии апстрима с пометкой «нет данных вендора».
Выпуск — ``7.3``, ``8`` (``8.0`` -> ``8``).
"""
from __future__ import annotations

import re

from scanner.feeds.advisories.base import FamilySpec
from scanner.feeds.advisories.oval import parse_oval


def release_of(version_id: str | None, codename: str | None) -> str | None:
    m = re.match(r"\d+(\.\d+)?", (version_id or "").strip())
    if not m:
        return None
    v = m.group(0)
    return v.removesuffix(".0")


SPEC = FamilySpec(
    family="redos", label="РЕД ОС", manager="rpm", parser=parse_oval,
    host_families=("redos",), release_of=release_of,
    note="OVAL бюллетеней РЕД ОС (файл/адрес задаёт оператор)")
