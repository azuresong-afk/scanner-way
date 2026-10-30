"""Astra Linux: бюллетени безопасности вендора в формате OVAL (dpkginfo).

Открытого машиночитаемого адреса по умолчанию нет: оператор кладёт файл OVAL
в ADVISORY_DIR (``astra-1.7.xml``) или задаёт ADVISORY_URL_ASTRA. Пока данных
нет, находки Astra остаются по версии апстрима с пометкой «нет данных вендора».
Выпуск — ``major.minor`` (VERSION_ID ``1.7_x86-64`` -> ``1.7``).
"""
from __future__ import annotations

import re

from scanner.feeds.advisories.base import FamilySpec
from scanner.feeds.advisories.oval import parse_oval


def release_of(version_id: str | None, codename: str | None) -> str | None:
    m = re.match(r"\d+\.\d+", (version_id or "").strip())
    return m.group(0) if m else None


SPEC = FamilySpec(
    family="astra", label="Astra Linux", manager="dpkg", parser=parse_oval,
    host_families=("astra",), release_of=release_of,
    note="OVAL бюллетеней Astra Linux (файл/адрес задаёт оператор)")
