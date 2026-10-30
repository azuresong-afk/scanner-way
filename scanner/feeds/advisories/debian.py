"""Debian: трекер безопасности (security-tracker.debian.org, JSON).

Один файл на все выпуски: ``{исходный пакет: {CVE: {"releases": {кодовое имя:
{"status": resolved|open|undetermined, "fixed_version": "…"}}}}}``.
``fixed_version`` = ``0`` — пакет выпуска уязвимости не содержал (not affected);
``undetermined`` — вендор ещё не разобрал, такие записи не сохраняются (нет данных).
Имена пакетов — исходные (source), поэтому инвентаризация читает и
``${source:Package}`` установленного пакета.
"""
from __future__ import annotations

import json
from collections.abc import Iterable, Iterator
from typing import IO

from scanner.feeds.advisories.base import (
    FIXED,
    NOT_AFFECTED,
    OPEN,
    Advisory,
    FamilySpec,
    is_cve,
    major,
)

CODENAMES = {"9": "stretch", "10": "buster", "11": "bullseye", "12": "bookworm",
             "13": "trixie", "14": "forky"}


def release_of(version_id: str | None, codename: str | None) -> str | None:
    if codename and codename.strip():
        return codename.strip().lower()
    return CODENAMES.get(major(version_id) or "")


def parse_tracker(stream: IO[bytes], family: str, releases: Iterable[str]) -> Iterator[Advisory]:
    wanted = set(releases)
    data = json.load(stream)
    if not isinstance(data, dict):
        raise TypeError("трекер Debian: ожидался JSON-объект {пакет: {CVE: …}}")
    for package, cves in data.items():
        if not isinstance(cves, dict):
            continue
        for cve, info in cves.items():
            if not is_cve(cve) or not isinstance(info, dict):
                continue
            for release, st in (info.get("releases") or {}).items():
                if release not in wanted or not isinstance(st, dict):
                    continue
                status, fixed = st.get("status"), st.get("fixed_version")
                if fixed == "0":
                    yield Advisory(family, release, package, cve, NOT_AFFECTED)
                elif status == "resolved" and fixed:
                    yield Advisory(family, release, package, cve, FIXED, str(fixed))
                elif status == "open":
                    yield Advisory(family, release, package, cve, OPEN)


SPEC = FamilySpec(
    family="debian", label="Debian", manager="dpkg", parser=parse_tracker,
    default_url="https://security-tracker.debian.org/tracker/data/json",
    host_families=("debian",), release_of=release_of,
    note="трекер безопасности Debian (DSA/DLA)")
