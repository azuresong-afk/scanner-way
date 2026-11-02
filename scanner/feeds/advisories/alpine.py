"""Alpine Linux: secdb (secdb.alpinelinux.org, JSON).

Файл на выпуск и репозиторий (``v3.19/main.json``, ``v3.19/community.json``):
``{"distroversion": "v3.19", "packages": [{"pkg": {"name": "openssl",
"secfixes": {"3.1.4-r1": ["CVE-2023-5678"], "0": ["CVE-…"]}}}]}``.
Ключ ``secfixes`` — первая версия пакета (``ver-rN``), где CVE исправлена;
``0`` — пакет Alpine уязвимости не содержал (not affected). Открытых записей
secdb не публикует: CVE без исправления остаётся «нет данных вендора».
Выпуск — ``major.minor`` (VERSION_ID ``3.19.1`` -> ``3.19``).
"""
from __future__ import annotations

import json
import re
from collections.abc import Iterable, Iterator
from typing import IO

from scanner.feeds.advisories.base import FIXED, NOT_AFFECTED, Advisory, FamilySpec

_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}")


def release_of(version_id: str | None, codename: str | None) -> str | None:
    m = re.match(r"\d+\.\d+", (version_id or "").strip())
    return m.group(0) if m else None


def parse_secdb(stream: IO[bytes], family: str, releases: Iterable[str]) -> Iterator[Advisory]:
    wanted = list(releases)
    data = json.load(stream)
    if not isinstance(data, dict) or not isinstance(data.get("packages"), list):
        raise TypeError("secdb Alpine: ожидался JSON-объект с полем packages")
    file_release = str(data.get("distroversion") or "").strip().lstrip("v")
    if file_release and file_release in wanted:
        targets = [file_release]
    elif len(wanted) == 1:
        targets = wanted                # файл оператора без distroversion
    else:
        return
    for item in data["packages"]:
        pkg = item.get("pkg") if isinstance(item, dict) else None
        if not isinstance(pkg, dict) or not isinstance(pkg.get("secfixes"), dict):
            continue
        name = str(pkg.get("name") or "").strip()
        if not name:
            continue
        for version, ids in pkg["secfixes"].items():
            if not isinstance(ids, list):
                continue
            version = str(version).strip()
            cves = dict.fromkeys(c for x in ids for c in _CVE_RE.findall(str(x)))
            for cve in cves:
                for release in targets:
                    if version == "0":
                        yield Advisory(family, release, name, cve, NOT_AFFECTED)
                    else:
                        yield Advisory(family, release, name, cve, FIXED, version)


SPEC = FamilySpec(
    family="alpine", label="Alpine Linux", manager="apk", parser=parse_secdb,
    # Несколько адресов через пробел: данные выпуска — их объединение.
    default_url="https://secdb.alpinelinux.org/v{release}/main.json "
                "https://secdb.alpinelinux.org/v{release}/community.json",
    host_families=("alpine",), release_of=release_of, note="secdb Alpine (main, community)")
