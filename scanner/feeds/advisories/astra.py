"""Astra Linux: бюллетени безопасности вендора в формате OVAL (dpkginfo).

Вендор публикует OVAL каталогом в Artifactory: https://dl.astralinux.ru/ui/native/al-oval/.
Файлы выпуска находятся по оглавлению каталога (API Artifactory
``api/storage/al-oval?list&deep=1``, либо HTML-листинг): берутся файлы
``.xml[.bz2|.gz]`` / ``.zip``, в пути которых есть номер выпуска (``1.7``).
Если есть файл ровно на выпуск (``…1.7.xml``) — берётся он, иначе все файлы
обновлений выпуска (``1.7.5``, ``1.7.6``…): решение по пакету тогда
консервативно — сравнивается с наибольшей исправленной версией.

Свой адрес — ADVISORY_URL_ASTRA (прямой файл, ``{release}`` подставляется),
закрытый контур — файл ``astra-1.7.xml`` в ADVISORY_DIR.
Выпуск — ``major.minor`` (VERSION_ID ``1.7_x86-64`` -> ``1.7``).
"""
from __future__ import annotations

import json
import re
from collections.abc import Callable
from urllib.parse import urljoin

from scanner.feeds.advisories.base import FamilySpec
from scanner.feeds.advisories.oval import parse_oval

BASE = "https://dl.astralinux.ru/artifactory/al-oval/"
INDEX = "https://dl.astralinux.ru/artifactory/api/storage/al-oval?list&deep=1&listFolders=0"
_EXT_RE = re.compile(r"\.(xml(\.bz2|\.gz)?|zip)$", re.IGNORECASE)
MAX_FILES = 12


def release_of(version_id: str | None, codename: str | None) -> str | None:
    m = re.match(r"\d+\.\d+", (version_id or "").strip())
    return m.group(0) if m else None


def _paths(data: bytes) -> list[str]:
    """Пути файлов из оглавления: JSON Artifactory или HTML-листинг."""
    try:
        doc = json.loads(data)
    except ValueError:
        doc = None
    if isinstance(doc, dict):
        out = [str(f.get("uri") or "") for f in doc.get("files") or []
               if isinstance(f, dict)]
        out += [str(c.get("uri") or "") for c in doc.get("children") or []
                if isinstance(c, dict) and not c.get("folder")]
        return [p.lstrip("/") for p in out if p]
    text = data.decode("utf-8", "replace")
    return [h for h in re.findall(r'href="([^"?#]+)"', text) if not h.startswith("..")]


def select_files(paths: list[str], release: str) -> list[str]:
    rel = re.escape(release)
    matched = [p for p in paths if _EXT_RE.search(p)
               and re.search(rf"(?<![\d.]){rel}(?!\d)", p)]
    exact = [p for p in matched if re.search(rf"(?<![\d.]){rel}(?!\d|\.\d)", p)]
    return sorted(exact or matched)[-MAX_FILES:]


def discover(release: str, read: Callable[[str], bytes]) -> list[str]:
    files = select_files(_paths(read(INDEX)), release)
    return [urljoin(BASE, p) for p in files]


SPEC = FamilySpec(
    family="astra", label="Astra Linux", manager="dpkg", parser=parse_oval,
    default_url=INDEX, discover=discover,
    host_families=("astra",), release_of=release_of,
    note="OVAL бюллетеней Astra Linux (каталог al-oval)")
