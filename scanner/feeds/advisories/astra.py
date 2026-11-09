"""Astra Linux: бюллетени безопасности вендора в формате OVAL (dpkginfo).

Вендор публикует OVAL каталогом в Artifactory: https://dl.astralinux.ru/ui/native/al-oval/,
файл на выпуск в папке платформы: ``al-oval/1.8_x86-64/oval-definitions-alse-1.8.xml``
(~130 МБ). Файлы выпуска находятся по оглавлению каталога: сначала полный
список (API Artifactory ``api/storage/al-oval?list&deep=1``), а если он закрыт
или пуст — обходом папок (``api/storage/al-oval`` и папки с выпуском в имени,
затем HTML-листинг ``artifactory/al-oval/``). Берутся файлы
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
STORAGE = "https://dl.astralinux.ru/artifactory/api/storage/al-oval"
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


def _entries(data: bytes) -> list[tuple[str, bool]]:
    """(имя, папка?) из листинга папки: JSON api/storage или HTML."""
    try:
        doc = json.loads(data)
    except ValueError:
        doc = None
    if isinstance(doc, dict):
        return [(str(c.get("uri") or "").strip("/"), bool(c.get("folder")))
                for c in doc.get("children") or [] if isinstance(c, dict) and c.get("uri")]
    text = data.decode("utf-8", "replace")
    return [(h.strip("/"), h.endswith("/")) for h in re.findall(r'href="([^"?#]+)"', text)
            if not h.startswith(("..", "/", "http")) and h.strip("/")]


def _walk(release: str, read: Callable[[str], bytes], root: str) -> list[str]:
    """Обход двух уровней: корень, затем папки с номером выпуска в имени
    (``1.8_x86-64``). root — api/storage (JSON) или сам каталог (HTML)."""
    rel = re.escape(release)
    out: list[str] = []
    for name, folder in _entries(read(root)):
        if not folder:
            out.append(name)
        elif re.search(rf"(?<![\d.]){rel}(?!\d)", name):
            sub = f"{root.rstrip('/')}/{name}" + ("/" if root.endswith("/") else "")
            out += [f"{name}/{n}" for n, f in _entries(read(sub)) if not f]
    return out


def discover(release: str, read: Callable[[str], bytes]) -> list[str]:
    errors: list[str] = []
    for source in ("list", STORAGE, BASE):
        try:
            paths = _paths(read(INDEX)) if source == "list" else _walk(release, read, source)
        except Exception as e:  # noqa: BLE001 — следующий способ оглавления
            errors.append(str(e))
            continue
        files = select_files(paths, release)
        if files:
            return [urljoin(BASE, p) for p in files]
    if len(errors) == 3:
        raise RuntimeError("; ".join(dict.fromkeys(errors)))
    return []


SPEC = FamilySpec(
    family="astra", label="Astra Linux", manager="dpkg", parser=parse_oval,
    default_url=INDEX, discover=discover,
    host_families=("astra",), release_of=release_of,
    note="OVAL бюллетеней Astra Linux (каталог al-oval)")
