"""Загрузка бюллетеней выбранных выпусков в хранилище.

Откуда берётся файл выпуска (по убыванию приоритета):
1. каталог ADVISORY_DIR (закрытый контур): ``<семейство>-<выпуск>.<расш>``,
   а для общего на все выпуски источника (трекер Debian) — ``<семейство>.<расш>``;
2. адрес ADVISORY_URL_<СЕМЕЙСТВО> или адрес вендора по умолчанию
   (``{release}`` подставляется).
Сжатие (bz2, gzip, zip) определяется по содержимому, не по имени.
"""
from __future__ import annotations

import bz2
import gzip
import hashlib
import shutil
import tempfile
import zipfile
from collections import defaultdict
from collections.abc import Callable, Iterator
from contextlib import ExitStack, contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import IO

from scanner.feeds.advisories import FAMILIES
from scanner.feeds.advisories.base import Advisory, FamilySpec
from scanner.feeds.advisories.store import AdvisoryStore

EXTENSIONS = ("", ".xml", ".xml.bz2", ".xml.gz", ".json", ".json.bz2", ".json.gz",
              ".bz2", ".gz", ".zip")


class AdvisoryError(Exception):
    """Понятная оператору причина, почему бюллетени не загрузились."""


@dataclass(slots=True)
class ReleaseResult:
    family: str
    release: str
    count: int = 0
    source: str = ""
    error: str | None = None


def parse_targets(text: str) -> list[tuple[str, str]]:
    """``debian:bookworm, rhel:9`` -> [("debian", "bookworm"), ("rhel", "9")]."""
    out: list[tuple[str, str]] = []
    for item in text.replace(";", ",").split(","):
        item = item.strip()
        if not item:
            continue
        family, sep, release = item.partition(":")
        family, release = family.strip().lower(), release.strip()
        if not sep or not release:
            raise AdvisoryError(f"выпуск «{item}»: нужен формат семейство:выпуск "
                                "(debian:bookworm)")
        if family not in FAMILIES:
            raise AdvisoryError(f"семейство «{family}» не поддержано; есть: "
                                + ", ".join(FAMILIES))
        if (family, release) not in out:
            out.append((family, release))
    return out


def local_file(directory: Path | None, family: str, release: str) -> tuple[Path, bool] | None:
    """(файл, общий на все выпуски?) в каталоге оператора."""
    if directory is None or not directory.is_dir():
        return None
    for stem, shared in ((f"{family}-{release}", False), (family, True)):
        for ext in EXTENSIONS:
            p = directory / f"{stem}{ext}"
            if p.is_file():
                return p, shared
    return None


def _download(url: str, dest: Path) -> None:
    import httpx
    try:
        with httpx.stream("GET", url, timeout=300, follow_redirects=True) as resp:
            resp.raise_for_status()
            with dest.open("wb") as fh:
                for chunk in resp.iter_bytes(1 << 20):
                    fh.write(chunk)
    except httpx.HTTPError as e:
        raise AdvisoryError(f"не удалось скачать {url}: {type(e).__name__}: {e}") from e


@contextmanager
def open_payload(path: Path) -> Iterator[list[IO[bytes]]]:
    """Потоки данных файла: распакованный bz2/gzip или каждый файл zip-архива."""
    with path.open("rb") as fh:
        magic = fh.read(4)
    with ExitStack() as stack:
        if magic.startswith(b"PK"):
            zf = stack.enter_context(zipfile.ZipFile(path))
            yield [stack.enter_context(zf.open(n)) for n in zf.namelist()
                   if not n.endswith("/") and n.lower().endswith((".xml", ".json"))]
        elif magic.startswith(b"BZh"):
            yield [stack.enter_context(bz2.BZ2File(path, "rb"))]  # type: ignore[list-item]
        elif magic.startswith(b"\x1f\x8b"):
            yield [stack.enter_context(gzip.GzipFile(path, "rb"))]  # type: ignore[arg-type]
        else:
            yield [stack.enter_context(path.open("rb"))]


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


@dataclass(slots=True)
class Job:
    spec: FamilySpec
    releases: list[str]
    path: Path | None = None
    url: str | None = None

    @property
    def label(self) -> str:
        return self.path.name if self.path else (self.url or "")


def plan(targets: list[tuple[str, str]], *, directory: Path | None,
         urls: dict[str, str]) -> tuple[list[Job], list[ReleaseResult]]:
    """Какие файлы/адреса загрузить для выпусков; выпуски без источника — ошибки."""
    jobs: dict[tuple[str, str], Job] = {}
    missing: list[ReleaseResult] = []
    for family, release in targets:
        spec = FAMILIES[family]
        local = local_file(directory, family, release)
        if local is not None:
            path, _shared = local
            key = (family, str(path))
            jobs.setdefault(key, Job(spec, [], path=path)).releases.append(release)
            continue
        template = (urls.get(family) or spec.default_url).strip()
        if not template:
            missing.append(ReleaseResult(
                family, release, error=f"нет источника данных {spec.label}: положите файл "
                f"OVAL «{family}-{release}.xml» в каталог бюллетеней или задайте "
                f"ADVISORY_URL_{family.upper()}"))
            continue
        url = template.replace("{release}", release)
        jobs.setdefault((family, url), Job(spec, [], url=url)).releases.append(release)
    return list(jobs.values()), missing


def run_job(job: Job, store: AdvisoryStore,
            fetch: Callable[[str, Path], None] = _download) -> tuple[list[ReleaseResult], str]:
    """Загружает один файл (для одного или нескольких выпусков). -> (итоги, sha256)."""
    tmpdir: str | None = None
    try:
        path = job.path
        if path is None:
            tmpdir = tempfile.mkdtemp(prefix="advisory-")
            path = Path(tmpdir) / "payload"
            fetch(job.url or "", path)
        digest = sha256(path)
        buckets: dict[str, list[Advisory]] = defaultdict(list)
        with open_payload(path) as streams:
            for stream in streams:
                for rec in job.spec.parser(stream, job.spec.family, job.releases):
                    buckets[rec.release].append(rec)
        results = []
        for release in job.releases:
            n = store.replace_release(job.spec.family, release, buckets.get(release, []))
            results.append(ReleaseResult(job.spec.family, release, n, job.label))
        return results, digest
    finally:
        if tmpdir:
            shutil.rmtree(tmpdir, ignore_errors=True)


def sync_releases(store: AdvisoryStore, targets: list[tuple[str, str]], *,
                  directory: Path | None, urls: dict[str, str],
                  fetch: Callable[[str, Path], None] = _download) -> tuple[list[ReleaseResult], str]:
    """Загружает все выпуски; ошибка одного файла не мешает остальным.
    -> (итоги по выпускам, общий отпечаток загруженных файлов)."""
    jobs, results = plan(targets, directory=directory, urls=urls)
    digests: list[str] = []
    for job in jobs:
        try:
            res, digest = run_job(job, store, fetch)
            results.extend(res)
            digests.append(f"{job.spec.family}:{','.join(job.releases)}:{digest}")
        except Exception as e:  # noqa: BLE001 — итог по выпуску, остальные грузим
            msg = str(e) if isinstance(e, AdvisoryError) else f"{type(e).__name__}: {e}"
            results.extend(ReleaseResult(job.spec.family, r, source=job.label,
                                         error=msg[:300]) for r in job.releases)
    fp = hashlib.sha256("\n".join(sorted(digests)).encode()).hexdigest() if digests else ""
    return results, fp
