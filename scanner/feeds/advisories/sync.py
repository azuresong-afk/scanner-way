"""Загрузка бюллетеней выбранных выпусков в хранилище.

Откуда берётся файл выпуска (по убыванию приоритета):
1. каталог ADVISORY_DIR (закрытый контур): ``<семейство>-<выпуск>.<расш>``,
   а для общего на все выпуски источника (трекер Debian) — ``<семейство>.<расш>``;
2. адрес ADVISORY_URL_<СЕМЕЙСТВО> или адрес вендора по умолчанию
   (``{release}`` подставляется; несколько адресов через пробел — данные
   выпуска собираются из всех, например main + community у Alpine;
   варианты через `` | `` — запасные: берётся первый, что скачался, например
   файл выпуска РЕД ОС, а если его нет — общий redos.xml).
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


def _download(url: str, dest: Path, *, allow_html: bool = False) -> None:
    from scanner.feeds.net import DownloadError, download
    try:
        download(url, dest, timeout=300, allow_html=allow_html)
    except DownloadError as e:
        raise AdvisoryError(f"не удалось скачать {e}") from e


def _download_index(url: str, dest: Path) -> None:
    """Оглавление каталога вендора может быть HTML-листингом."""
    _download(url, dest, allow_html=True)


def expand(template: str, spec: FamilySpec, release: str) -> list[tuple[tuple[str, ...], bool]]:
    """Шаблон адреса -> варианты по порядку: (адреса, файл только этого выпуска?).

    ``a b`` — данные из обоих адресов; ``a | b`` — b, только если a не скачался."""
    out: list[tuple[tuple[str, ...], bool]] = []
    for alt in template.split("|"):
        if not alt.strip():
            continue
        urls = tuple(u.replace("{release}", spec.url_release(release)) for u in alt.split())
        per_release = "{release}" in alt
        if (urls, per_release) not in out:
            out.append((urls, per_release))
    return out


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
    urls: tuple[str, ...] = ()
    index: str | None = None           # оглавление вендора (spec.discover)
    # Запасные варианты адресов (шаблон «a | b»), если не скачались urls.
    fallbacks: tuple[tuple[tuple[str, ...], bool], ...] = ()
    # Источник — файл одного выпуска (не общий на все): записи файла
    # относятся к нему целиком.
    per_release: bool = False

    @property
    def url(self) -> str | None:
        return self.urls[0] if self.urls else None

    @property
    def label(self) -> str:
        return self.path.name if self.path else (" ".join(self.urls) or self.index or "")


def plan(targets: list[tuple[str, str]], *, directory: Path | None,
         urls: dict[str, str]) -> tuple[list[Job], list[ReleaseResult]]:
    """Какие файлы/адреса загрузить для выпусков; выпуски без источника — ошибки."""
    jobs: dict[tuple[str, str], Job] = {}
    missing: list[ReleaseResult] = []
    for family, release in targets:
        spec = FAMILIES[family]
        local = local_file(directory, family, release)
        if local is not None:
            path, shared = local
            key = (family, str(path))
            jobs.setdefault(key, Job(spec, [], path=path, per_release=not shared)
                            ).releases.append(release)
            continue
        template = (urls.get(family) or spec.default_url).strip()
        if not template:
            missing.append(ReleaseResult(
                family, release, error=f"нет источника данных {spec.label}: положите файл "
                f"OVAL «{family}-{release}.xml» в каталог бюллетеней или задайте "
                f"ADVISORY_URL_{family.upper()}"))
            continue
        if spec.discover is not None and not urls.get(family):
            # оглавление вендора: файлы выпуска находятся при загрузке
            jobs[(family, f"{template}#{release}")] = Job(
                spec, [release], index=template.replace("{release}", release))
            continue
        variants = expand(template, spec, release)
        if not variants:
            missing.append(ReleaseResult(family, release,
                                         error=f"пустой адрес источника {spec.label}"))
            continue
        (job_urls, per_release), *rest = variants
        key = (family, " | ".join(" ".join(u) for u, _ in variants))
        jobs.setdefault(key, Job(spec, [], urls=job_urls, fallbacks=tuple(rest),
                                 per_release=per_release)).releases.append(release)
    return list(jobs.values()), missing


def _read_url(fetch: Callable[[str, Path], None], tmpdir: str) -> Callable[[str], bytes]:
    def read(url: str) -> bytes:
        p = Path(tmpdir) / "index"
        fetch(url, p)
        return p.read_bytes()
    return read


def _fetch_variants(job: Job, first: list[str], fetch: Callable[[str, Path], None],
                    tmp: Path) -> list[Path]:
    """Скачивает первый вариант адресов, что удался; ошибки всех — в одном сообщении."""
    variants = [(tuple(first), job.per_release), *job.fallbacks]
    errors: list[str] = []
    for n, (urls, per_release) in enumerate(variants):
        paths: list[Path] = []
        try:
            for i, url in enumerate(urls):
                p = tmp / f"payload{n}-{i}"
                fetch(url, p)
                paths.append(p)
        except Exception as e:  # noqa: BLE001 — пробуем следующий вариант
            errors.append(str(e) if isinstance(e, AdvisoryError) else f"{url}: {e}")
            continue
        job.urls, job.per_release = urls, per_release
        return paths
    if len(errors) == 1:
        raise AdvisoryError(errors[0])
    raise AdvisoryError("ни один адрес не скачался: " + "; ".join(errors))


def run_job(job: Job, store: AdvisoryStore,
            fetch: Callable[[str, Path], None] | None = None
            ) -> tuple[list[ReleaseResult], str]:
    """Загружает один файл (для одного или нескольких выпусков). -> (итоги, sha256).

    Выпуск, для которого в непустом файле не нашлось ни одной записи, не
    перезаписывается пустотой (вероятно, вендор поменял формат или разметку
    выпусков) — он возвращается с ошибкой, прежние данные остаются."""
    index_fetch = fetch or _download_index
    fetch = fetch or _download
    tmpdir: str | None = None
    try:
        paths: list[Path] = [job.path] if job.path is not None else []
        if not paths:
            tmpdir = tempfile.mkdtemp(prefix="advisory-")
            job_urls = list(job.urls)
            if job.index and job.spec.discover is not None:
                try:
                    job_urls = job.spec.discover(job.releases[0],
                                                 _read_url(index_fetch, tmpdir))
                except AdvisoryError:
                    raise
                except Exception as e:
                    raise AdvisoryError(f"оглавление {job.index} не читается: {e}") from e
                if not job_urls:
                    raise AdvisoryError(
                        f"в каталоге {job.index} нет файла OVAL для {job.spec.label} "
                        f"{job.releases[0]}: задайте ADVISORY_URL_{job.spec.family.upper()} "
                        "или положите файл в каталог бюллетеней")
                job.urls = tuple(job_urls)
            paths = _fetch_variants(job, job_urls, fetch, Path(tmpdir))
        digest = hashlib.sha256("".join(sha256(p) for p in paths).encode()).hexdigest() \
            if len(paths) > 1 else sha256(paths[0])
        parser = job.spec.parser
        if job.per_release and job.spec.release_parser is not None:
            parser = job.spec.release_parser
        buckets: dict[str, list[Advisory]] = defaultdict(list)
        for path in paths:
            with open_payload(path) as streams:
                for stream in streams:
                    for rec in parser(stream, job.spec.family, job.releases):
                        buckets[rec.release].append(rec)
        results = []
        total = sum(len(v) for v in buckets.values())
        if not total:
            # пустая выборка из скачанного файла — почти всегда не тот файл
            # (страница вместо данных, сменился формат); прежние данные не трогаем
            raise AdvisoryError(
                f"в файле {job.label} не найдено ни одной записи бюллетеней "
                f"{job.spec.label} — прежние данные оставлены (проверьте, что по адресу "
                "лежит OVAL/JSON вендора)")
        for release in job.releases:
            if total and not buckets.get(release):
                results.append(ReleaseResult(
                    job.spec.family, release, source=job.label,
                    error=f"в файле нет записей для выпуска {release} — прежние данные "
                          "оставлены"))
                continue
            n = store.replace_release(job.spec.family, release, buckets.get(release, []))
            results.append(ReleaseResult(job.spec.family, release, n, job.label))
        return results, digest
    finally:
        if tmpdir:
            shutil.rmtree(tmpdir, ignore_errors=True)


def sync_releases(store: AdvisoryStore, targets: list[tuple[str, str]], *,
                  directory: Path | None, urls: dict[str, str],
                  fetch: Callable[[str, Path], None] | None = None
                  ) -> tuple[list[ReleaseResult], str]:
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


@dataclass(slots=True)
class SourceCheck:
    family: str
    release: str
    ok: bool
    detail: str
    url: str = ""


def check_sources(targets: list[tuple[str, str]], *, directory: Path | None,
                  urls: dict[str, str],
                  probe: Callable[[str], tuple[int, str, bytes]] | None = None,
                  read: Callable[[str], bytes] | None = None) -> list[SourceCheck]:
    """Доступны ли источники выпусков, без загрузки в справочник: адрес отвечает
    и отдаёт данные (XML/JSON/архив), а не HTML. Для каталога вендора (Astra)
    проверяется, что в оглавлении находится файл выпуска."""
    from scanner.feeds import net
    probe = probe or net.probe

    def _read(url: str) -> bytes:
        with tempfile.TemporaryDirectory(prefix="advisory-check-") as d:
            p = Path(d) / "index"
            _download_index(url, p)
            return p.read_bytes()

    read = read or _read
    jobs, missing = plan(targets, directory=directory, urls=urls)
    out = [SourceCheck(m.family, m.release, False, m.error or "") for m in missing]
    for job in jobs:
        for release in job.releases:
            if job.path is not None:
                out.append(SourceCheck(job.spec.family, release, True,
                                       f"локальный файл {job.path}", str(job.path)))
                continue
            variants = [(job.urls, job.per_release), *job.fallbacks]
            if job.index and job.spec.discover is not None:
                try:
                    found = job.spec.discover(release, read)
                except Exception as e:  # noqa: BLE001
                    out.append(SourceCheck(job.spec.family, release, False,
                                           f"оглавление {job.index}: {e}", job.index))
                    continue
                if not found:
                    out.append(SourceCheck(job.spec.family, release, False,
                                           f"в оглавлении {job.index} нет файла выпуска",
                                           job.index))
                    continue
                variants = [(tuple(found), True)]
            errors: list[str] = []
            for urls_, _per in variants:
                bad = None
                for url in urls_:
                    try:
                        code, ctype, head = probe(url)
                    except Exception as e:  # noqa: BLE001
                        bad = str(e)
                        break
                    kind = net.kind_of(head)
                    if code >= 400:
                        bad = f"{url}: HTTP {code}"
                        break
                    if kind in ("html", "?"):
                        bad = (f"{url}: HTTP {code}, но вместо данных "
                               f"{'HTML-страница' if kind == 'html' else 'неизвестный формат'}"
                               f" ({ctype or 'без Content-Type'})")
                        break
                if bad is None:
                    out.append(SourceCheck(
                        job.spec.family, release, True,
                        "доступен" + (" (запасной адрес)" if errors else ""),
                        " ".join(urls_)))
                    break
                errors.append(bad)
            else:
                out.append(SourceCheck(job.spec.family, release, False, "; ".join(errors)))
    return out
