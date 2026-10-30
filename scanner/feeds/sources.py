"""Источники справочников для автообновления: БДУ ФСТЭК, NVD, шаблоны Nuclei.

Каждый источник — функция-загрузчик `(FeedContext) -> FeedResult`; планировщик
(`scanner.feeds.scheduler`) вызывает их по расписанию, а «Обновить сейчас» в
API — вручную. Загрузчики вызывают те же классы, что и CLI
(`scanner feeds sync-bdu / sync-nvd`). Новый источник (бюллетени дистрибутивов,
EPSS, KEV) подключается добавлением записи в `SOURCES` — без правок планировщика.

Адреса и ключи берутся из окружения (`scanner.core.config.settings`):
NVD_API_KEY, BDU_FSTEC_FEED_PATH, BDU_FSTEC_FEED_URL, NUCLEI_TEMPLATES_DIR.
"""
from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
import tempfile
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

from sqlalchemy.engine import Engine

from scanner.core.audit import AuditSink
from scanner.core.config import settings

# NVD отвергает период lastMod длиннее 120 суток — режем с запасом.
NVD_MAX_WINDOW = timedelta(days=100)
# Окно инкремента начинается чуть раньше прошлой успешной загрузки: запись,
# изменённая во время самой загрузки, иначе могла бы потеряться.
NVD_OVERLAP = timedelta(hours=1)
NUCLEI_TIMEOUT_SECONDS = 1800


class FeedError(Exception):
    """Понятная оператору причина, почему справочник не обновился."""


@dataclass(slots=True)
class FeedContext:
    engine: Engine
    audit: AuditSink
    now: datetime
    last_success_at: datetime | None = None
    fingerprint: str | None = None          # отпечаток последней загруженной выгрузки
    actor: str = "feeds:scheduler"


@dataclass(slots=True)
class FeedResult:
    count: int | None = None
    message: str = ""
    unchanged: bool = False
    fingerprint: str | None = None


Loader = Callable[[FeedContext], FeedResult]


@dataclass(frozen=True, slots=True)
class FeedSource:
    id: str
    title: str
    loader: Loader
    # Расписание по умолчанию для строки, создаваемой при первом старте.
    kind: str = "daily"
    time_of_day: str = "03:00"
    weekdays: tuple[int, ...] = ()
    description: str = ""


# ---------- БДУ ФСТЭК ----------
def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _download(url: str, dest: Path, what: str = "выгрузку БДУ") -> None:
    import httpx
    try:
        with httpx.stream("GET", url, timeout=120, follow_redirects=True) as resp:
            resp.raise_for_status()
            with dest.open("wb") as fh:
                for chunk in resp.iter_bytes(1 << 20):
                    fh.write(chunk)
    except httpx.HTTPError as e:
        raise FeedError(f"не удалось скачать {what}: {type(e).__name__}: {e}") from e


def load_bdu(ctx: FeedContext) -> FeedResult:
    from scanner.feeds.bdu_fstec import BduFstecFeed
    from scanner.feeds.store import SqlReferenceStore

    url = settings.bdu_fstec_feed_url.strip()
    tmpdir: str | None = None
    try:
        if url:
            tmpdir = tempfile.mkdtemp(prefix="bdu-")
            path = Path(tmpdir) / "vullist.xlsx"
            _download(url, path)
        else:
            path = Path(settings.bdu_fstec_feed_path)
            if not path.is_file():
                raise FeedError(
                    f"файл выгрузки БДУ не найден: {path} (положите vullist.xlsx в ./data "
                    "или задайте BDU_FSTEC_FEED_URL)")
        fingerprint = _sha256(path)
        if fingerprint == ctx.fingerprint:
            return FeedResult(message="Выгрузка не изменилась с прошлой загрузки",
                              unchanged=True, fingerprint=fingerprint)
        n = BduFstecFeed(str(path)).sync(SqlReferenceStore(ctx.engine))
        return FeedResult(count=n, message=f"Загружено записей БДУ: {n}",
                          fingerprint=fingerprint)
    finally:
        if tmpdir:
            shutil.rmtree(tmpdir, ignore_errors=True)


# ---------- NVD ----------
def nvd_windows(since: datetime, until: datetime,
                step: timedelta = NVD_MAX_WINDOW) -> list[tuple[datetime, datetime]]:
    """Делит период изменения CVE на куски не длиннее `step` (лимит NVD — 120 суток)."""
    out, start = [], since
    while start < until:
        end = min(start + step, until)
        out.append((start, end))
        start = end
    return out


def load_nvd(ctx: FeedContext) -> FeedResult:
    """Первый раз — полная выгрузка, дальше — только изменённые с прошлой успешной
    загрузки CVE (инкремент по lastModStartDate/lastModEndDate)."""
    from scanner.feeds.nvd import NvdFeed
    from scanner.feeds.store import SqlReferenceStore

    feed = NvdFeed(settings.nvd_api_key, audit=ctx.audit)
    store = SqlReferenceStore(ctx.engine)
    try:
        if ctx.last_success_at is None:
            n = feed.sync(store, records=feed.iter_api())
            return FeedResult(count=n, message=f"Полная загрузка NVD: {n} CVE")
        since = ctx.last_success_at.astimezone(UTC) - NVD_OVERLAP
        n = 0
        for start, end in nvd_windows(since, ctx.now):
            n += feed.sync(store, records=feed.iter_api(last_mod_start=start,
                                                        last_mod_end=end))
    except Exception as e:
        if isinstance(e, FeedError):
            raise
        raise FeedError(f"NVD: {type(e).__name__}: {e}") from e
    return FeedResult(
        count=n, message=f"Обновлено CVE за период с {since:%Y-%m-%d %H:%M} UTC: {n}")


# ---------- Шаблоны Nuclei ----------
def nuclei_templates_dir() -> Path:
    if settings.nuclei_templates_dir:
        return Path(settings.nuclei_templates_dir)
    return Path(os.environ.get("HOME") or "/root") / "nuclei-templates"


def count_templates(directory: Path) -> int:
    return sum(1 for _ in directory.rglob("*.yaml")) if directory.is_dir() else 0


def load_nuclei(ctx: FeedContext) -> FeedResult:
    binary = shutil.which("nuclei")
    if binary is None:
        raise FeedError("nuclei не установлен в этом окружении")
    try:
        proc = subprocess.run(
            [binary, "-update-templates", "-disable-update-check"],
            capture_output=True, text=True, timeout=NUCLEI_TIMEOUT_SECONDS, check=False)
    except subprocess.TimeoutExpired as e:
        raise FeedError("обновление шаблонов Nuclei не уложилось во время") from e
    if proc.returncode != 0:
        tail = "\n".join((proc.stderr or proc.stdout or "").strip().splitlines()[-3:])
        raise FeedError(f"nuclei завершился с кодом {proc.returncode}: {tail}"[:500])
    total = count_templates(nuclei_templates_dir())
    return FeedResult(count=total, message=f"Шаблонов Nuclei на диске: {total}")


# ---------- EPSS и CISA KEV (приоритизация риска, R6) ----------
def _fetch_bytes(path: str, url: str, what: str) -> bytes:
    """Файл из *_PATH (закрытый контур) либо скачивание по *_URL."""
    if path.strip():
        p = Path(path.strip())
        if not p.is_file():
            raise FeedError(f"файл {what} не найден: {p}")
        return p.read_bytes()
    if not url.strip():
        raise FeedError(f"не задан адрес или путь к {what}")
    tmpdir = tempfile.mkdtemp(prefix="feed-")
    try:
        dest = Path(tmpdir) / "feed.bin"
        _download(url.strip(), dest, what)
        return dest.read_bytes()
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


def load_epss(ctx: FeedContext) -> FeedResult:
    from scanner.feeds.epss import parse_epss, sync_epss

    data = _fetch_bytes(settings.epss_feed_path, settings.epss_feed_url, "выгрузку EPSS")
    fingerprint = hashlib.sha256(data).hexdigest()
    if fingerprint == ctx.fingerprint:
        return FeedResult(message="Выгрузка EPSS не изменилась с прошлой загрузки",
                          unchanged=True, fingerprint=fingerprint)
    try:
        rows, as_of = parse_epss(data)
    except (OSError, EOFError, UnicodeDecodeError) as e:
        raise FeedError(f"выгрузка EPSS не читается: {type(e).__name__}: {e}") from e
    if not rows:
        raise FeedError("в выгрузке EPSS нет ни одной записи — справочник не изменён")
    n = sync_epss(ctx.engine, rows, as_of)
    return FeedResult(count=n, message=f"Загружено оценок EPSS: {n}", fingerprint=fingerprint)


def load_kev(ctx: FeedContext) -> FeedResult:
    from scanner.feeds.kev import parse_kev, sync_kev

    data = _fetch_bytes(settings.kev_feed_path, settings.kev_feed_url, "каталог CISA KEV")
    fingerprint = hashlib.sha256(data).hexdigest()
    if fingerprint == ctx.fingerprint:
        return FeedResult(message="Каталог KEV не изменился с прошлой загрузки",
                          unchanged=True, fingerprint=fingerprint)
    try:
        entries = parse_kev(data)
    except ValueError as e:     # JSONDecodeError — его подкласс
        raise FeedError(f"каталог KEV не читается: {e}") from e
    if not entries:
        raise FeedError("в каталоге KEV нет ни одной записи — справочник не изменён")
    n = sync_kev(ctx.engine, entries)
    return FeedResult(count=n, message=f"Загружено записей KEV: {n}", fingerprint=fingerprint)


SOURCES: dict[str, FeedSource] = {s.id: s for s in (
    FeedSource("bdu", "БДУ ФСТЭК", load_bdu, kind="weekly", time_of_day="04:00",
               weekdays=(0,), description="Выгрузка vullist.xlsx → справочник БДУ"),
    FeedSource("nvd", "NVD (CVE)", load_nvd, kind="daily", time_of_day="03:00",
               description="Инкрементально: только изменённые с прошлой загрузки CVE"),
    FeedSource("nuclei", "Шаблоны Nuclei", load_nuclei, kind="daily", time_of_day="05:00",
               description="nuclei -update-templates"),
    FeedSource("epss", "EPSS (вероятность эксплуатации)", load_epss, kind="daily",
               time_of_day="02:00", description="FIRST EPSS: CSV → таблица epss_score"),
    FeedSource("kev", "CISA KEV (эксплуатируемые уязвимости)", load_kev, kind="daily",
               time_of_day="02:30", description="Каталог CISA KEV (JSON) → таблица kev"),
)}
