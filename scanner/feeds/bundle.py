"""Комплект данных уязвимостей для поставки: снимок справочников одним файлом.

Зачем. Без комплекта каждая новая установка качает справочники с нуля: полная
выгрузка NVD через API, БДУ, бюллетени всех выпусков ОС. Комплект
(`scanner-data-<дата>.tar`) собирается один раз — на эталонном стенде командой
`scanner bundle export` или в CI — и импортируется при первом старте
(`docker/entrypoint.sh` → `scanner bundle import --auto`) за минуты и без
интернета. Даты загрузки из комплекта записываются в feed_sync как «последняя
успешная загрузка», поэтому дальше автообновление докачивает только изменения:
NVD и MSRC — инкрементом с даты комплекта, остальные источники (выгрузки
целиком) не перезагружаются, пока файл у вендора не изменился (отпечаток).

Формат (tar без сжатия, внутри сжатые gzip части):

    manifest.json                  — версия формата, дата, источники, суммы
    NOTICE.txt                     — источники данных и условия их использования
    data/<таблица>.jsonl.gz        — строки таблицы, по одной JSON-строке
    nuclei-templates.tar.gz        — шаблоны Nuclei (необязательно)

Импорт источника идёт в одной транзакции (старые строки источника удаляются,
новые вставляются, контрольная сумма сверяется до фиксации): сканер, читающий
справочник во время импорта, видит либо старые данные, либо новые. Источник,
локальные данные которого новее комплекта, не трогается (кроме --force).
"""
from __future__ import annotations

import gzip
import hashlib
import io
import json
import os
import shutil
import tarfile
import tempfile
from collections.abc import Iterable, Iterator, Sequence
from dataclasses import dataclass, field
from datetime import UTC, date, datetime
from decimal import Decimal
from pathlib import Path, PurePosixPath
from typing import Any

from sqlalchemy import DateTime, Numeric, Table, delete, func, insert, select, update
from sqlalchemy.engine import Connection, Engine

from scanner.core.db import (
    DistroAdvisoryRow,
    FeedSync,
    make_session_factory,
    session_scope,
)
from scanner.feeds.msrc import msrc_fix
from scanner.feeds.store import (
    bdu_cve,
    bdu_entry,
    epss_score,
    kev,
    nvd_cpe_match,
    nvd_cve,
)

FORMAT = 1
KIND = "scanner-data-bundle"
MANIFEST = "manifest.json"
NOTICE = "NOTICE.txt"
NUCLEI_MEMBER = "nuclei-templates.tar.gz"
BATCH = 5000
# Где entrypoint ищет комплект: том данных и каталог в образе (вшитый при сборке).
DEFAULT_DIRS = ("/data/bundle", "/app/docker/data-bundle")
FILE_GLOB = "scanner-data-*.tar"


class BundleError(Exception):
    """Понятная оператору причина, почему комплект не собран или не загружен."""


@dataclass(frozen=True, slots=True)
class BundleSource:
    id: str                     # совпадает с id источника автообновления (feed_sync)
    title: str
    tables: tuple[Table, ...]   # первая — основная (по ней «есть ли данные»)
    notice: str


_ADV: Table = DistroAdvisoryRow.__table__  # type: ignore[assignment]

SOURCES: dict[str, BundleSource] = {s.id: s for s in (
    BundleSource("bdu", "БДУ ФСТЭК", (bdu_entry,),
                 "Банк данных угроз безопасности информации ФСТЭК России, "
                 "https://bdu.fstec.ru. Условия передачи третьим лицам на сайте явно не "
                 "указаны: перед передачей комплекта за пределы организации уточните их."),
    BundleSource("nvd", "NVD (CVE)", (nvd_cve, nvd_cpe_match),
                 "This product uses data from the NVD API but is not endorsed or "
                 "certified by the NVD. https://nvd.nist.gov (public domain, U.S. Gov)."),
    BundleSource("epss", "EPSS", (epss_score,),
                 "EPSS (Exploit Prediction Scoring System), FIRST.org, "
                 "https://www.first.org/epss — свободное использование со ссылкой на FIRST."),
    BundleSource("kev", "CISA KEV", (kev,),
                 "CISA Known Exploited Vulnerabilities Catalog, https://www.cisa.gov/kev "
                 "(общественное достояние, U.S. Gov)."),
    BundleSource("msrc", "Обновления Microsoft (MSRC)", (msrc_fix,),
                 "Microsoft Security Response Center, https://msrc.microsoft.com "
                 "(условия использования API MSRC)."),
    BundleSource("advisories", "Бюллетени дистрибутивов", (_ADV,),
                 "Бюллетени вендоров ОС: Debian Security Tracker; Ubuntu OVAL "
                 "(Canonical); Red Hat OVAL (CC BY 4.0); ALT Linux; Alpine secdb; "
                 "Astra Linux al-oval; РЕД ОС redos.xml. Для Astra Linux и РЕД ОС "
                 "условия передачи третьим лицам явно не указаны — уточните перед "
                 "передачей комплекта за пределы организации."),
)}

NUCLEI_NOTICE = ("Шаблоны Nuclei: ProjectDiscovery nuclei-templates, "
                 "https://github.com/projectdiscovery/nuclei-templates (MIT).")

# Суррогатные ключи и служебные колонки не переносятся: их назначит база.
_SKIP_COLUMNS = {"id"}


# ---------- общие помощники ----------
def _columns(table: Table) -> list[str]:
    return [c.name for c in table.columns
            if not (c.primary_key and c.name in _SKIP_COLUMNS)]


def _to_json(v: Any) -> Any:
    if isinstance(v, Decimal):
        return str(v)
    if isinstance(v, datetime):
        if v.tzinfo is None:
            v = v.replace(tzinfo=UTC)
        return v.isoformat()
    if isinstance(v, date):
        return v.isoformat()
    if isinstance(v, (list, tuple)):
        return list(v)
    return v


def _converters(table: Table) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for c in table.columns:
        t = c.type
        if isinstance(t, DateTime):
            out[c.name] = _parse_dt
        elif isinstance(t, Numeric):
            out[c.name] = lambda v: None if v is None else Decimal(str(v))
    return out


def _parse_dt(v: Any) -> datetime | None:
    if v is None or v == "":
        return None
    dt = datetime.fromisoformat(str(v))
    return dt if dt.tzinfo else dt.replace(tzinfo=UTC)


def _iso(dt: datetime | None) -> str | None:
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt.astimezone(UTC).isoformat()


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _table_exists(engine_or_conn: Engine | Connection, table: Table) -> bool:
    from sqlalchemy import inspect
    return inspect(engine_or_conn).has_table(table.name)


def _ensure_tables(engine: Engine, tables: Iterable[Table]) -> None:
    """В Postgres таблицы создают миграции; в SQLite (офлайн, тесты) — здесь."""
    if engine.dialect.name == "postgresql":
        return
    for t in tables:
        t.create(engine, checkfirst=True)
    bdu_cve.create(engine, checkfirst=True)


def _feed_rows(engine: Engine) -> dict[str, FeedSync]:
    sessions = make_session_factory(engine)
    with session_scope(sessions) as s:
        rows = {r.source: r for r in s.scalars(select(FeedSync))}
        for r in rows.values():
            s.expunge(r)
    return rows


# ---------- сборка ----------
@dataclass(slots=True)
class ExportResult:
    path: Path
    manifest: dict[str, Any]
    skipped: list[str] = field(default_factory=list)   # источники без данных


def _as_of(engine: Engine, src: BundleSource, feed: FeedSync | None,
           now: datetime) -> datetime:
    """Граница «данные актуальны на»: дата последней успешной загрузки.

    Если источник грузили не через автообновление (CLI `feeds sync-nvd`), даты
    в feed_sync нет. Для NVD тогда берётся самая поздняя дата изменения CVE в
    справочнике — с неё инкремент гарантированно ничего не пропустит; для
    остальных (выгрузки целиком, инкремента нет) — момент сборки."""
    if feed is not None and feed.last_success_at is not None:
        return feed.last_success_at
    if src.id == "nvd":
        with engine.connect() as c:
            latest = c.scalar(select(func.max(nvd_cve.c.updated_at)))
        if latest is not None:
            return latest if latest.tzinfo else latest.replace(tzinfo=UTC)
    return now


def _dump_table(conn: Connection, table: Table, dest: Path) -> int:
    cols = _columns(table)
    n = 0
    with gzip.open(dest, "wt", encoding="utf-8", compresslevel=6) as fh:
        result = conn.execution_options(stream_results=True, yield_per=BATCH).execute(
            select(*[table.c[c] for c in cols]))
        for row in result:
            fh.write(json.dumps([_to_json(v) for v in row], ensure_ascii=False,
                                separators=(",", ":")))
            fh.write("\n")
            n += 1
    return n


def _notice_text(source_ids: Iterable[str], with_nuclei: bool) -> str:
    lines = ["Комплект данных уязвимостей сканера. Источники и условия использования:",
             ""]
    for sid in source_ids:
        lines.append(f"* {SOURCES[sid].title}: {SOURCES[sid].notice}")
    if with_nuclei:
        lines.append(f"* {NUCLEI_NOTICE}")
    lines += ["", "Комплект предназначен для установок сканера в вашей организации."]
    return "\n".join(lines) + "\n"


def export_bundle(engine: Engine, out: Path, *, sources: Sequence[str] | None = None,
                  nuclei_dir: Path | None = None, scanner_version: str = "",
                  now: datetime | None = None) -> ExportResult:
    """Собирает комплект из справочников в БД. Источники без данных пропускаются."""
    now = (now or datetime.now(UTC)).astimezone(UTC)
    wanted = list(sources or SOURCES)
    unknown = [s for s in wanted if s not in SOURCES]
    if unknown:
        raise BundleError(f"неизвестные источники: {', '.join(unknown)} "
                          f"(доступны: {', '.join(SOURCES)})")
    feeds = _feed_rows(engine)
    out = Path(out)
    out.parent.mkdir(parents=True, exist_ok=True)
    work = Path(tempfile.mkdtemp(prefix="bundle-", dir=out.parent))
    manifest: dict[str, Any] = {"kind": KIND, "format": FORMAT, "created_at": _iso(now),
                                "scanner_version": scanner_version, "sources": {}}
    skipped: list[str] = []
    try:
        (work / "data").mkdir()
        with engine.connect() as conn:
            for sid in wanted:
                src = SOURCES[sid]
                if not _table_exists(conn, src.tables[0]) or not conn.scalar(
                        select(func.count()).select_from(src.tables[0])):
                    skipped.append(sid)
                    continue
                files = []
                for table in src.tables:
                    member = f"data/{table.name}.jsonl.gz"
                    rows = _dump_table(conn, table, work / member)
                    files.append({"table": table.name, "path": member, "rows": rows,
                                  "columns": _columns(table),
                                  "sha256": _sha256_file(work / member)})
                feed = feeds.get(sid)
                entry: dict[str, Any] = {
                    "title": src.title,
                    "as_of": _iso(_as_of(engine, src, feed, now)),
                    "fingerprint": feed.fingerprint if feed else None,
                    "count": files[0]["rows"],
                    "files": files,
                }
                if sid == "advisories":
                    entry["releases"] = sorted(
                        f"{f}:{r}" for f, r in conn.execute(
                            select(_ADV.c.family, _ADV.c.release).distinct()))
                manifest["sources"][sid] = entry
        if not manifest["sources"]:
            raise BundleError("в базе нет данных ни одного источника — собирать нечего "
                              "(сначала загрузите справочники)")
        with_nuclei = False
        if nuclei_dir is not None and nuclei_dir.is_dir():
            count = sum(1 for _ in nuclei_dir.rglob("*.yaml"))
            if count:
                with tarfile.open(work / NUCLEI_MEMBER, "w:gz") as t:
                    t.add(nuclei_dir, arcname="nuclei-templates",
                          filter=_no_links)
                manifest["nuclei_templates"] = {
                    "path": NUCLEI_MEMBER, "count": count,
                    "sha256": _sha256_file(work / NUCLEI_MEMBER)}
                with_nuclei = True
        (work / NOTICE).write_text(_notice_text(manifest["sources"], with_nuclei),
                                   encoding="utf-8")
        (work / MANIFEST).write_text(json.dumps(manifest, ensure_ascii=False, indent=2),
                                     encoding="utf-8")
        part = out.with_name(out.name + ".part")
        with tarfile.open(part, "w") as t:
            # Манифест первым: `bundle info` и автоимпорт читают его, не листая файл.
            t.add(work / MANIFEST, arcname=MANIFEST)
            t.add(work / NOTICE, arcname=NOTICE)
            for entry in manifest["sources"].values():
                for f in entry["files"]:
                    t.add(work / f["path"], arcname=f["path"])
            if with_nuclei:
                t.add(work / NUCLEI_MEMBER, arcname=NUCLEI_MEMBER)
        os.replace(part, out)
    finally:
        shutil.rmtree(work, ignore_errors=True)
    return ExportResult(path=out, manifest=manifest, skipped=skipped)


def _no_links(info: tarfile.TarInfo) -> tarfile.TarInfo | None:
    return info if (info.isfile() or info.isdir()) else None


# ---------- чтение ----------
def read_manifest(path: Path) -> dict[str, Any]:
    try:
        with tarfile.open(path, "r") as t:
            member = t.extractfile(MANIFEST)
            if member is None:
                raise KeyError(MANIFEST)
            manifest = json.loads(member.read().decode("utf-8"))
    except (OSError, tarfile.TarError, KeyError, ValueError) as e:
        raise BundleError(f"{path}: не комплект данных сканера "
                          f"({type(e).__name__}: {e})") from e
    if manifest.get("kind") != KIND:
        raise BundleError(f"{path}: не комплект данных сканера")
    fmt = manifest.get("format")
    if not isinstance(fmt, int) or fmt > FORMAT:
        raise BundleError(f"{path}: формат комплекта {fmt} новее, чем понимает эта версия "
                          f"сканера ({FORMAT}) — обновите сканер")
    return manifest


def find_bundle(dirs: Iterable[str | Path] = DEFAULT_DIRS) -> Path | None:
    """Самый свежий комплект в каталогах (по дате сборки из манифеста)."""
    best: tuple[str, Path] | None = None
    for d in dirs:
        p = Path(d)
        if not p.is_dir():
            continue
        for f in p.glob(FILE_GLOB):
            try:
                created = read_manifest(f).get("created_at") or ""
            except BundleError:
                continue
            if best is None or created > best[0]:
                best = (created, f)
    return best[1] if best else None


# ---------- импорт ----------
@dataclass(slots=True)
class ImportResult:
    source: str
    status: str            # imported | skipped
    count: int = 0
    message: str = ""


def _member_sha256(tar: tarfile.TarFile, path: str) -> str:
    member = tar.extractfile(path)
    if member is None:
        raise BundleError(f"в комплекте нет файла {path}")
    h = hashlib.sha256()
    for chunk in iter(lambda: member.read(1 << 20), b""):
        h.update(chunk)
    return h.hexdigest()


def _iter_rows(tar: tarfile.TarFile, path: str) -> Iterator[list[Any]]:
    member = tar.extractfile(path)
    if member is None:
        raise BundleError(f"в комплекте нет файла {path}")
    with gzip.open(member, "rt", encoding="utf-8") as fh:
        for line in fh:
            if line.strip():
                yield json.loads(line)


def _load_table(conn: Connection, tar: tarfile.TarFile, table: Table,
                spec: dict[str, Any]) -> int:
    cols: list[str] = spec["columns"]
    known = {c.name for c in table.columns}
    keep = [i for i, c in enumerate(cols) if c in known]   # колонки из будущих версий — мимо
    conv = _converters(table)
    # Сумма сверяется до вставки: повреждённый файл не оставит полсправочника.
    if _member_sha256(tar, spec["path"]) != spec.get("sha256"):
        raise BundleError(f"контрольная сумма {spec['path']} не совпала — файл комплекта "
                          "повреждён или неполон; справочник не изменён")
    batch: list[dict[str, Any]] = []
    n = 0
    links: list[dict[str, str]] = []
    sqlite_bdu = table is bdu_entry and conn.dialect.name != "postgresql"
    for values in _iter_rows(tar, spec["path"]):
        row = {}
        for i in keep:
            name, v = cols[i], values[i]
            f = conv.get(name)
            row[name] = f(v) if f and v is not None else v
        batch.append(row)
        if sqlite_bdu:
            links += [{"bdu_id": row["bdu_id"], "cve_id": c}
                      for c in dict.fromkeys(row.get("cve_ids") or [])]
        if len(batch) >= BATCH:
            conn.execute(insert(table), batch)
            n += len(batch)
            batch = []
            if links:
                conn.execute(insert(bdu_cve), links)
                links = []
    if batch:
        conn.execute(insert(table), batch)
        n += len(batch)
    if links:
        conn.execute(insert(bdu_cve), links)
    if n != spec.get("rows", n):
        raise BundleError(f"{spec['path']}: строк {n}, в манифесте {spec['rows']}")
    return n


def _has_rows(engine: Engine, table: Table) -> bool:
    with engine.connect() as c:
        if not _table_exists(c, table):
            return False
        return c.scalar(select(func.count()).select_from(table).limit(1)) > 0


def _seed_feed(engine: Engine, timezone: str) -> None:
    from scanner.feeds.scheduler import seed_feed_sync
    seed_feed_sync(make_session_factory(engine), timezone=timezone)


def import_bundle(engine: Engine, path: Path, *, sources: Sequence[str] | None = None,
                  force: bool = False, nuclei_dir: Path | None = None,
                  timezone: str = "UTC", now: datetime | None = None) -> list[ImportResult]:
    """Загружает источники из комплекта.

    Источник загружается, если локально его нет, или локальная загрузка старше
    комплекта, или задан force. Иначе пропускается: данные установки свежее."""
    now = (now or datetime.now(UTC)).astimezone(UTC)
    manifest = read_manifest(path)
    created = _parse_dt(manifest.get("created_at")) or now
    wanted = list(sources) if sources else list(manifest["sources"])
    _seed_feed(engine, timezone)
    feeds = _feed_rows(engine)
    results: list[ImportResult] = []
    with tarfile.open(path, "r") as tar:
        for sid in wanted:
            entry = manifest["sources"].get(sid)
            src = SOURCES.get(sid)
            if entry is None or src is None:
                results.append(ImportResult(sid, "skipped", message="нет в комплекте"))
                continue
            as_of = _parse_dt(entry.get("as_of")) or created
            feed = feeds.get(sid)
            local_at = feed.last_success_at if feed else None
            if local_at is not None and local_at.tzinfo is None:
                local_at = local_at.replace(tzinfo=UTC)
            _ensure_tables(engine, src.tables)
            has_local = _has_rows(engine, src.tables[0])
            if not force and has_local and (local_at is None or local_at >= as_of):
                why = (f"локальные данные от {local_at:%d.%m.%Y} не старше комплекта"
                       if local_at else "в базе уже есть данные (загружены вручную)")
                results.append(ImportResult(sid, "skipped", message=why))
                continue
            by_table = {f["table"]: f for f in entry["files"]}
            with engine.begin() as conn:
                for table in src.tables:
                    conn.execute(delete(table))
                    if table is bdu_entry and engine.dialect.name != "postgresql":
                        conn.execute(delete(bdu_cve))
                count = 0
                for table in src.tables:
                    spec = by_table.get(table.name)
                    if spec is None:
                        continue
                    n = _load_table(conn, tar, table, spec)
                    if table is src.tables[0]:
                        count = n
                msg = (f"Из комплекта данных от {created:%d.%m.%Y} (актуально на "
                       f"{as_of:%d.%m.%Y}): {count} записей; дальше — только обновления")
                conn.execute(update(FeedSync).where(FeedSync.source == sid).values(
                    last_success_at=as_of, last_run_at=now, last_result="ok",
                    last_count=count, message=msg,
                    fingerprint=entry.get("fingerprint")))
            results.append(ImportResult(sid, "imported", count, msg))
        nuclei = manifest.get("nuclei_templates")
        if nuclei and nuclei_dir is not None and (sources is None or "nuclei" in sources):
            results.append(_import_nuclei(tar, nuclei, nuclei_dir, force))
    return results


def _import_nuclei(tar: tarfile.TarFile, spec: dict[str, Any], dest: Path,
                   force: bool) -> ImportResult:
    if not force and dest.is_dir() and any(dest.rglob("*.yaml")):
        return ImportResult("nuclei", "skipped", message="шаблоны уже есть на диске")
    member = tar.extractfile(spec["path"])
    if member is None:
        return ImportResult("nuclei", "skipped", message="нет в комплекте")
    data = member.read()
    if hashlib.sha256(data).hexdigest() != spec.get("sha256"):
        raise BundleError("контрольная сумма шаблонов Nuclei не совпала")
    dest.mkdir(parents=True, exist_ok=True)
    root = dest.resolve()
    n = 0
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as t:
        for m in t.getmembers():
            parts = PurePosixPath(m.name).parts
            if not parts or parts[0] != "nuclei-templates" or ".." in parts \
                    or m.name.startswith("/") or not (m.isfile() or m.isdir()):
                continue
            target = (root / Path(*parts[1:])) if len(parts) > 1 else root
            if root not in (target.resolve(), *target.resolve().parents):
                continue
            if m.isdir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            src = t.extractfile(m)
            if src is None:
                continue
            with target.open("wb") as fh:
                shutil.copyfileobj(src, fh)
            n += target.suffix == ".yaml"
    return ImportResult("nuclei", "imported", n, f"шаблонов Nuclei: {n}")


def download_bundle(url: str, dest_dir: Path) -> Path:
    """Скачивает комплект по адресу (например, файл релиза) в каталог комплектов."""
    from scanner.feeds.sources import FeedError, _download

    dest_dir.mkdir(parents=True, exist_ok=True)
    name = PurePosixPath(url.split("?", 1)[0]).name
    if not name.endswith(".tar"):
        name = f"scanner-data-{datetime.now(UTC):%Y%m%d}.tar"
    dest = dest_dir / name
    part = dest.with_name(dest.name + ".part")
    try:
        _download(url, part, "комплект данных")
    except FeedError as e:
        part.unlink(missing_ok=True)
        raise BundleError(str(e)) from e
    read_manifest(part)
    os.replace(part, dest)
    return dest
