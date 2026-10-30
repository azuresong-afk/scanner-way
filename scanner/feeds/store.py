"""Хранилище справочников уязвимостей (NVD + БДУ ФСТЭК) для сопоставления.

``ReferenceStore`` — интерфейс, которым пользуются загрузчики фидов и matcher.
Реализации:
  * ``SqlReferenceStore`` — таблицы reference_nvd_cve, reference_nvd_cpe_match,
    reference_bdu_entry (PostgreSQL в проде, SQLite в тестах/офлайн);
  * ``InMemoryReferenceStore`` — для тестов и разовых прогонов без БД.
"""
from __future__ import annotations

import json
import threading
from collections import defaultdict
from collections.abc import Iterable
from datetime import UTC, datetime
from typing import Any, Protocol

from sqlalchemy import (
    Column,
    DateTime,
    Integer,
    MetaData,
    Numeric,
    Table,
    Text,
    bindparam,
    create_engine,
    delete,
    select,
    text,
)
from sqlalchemy.engine import Engine
from sqlalchemy.types import TypeDecorator

from scanner.feeds.bdu_fstec import BduRecord, parse_bdu_versions
from scanner.feeds.cpe import normalize_name
from scanner.feeds.nvd import CpeMatch, NvdRecord


class ReferenceStore(Protocol):
    def upsert_bdu(self, records: Iterable[BduRecord]) -> int: ...
    def upsert_nvd(self, records: Iterable[NvdRecord]) -> int: ...
    def get_nvd(self, cve_id: str) -> NvdRecord | None: ...
    def get_bdu(self, bdu_id: str) -> BduRecord | None: ...
    def bdu_by_cve(self, cve_id: str) -> list[BduRecord]: ...
    def cpe_matches(self, product: str) -> list[CpeMatch]: ...
    def bdu_by_software(self, name: str) -> list[BduRecord]: ...
    def bdu_software_names(self) -> set[str]: ...


# ---------- In-memory ----------

class InMemoryReferenceStore:
    def __init__(self) -> None:
        self.nvd: dict[str, NvdRecord] = {}
        self.bdu: dict[str, BduRecord] = {}
        self._bdu_by_cve: dict[str, set[str]] = defaultdict(set)
        self._bdu_by_soft: dict[str, set[str]] = defaultdict(set)
        self._cpe_by_product: dict[str, list[CpeMatch]] = defaultdict(list)

    def upsert_bdu(self, records: Iterable[BduRecord]) -> int:
        n = 0
        for rec in records:
            old = self.bdu.get(rec.bdu_id)
            if old:
                for cve in old.cve_ids:
                    self._bdu_by_cve[cve].discard(rec.bdu_id)
            self.bdu[rec.bdu_id] = rec
            for cve in rec.cve_ids:
                self._bdu_by_cve[cve.upper()].add(rec.bdu_id)
            for spec in parse_bdu_versions(rec.versions):
                self._bdu_by_soft[normalize_name(spec.software)].add(rec.bdu_id)
            n += 1
        return n

    def upsert_nvd(self, records: Iterable[NvdRecord]) -> int:
        n = 0
        for rec in records:
            old = self.nvd.get(rec.cve_id)
            if old:
                for m in old.cpe_matches:
                    self._cpe_by_product[m.product].remove(m)
            self.nvd[rec.cve_id] = rec
            for m in rec.cpe_matches:
                self._cpe_by_product[m.product].append(m)
            n += 1
        return n

    def get_nvd(self, cve_id: str) -> NvdRecord | None:
        return self.nvd.get(cve_id.upper())

    def get_bdu(self, bdu_id: str) -> BduRecord | None:
        return self.bdu.get(bdu_id.upper())

    def bdu_by_cve(self, cve_id: str) -> list[BduRecord]:
        return [self.bdu[i] for i in sorted(self._bdu_by_cve.get(cve_id.upper(), ()))]

    def cpe_matches(self, product: str) -> list[CpeMatch]:
        return list(self._cpe_by_product.get(product.lower(), ()))

    def bdu_by_software(self, name: str) -> list[BduRecord]:
        return [self.bdu[i] for i in sorted(self._bdu_by_soft.get(normalize_name(name), ()))]

    def bdu_software_names(self) -> set[str]:
        return {n for n, ids in self._bdu_by_soft.items() if ids}


# ---------- SQL (PostgreSQL / SQLite) ----------

class StrArray(TypeDecorator):
    """TEXT[] в PostgreSQL, JSON-строка в остальных СУБД (SQLite в тестах)."""
    impl = Text
    cache_ok = True

    def load_dialect_impl(self, dialect):
        if dialect.name == "postgresql":
            from sqlalchemy.dialects.postgresql import ARRAY
            return dialect.type_descriptor(ARRAY(Text))
        return dialect.type_descriptor(Text())

    def process_bind_param(self, value, dialect):
        value = list(value or [])
        return value if dialect.name == "postgresql" else json.dumps(value)

    def process_result_value(self, value, dialect):
        if value is None:
            return []
        return list(value) if dialect.name == "postgresql" else json.loads(value)


metadata = MetaData()

nvd_cve = Table(
    "reference_nvd_cve", metadata,
    Column("cve_id", Text, primary_key=True),
    Column("cvss_v3", Numeric(4, 1)),
    Column("cvss_vector", Text),
    Column("severity", Text),
    Column("cpe", StrArray),
    Column("summary", Text),
    Column("refs", StrArray),
    Column("updated_at", DateTime(timezone=True)),
)

nvd_cpe_match = Table(
    "reference_nvd_cpe_match", metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("cve_id", Text, nullable=False, index=True),
    Column("criteria", Text, nullable=False),
    Column("vendor", Text, nullable=False),
    Column("product", Text, nullable=False, index=True),
    Column("version", Text),
    Column("update", Text),
    Column("version_start_incl", Text),
    Column("version_start_excl", Text),
    Column("version_end_incl", Text),
    Column("version_end_excl", Text),
)

bdu_entry = Table(
    "reference_bdu_entry", metadata,
    Column("bdu_id", Text, primary_key=True),
    Column("title", Text),
    Column("description", Text),
    Column("vendor", Text),
    Column("software", Text),
    Column("versions", Text),
    Column("software_type", Text),
    Column("vuln_class", Text),
    Column("cvss2_vector", Text),
    Column("cvss3", Text),
    Column("cvss4", Text),
    Column("cvss_score", Numeric(4, 1)),
    Column("severity_text", Text),
    Column("exploit_available", Text),
    Column("status", Text),
    Column("cwe", Text),
    Column("cve_ids", StrArray),
    Column("other_ids", Text),
    Column("remediation", Text),
    Column("refs", Text),
    Column("detection_date", Text),
    Column("published_at", Text),
    Column("updated_at", DateTime(timezone=True)),
)

# Связь БДУ <-> CVE для СУБД без массивов (SQLite): в PostgreSQL поиск идёт
# по reference_bdu_entry.cve_ids через GIN-индекс idx_bdu_cve.
bdu_cve = Table(
    "reference_bdu_cve", metadata,
    Column("bdu_id", Text, primary_key=True),
    Column("cve_id", Text, primary_key=True, index=True),
)

# Приоритизация риска (R6): EPSS и CISA KEV. Полностью заменяются при загрузке.
epss_score = Table(
    "epss_score", metadata,
    Column("cve", Text, primary_key=True),
    Column("score", Numeric(7, 6), nullable=False),
    Column("percentile", Numeric(7, 6)),
    Column("as_of", Text),
)

kev = Table(
    "kev", metadata,
    Column("cve", Text, primary_key=True),
    Column("added", Text),
)

# Поле BduRecord -> колонка таблицы (где имена различаются)
_BDU_RENAME = {"cvss2": "cvss2_vector"}
_BDU_SKIP = {"fix_method"}  # нет в схеме reference_bdu_entry


def _parse_ru_date(value: str | None) -> datetime | None:
    if not value:
        return None
    for fmt in ("%d.%m.%Y", "%Y-%m-%d", "%Y-%m-%d %H:%M:%S"):
        try:
            return datetime.strptime(value.strip(), fmt).replace(tzinfo=UTC)
        except ValueError:
            continue
    return None


def _bdu_to_row(rec: BduRecord) -> dict[str, Any]:
    row: dict[str, Any] = {}
    for name in BduRecord.__slots__:
        if name in _BDU_SKIP:
            continue
        row[_BDU_RENAME.get(name, name)] = getattr(rec, name)
    row["bdu_id"] = rec.bdu_id.upper()
    row["cve_ids"] = [c.upper() for c in rec.cve_ids]
    row["updated_at"] = _parse_ru_date(rec.updated_at)
    return row


def _row_to_bdu(row: Any) -> BduRecord:
    m = row._mapping
    data = {}
    for name in BduRecord.__slots__:
        col = _BDU_RENAME.get(name, name)
        if col in m:
            data[name] = m[col]
    if data.get("cvss_score") is not None:
        data["cvss_score"] = float(data["cvss_score"])
    if isinstance(data.get("updated_at"), datetime):
        data["updated_at"] = data["updated_at"].strftime("%d.%m.%Y")
    data["cve_ids"] = list(data.get("cve_ids") or [])
    return BduRecord(**data)


def _row_to_cpe_match(row: Any) -> CpeMatch:
    m = dict(row._mapping)
    m.pop("id", None)
    return CpeMatch(**m)


class SqlReferenceStore:
    def __init__(self, engine: Engine):
        self.engine = engine

    @classmethod
    def from_url(cls, url: str, *, create: bool = False) -> SqlReferenceStore:
        store = cls(create_engine(url))
        if create:
            store.create_schema()
        return store

    def create_schema(self) -> None:
        """Создаёт таблицы справочников, если их нет (в проде — миграции)."""
        tables = [nvd_cve, nvd_cpe_match, bdu_entry]
        if not self._pg:
            tables.append(bdu_cve)
        metadata.create_all(self.engine, tables=tables)

    @property
    def _pg(self) -> bool:
        return self.engine.dialect.name == "postgresql"

    def _insert(self):
        name = self.engine.dialect.name
        if name == "postgresql":
            from sqlalchemy.dialects.postgresql import insert
        elif name == "sqlite":
            from sqlalchemy.dialects.sqlite import insert
        else:  # pragma: no cover
            raise NotImplementedError(f"upsert для {name} не поддержан")
        return insert

    def _upsert(self, conn, table: Table, rows: list[dict[str, Any]], key: str) -> None:
        if not rows:
            return
        stmt = self._insert()(table).values(rows)
        update = {c.name: stmt.excluded[c.name] for c in table.columns if c.name != key}
        conn.execute(stmt.on_conflict_do_update(index_elements=[key], set_=update))

    def upsert_bdu(self, records: Iterable[BduRecord]) -> int:
        # Дедупликация внутри пачки: ON CONFLICT не терпит повтор ключа в одном INSERT.
        rows = list({r["bdu_id"]: r for r in map(_bdu_to_row, records)}.values())
        with self.engine.begin() as conn:
            self._upsert(conn, bdu_entry, rows, "bdu_id")
            if not self._pg and rows:
                ids = [r["bdu_id"] for r in rows]
                conn.execute(delete(bdu_cve).where(bdu_cve.c.bdu_id.in_(ids)))
                links = [{"bdu_id": r["bdu_id"], "cve_id": c}
                         for r in rows for c in dict.fromkeys(r["cve_ids"])]
                if links:
                    conn.execute(bdu_cve.insert(), links)
        return len(rows)

    def upsert_nvd(self, records: Iterable[NvdRecord]) -> int:
        recs = list({r.cve_id: r for r in records}.values())
        if not recs:
            return 0
        rows = [{"cve_id": r.cve_id, "cvss_v3": r.cvss_v3, "cvss_vector": r.cvss_vector,
                 "severity": r.severity, "cpe": r.cpe, "summary": r.summary,
                 "refs": r.refs, "updated_at": r.updated_at} for r in recs]
        matches = [{"cve_id": m.cve_id, "criteria": m.criteria, "vendor": m.vendor,
                    "product": m.product, "version": m.version, "update": m.update,
                    "version_start_incl": m.version_start_incl,
                    "version_start_excl": m.version_start_excl,
                    "version_end_incl": m.version_end_incl,
                    "version_end_excl": m.version_end_excl}
                   for r in recs for m in r.cpe_matches]
        with self.engine.begin() as conn:
            self._upsert(conn, nvd_cve, rows, "cve_id")
            conn.execute(delete(nvd_cpe_match).where(
                nvd_cpe_match.c.cve_id.in_([r.cve_id for r in recs])))
            if matches:
                conn.execute(nvd_cpe_match.insert(), matches)
        return len(recs)

    def get_nvd(self, cve_id: str) -> NvdRecord | None:
        cve_id = cve_id.upper()
        with self.engine.connect() as conn:
            row = conn.execute(select(nvd_cve).where(nvd_cve.c.cve_id == cve_id)).first()
            if row is None:
                return None
            ms = conn.execute(select(nvd_cpe_match).where(
                nvd_cpe_match.c.cve_id == cve_id)).all()
        m = row._mapping
        return NvdRecord(
            cve_id=m["cve_id"],
            cvss_v3=float(m["cvss_v3"]) if m["cvss_v3"] is not None else None,
            cvss_vector=m["cvss_vector"], severity=m["severity"], summary=m["summary"],
            refs=m["refs"], cpe=m["cpe"], updated_at=m["updated_at"],
            cpe_matches=[_row_to_cpe_match(r) for r in ms])

    def get_bdu(self, bdu_id: str) -> BduRecord | None:
        with self.engine.connect() as conn:
            row = conn.execute(select(bdu_entry).where(
                bdu_entry.c.bdu_id == bdu_id.upper())).first()
        return _row_to_bdu(row) if row else None

    def bdu_by_cve(self, cve_id: str) -> list[BduRecord]:
        cve_id = cve_id.upper()
        if self._pg:
            # Оператор @> использует GIN-индекс idx_bdu_cve.
            stmt = select(bdu_entry).where(
                text("reference_bdu_entry.cve_ids @> ARRAY[:cve]::text[]"))
        else:
            stmt = select(bdu_entry).join(bdu_cve, bdu_cve.c.bdu_id == bdu_entry.c.bdu_id) \
                .where(bdu_cve.c.cve_id == bindparam("cve"))
        stmt = stmt.order_by(bdu_entry.c.bdu_id)
        with self.engine.connect() as conn:
            rows = conn.execute(stmt, {"cve": cve_id}).all()
        return [_row_to_bdu(r) for r in rows]

    def cpe_matches(self, product: str) -> list[CpeMatch]:
        stmt = select(nvd_cpe_match).where(nvd_cpe_match.c.product == product.lower())
        with self.engine.connect() as conn:
            return [_row_to_cpe_match(r) for r in conn.execute(stmt).all()]

    def bdu_by_software(self, name: str) -> list[BduRecord]:
        """Кандидаты по названию ПО (грубый LIKE), затем точная проверка по
        разобранному полю «Версия ПО»."""
        norm = normalize_name(name)
        if not norm:
            return []
        stmt = (select(bdu_entry)
                .where(bdu_entry.c.versions.ilike(f"%{name.strip()}%"))
                .order_by(bdu_entry.c.bdu_id))
        with self.engine.connect() as conn:
            rows = conn.execute(stmt).all()
        out = []
        for r in rows:
            rec = _row_to_bdu(r)
            if any(normalize_name(s.software) == norm for s in parse_bdu_versions(rec.versions)):
                out.append(rec)
        return out

    def bdu_software_names(self) -> set[str]:
        """Нормализованные названия ПО из «Версия ПО» всех записей БДУ.

        Полный проход по справочнику (~100 тыс. записей — секунды): вызывать
        один раз на прогон (см. CachingReferenceStore).
        """
        names: set[str] = set()
        with self.engine.connect() as conn:
            for (versions,) in conn.execute(select(bdu_entry.c.versions)):
                names.update(normalize_name(s.software) for s in parse_bdu_versions(versions))
        names.discard("")
        return names


# ---------- Кэш на время прогона ----------

class CachingReferenceStore:
    """Только чтение с запоминанием ответов — для одного прогона.

    Инвентаризация сотен хостов спрашивает справочник об одних и тех же
    пакетах (OpenSSH, OpenSSL…), а поиск БДУ по названию ПО — это LIKE по всей
    таблице. Кэш живёт столько же, сколько модуль прогона, поэтому свежая
    загрузка справочников видна со следующего прогона.
    """

    def __init__(self, store: ReferenceStore):
        self.store = store
        self._cache: dict[tuple, Any] = {}
        self._names: set[str] | None = None
        self._lock = threading.Lock()      # хосты инвентаризуются параллельно

    def _get(self, method: str, key: str):
        k = (method, key.upper())
        if k not in self._cache:
            self._cache[k] = getattr(self.store, method)(key)
        return self._cache[k]

    def upsert_bdu(self, records: Iterable[BduRecord]) -> int:  # pragma: no cover
        raise TypeError("CachingReferenceStore is read-only")

    def upsert_nvd(self, records: Iterable[NvdRecord]) -> int:  # pragma: no cover
        raise TypeError("CachingReferenceStore is read-only")

    def get_nvd(self, cve_id: str) -> NvdRecord | None:
        return self._get("get_nvd", cve_id)

    def get_bdu(self, bdu_id: str) -> BduRecord | None:
        return self._get("get_bdu", bdu_id)

    def bdu_by_cve(self, cve_id: str) -> list[BduRecord]:
        return self._get("bdu_by_cve", cve_id)

    def cpe_matches(self, product: str) -> list[CpeMatch]:
        return self._get("cpe_matches", product)

    def bdu_by_software(self, name: str) -> list[BduRecord]:
        return self._get("bdu_by_software", name)

    def bdu_software_names(self) -> set[str]:
        with self._lock:
            if self._names is None:
                self._names = set(self.store.bdu_software_names())
        return self._names
