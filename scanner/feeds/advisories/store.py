"""Хранилище бюллетеней: таблица distro_advisory (миграция 0012) или память."""
from __future__ import annotations

import threading
from collections import defaultdict
from collections.abc import Iterable
from typing import Protocol

from sqlalchemy import Table, delete, insert, select
from sqlalchemy.engine import Engine

from scanner.core.db import DistroAdvisoryRow
from scanner.feeds.advisories.base import Advisory

_T: Table = DistroAdvisoryRow.__table__  # type: ignore[assignment]
_IN_CHUNK = 500


class AdvisoryStore(Protocol):
    def releases(self) -> set[tuple[str, str]]: ...
    def for_packages(self, family: str, release: str,
                     names: Iterable[str]) -> dict[str, list[Advisory]]: ...
    def replace_release(self, family: str, release: str,
                        records: Iterable[Advisory]) -> int: ...


class InMemoryAdvisoryStore:
    def __init__(self, records: Iterable[Advisory] = ()) -> None:
        self._rows: dict[tuple[str, str], dict[str, list[Advisory]]] = {}
        for r in records:
            self._rows.setdefault((r.family, r.release), defaultdict(list))[r.package].append(r)

    def releases(self) -> set[tuple[str, str]]:
        return {k for k, v in self._rows.items() if v}

    def for_packages(self, family, release, names):
        rel = self._rows.get((family, release), {})
        return {n: list(rel[n]) for n in set(names) if n in rel}

    def replace_release(self, family, release, records):
        rel: dict[str, list[Advisory]] = defaultdict(list)
        n = 0
        for r in records:
            rel[r.package].append(r)
            n += 1
        self._rows[(family, release)] = rel
        return n


class SqlAdvisoryStore:
    def __init__(self, engine: Engine, *, batch_size: int = 5000) -> None:
        self.engine = engine
        self.batch_size = batch_size

    def create_schema(self) -> None:
        """Таблица для SQLite/офлайна; в проде её создаёт миграция 0012."""
        _T.create(self.engine, checkfirst=True)

    def releases(self) -> set[tuple[str, str]]:
        with self.engine.connect() as c:
            return {(f, r) for f, r in c.execute(select(_T.c.family, _T.c.release).distinct())}

    def for_packages(self, family, release, names):
        out: dict[str, list[Advisory]] = defaultdict(list)
        names = sorted(set(names))
        with self.engine.connect() as c:
            for i in range(0, len(names), _IN_CHUNK):
                q = select(_T.c.package, _T.c.cve, _T.c.status, _T.c.fixed_version,
                           _T.c.advisory_id).where(
                    _T.c.family == family, _T.c.release == release,
                    _T.c.package.in_(names[i:i + _IN_CHUNK]))
                for pkg, cve, status, fixed, adv in c.execute(q):
                    out[pkg].append(Advisory(family, release, pkg, cve, status, fixed, adv))
        return dict(out)

    def replace_release(self, family, release, records):
        """Заменяет данные выпуска целиком в одной транзакции: сканер, читающий
        таблицу во время загрузки, видит либо старые данные, либо новые."""
        n = 0
        with self.engine.begin() as c:
            c.execute(delete(_T).where(_T.c.family == family, _T.c.release == release))
            batch: list[dict] = []
            for r in records:
                batch.append({"family": family, "release": release, "package": r.package,
                              "cve": r.cve, "status": r.status,
                              "fixed_version": r.fixed_version,
                              "advisory_id": r.advisory_id})
                if len(batch) >= self.batch_size:
                    c.execute(insert(_T), batch)
                    n += len(batch)
                    batch = []
            if batch:
                c.execute(insert(_T), batch)
                n += len(batch)
        return n


class CachingAdvisoryStore:
    """Кэш на время прогона: одни и те же пакеты на сотнях хостов одного выпуска."""

    def __init__(self, inner: AdvisoryStore) -> None:
        self.inner = inner
        self._releases: set[tuple[str, str]] | None = None
        self._pkgs: dict[tuple[str, str, str], list[Advisory]] = {}
        self._lock = threading.Lock()

    def releases(self) -> set[tuple[str, str]]:
        with self._lock:
            if self._releases is None:
                self._releases = self.inner.releases()
            return self._releases

    def for_packages(self, family, release, names):
        names = set(names)
        with self._lock:
            missing = [n for n in names if (family, release, n) not in self._pkgs]
        if missing:
            got = self.inner.for_packages(family, release, missing)
            with self._lock:
                for n in missing:
                    self._pkgs[(family, release, n)] = got.get(n, [])
        with self._lock:
            return {n: self._pkgs[(family, release, n)] for n in names
                    if self._pkgs.get((family, release, n))}

    def replace_release(self, family, release, records):
        raise TypeError("кэш прогона только для чтения")
