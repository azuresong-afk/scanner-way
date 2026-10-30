"""Загрузка EPSS (Exploit Prediction Scoring System, FIRST) в таблицу epss_score.

Источник — `epss_scores-current.csv.gz` (epss.cyentia.com): первая строка —
комментарий `#model_version:…,score_date:…`, затем `cve,epss,percentile`.
Таблица заменяется целиком в одной транзакции.
"""
from __future__ import annotations

import csv
import gzip
import io
import re
from collections.abc import Iterable, Iterator
from dataclasses import dataclass

from sqlalchemy import delete, insert, select
from sqlalchemy.engine import Engine
from sqlalchemy.exc import SQLAlchemyError

from scanner.feeds.store import epss_score

CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")
BATCH = 5000


@dataclass(frozen=True, slots=True)
class EpssRow:
    cve: str
    score: float
    percentile: float | None


def parse_epss(data: bytes) -> tuple[list[EpssRow], str | None]:
    """CSV (в том числе .gz) -> (строки, дата оценки). Битые строки пропускаются."""
    if data[:2] == b"\x1f\x8b":
        data = gzip.decompress(data)
    text = data.decode("utf-8-sig")
    as_of = None
    m = re.match(r"#.*?score_date:([0-9T:\-.Z+]+)", text)
    if m:
        as_of = m.group(1)
    lines = (ln for ln in io.StringIO(text) if not ln.startswith("#"))
    rows: list[EpssRow] = []
    for rec in csv.DictReader(lines):
        cve = (rec.get("cve") or "").strip().upper()
        if not CVE_RE.match(cve):
            continue
        try:
            score = float(rec["epss"])
        except (KeyError, TypeError, ValueError):
            continue
        if not 0.0 <= score <= 1.0:
            continue
        try:
            pct = float(rec["percentile"])
        except (KeyError, TypeError, ValueError):
            pct = None
        rows.append(EpssRow(cve, score, pct))
    return rows, as_of


def _batches(rows: list[dict], size: int = BATCH) -> Iterator[list[dict]]:
    for i in range(0, len(rows), size):
        yield rows[i:i + size]


def sync_epss(engine: Engine, rows: Iterable[EpssRow], as_of: str | None = None) -> int:
    payload = [{"cve": r.cve, "score": r.score, "percentile": r.percentile, "as_of": as_of}
               for r in rows]
    epss_score.create(engine, checkfirst=True)
    with engine.begin() as conn:
        conn.execute(delete(epss_score))
        for chunk in _batches(payload):
            conn.execute(insert(epss_score), chunk)
    return len(payload)


def lookup_epss(engine: Engine, cves: Iterable[str]) -> dict[str, tuple[float, float | None]]:
    """{CVE: (score, percentile)} для известных CVE; пусто, если EPSS не загружен."""
    ids = sorted({c.upper() for c in cves})
    out: dict[str, tuple[float, float | None]] = {}
    try:
        with engine.connect() as conn:
            for i in range(0, len(ids), 500):
                q = select(epss_score.c.cve, epss_score.c.score, epss_score.c.percentile
                           ).where(epss_score.c.cve.in_(ids[i:i + 500]))
                for cve, score, pct in conn.execute(q):
                    out[cve] = (float(score), float(pct) if pct is not None else None)
    except SQLAlchemyError:   # таблицы нет (миграция/загрузка не выполнены) — деградируем
        return {}
    return out
