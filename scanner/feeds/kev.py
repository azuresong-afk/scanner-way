"""Загрузка каталога CISA KEV (Known Exploited Vulnerabilities) в таблицу kev.

Берём только CVE и дату добавления в каталог. Срок устранения из каталога
(`dueDate`) не используем — сроков в отчётах нет. Таблица заменяется целиком.
"""
from __future__ import annotations

import json
import re
from collections.abc import Iterable

from sqlalchemy import delete, insert, select
from sqlalchemy.engine import Engine
from sqlalchemy.exc import SQLAlchemyError

from scanner.feeds.store import kev

CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")


def parse_kev(data: bytes) -> list[tuple[str, str | None]]:
    """JSON каталога -> [(CVE, дата добавления)], без повторов, по возрастанию CVE."""
    doc = json.loads(data.decode("utf-8-sig"))
    items = doc.get("vulnerabilities") if isinstance(doc, dict) else None
    if not isinstance(items, list):
        raise ValueError("в файле KEV нет списка vulnerabilities")  # noqa: TRY004
    out: dict[str, str | None] = {}
    for it in items:
        if not isinstance(it, dict):
            continue
        cve = str(it.get("cveID") or "").strip().upper()
        if CVE_RE.match(cve):
            out[cve] = it.get("dateAdded")
    return sorted(out.items())


def sync_kev(engine: Engine, entries: Iterable[tuple[str, str | None]]) -> int:
    payload = [{"cve": c, "added": a} for c, a in entries]
    kev.create(engine, checkfirst=True)
    with engine.begin() as conn:
        conn.execute(delete(kev))
        if payload:
            conn.execute(insert(kev), payload)
    return len(payload)


def lookup_kev(engine: Engine, cves: Iterable[str]) -> frozenset[str]:
    """Подмножество CVE, входящее в KEV; пусто, если каталог не загружен."""
    ids = sorted({c.upper() for c in cves})
    found: set[str] = set()
    try:
        with engine.connect() as conn:
            for i in range(0, len(ids), 500):
                q = select(kev.c.cve).where(kev.c.cve.in_(ids[i:i + 500]))
                found.update(r[0] for r in conn.execute(q))
    except SQLAlchemyError:
        return frozenset()
    return frozenset(found)
