"""Выборка находок и прогонов для API: фильтры, сортировка и страницы в БД.

Большой прогон (сотни хостов × сотни находок) не выгружается целиком:
фильтры и сортировка — в SQL, наружу отдаётся одна страница и общее число.
Исключение — сортировка по приоритету исправления (R6): ранг считается по всем
находкам прогона (scanner.reporting.risk), поэтому сортируются только пары
(id, dedup_key) отфильтрованных находок, а строки читаются для одной страницы.
"""
from __future__ import annotations

import ipaddress
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from datetime import datetime

from sqlalchemy import Select, String, and_, case, cast, exists, func, or_, select
from sqlalchemy.orm import Session

from scanner.core import repository as repo
from scanner.core.db import FalsePositiveRow, FindingRow, HostResult, ScanRun
from scanner.core.models import Severity

# info < low < … < critical — для сортировки «сначала опасные».
SEVERITY_RANK = {str(s): i for i, s in enumerate(Severity)}
FINDING_SORTS = ("severity", "priority", "cvss", "host", "title", "module", "id")
RUN_SORTS = ("id", "created_at", "started_at", "finished_at", "status", "name")
FP_MODES = ("include", "exclude", "only")


@dataclass(slots=True)
class FindingFilter:
    severities: list[str] = field(default_factory=list)
    modules: list[str] = field(default_factory=list)
    statuses: list[str] = field(default_factory=list)
    host: str | None = None
    query: str | None = None
    bdu_only: bool = False
    include_info: bool = True
    false_positives: str = "include"        # include | exclude | only


def _like(text: str) -> str:
    """Шаблон ILIKE для подстроки text (спецсимволы экранированы «\\»)."""
    esc = text.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    return f"%{esc}%"


def _pg(session: Session) -> bool:
    return session.get_bind().dialect.name == "postgresql"


def _array_text(session: Session, col):
    """Массив строк (CVE/БДУ) как текст для поиска подстроки."""
    if _pg(session):
        return func.array_to_string(col, " ")
    return cast(col, String)                 # SQLite: JSON-текст


def _host_text(session: Session):
    return func.host(FindingRow.host) if _pg(session) else FindingRow.host


def _fp_exists(engagement_id: int):
    return exists().where(FalsePositiveRow.engagement_id == engagement_id,
                          FalsePositiveRow.dedup_key == FindingRow.dedup_key)


def filtered(session: Session, scan_run_id: int, engagement_id: int,
             f: FindingFilter, columns=None) -> Select:
    """SELECT находок прогона с фильтрами (без сортировки и страниц)."""
    q = select(*(columns or (FindingRow,))).where(FindingRow.scan_run_id == scan_run_id)
    if f.severities:
        q = q.where(FindingRow.severity.in_(f.severities))
    elif not f.include_info:
        q = q.where(FindingRow.severity != "info")
    if f.modules:
        q = q.where(FindingRow.module.in_(f.modules))
    if f.statuses:
        q = q.where(FindingRow.status.in_(f.statuses))
    if f.host:
        q = q.where(FindingRow.host == str(ipaddress.ip_address(f.host.strip())))
    if f.bdu_only:
        if _pg(session):
            q = q.where(func.cardinality(FindingRow.bdu_ids) > 0)
        else:
            q = q.where(cast(FindingRow.bdu_ids, String) != "[]")
    if f.false_positives == "exclude":
        q = q.where(~_fp_exists(engagement_id))
    elif f.false_positives == "only":
        q = q.where(_fp_exists(engagement_id))
    text = (f.query or "").strip()
    if text:
        like = _like(text)
        host = _host_text(session)
        q = q.where(or_(
            FindingRow.title.ilike(like, escape="\\"),
            cast(host, String).ilike(like, escape="\\"),
            (cast(host, String) + ":" + cast(FindingRow.port, String)).ilike(like, escape="\\"),
            FindingRow.vuln_id.ilike(like, escape="\\"),
            _array_text(session, FindingRow.cve_ids).ilike(like, escape="\\"),
            _array_text(session, FindingRow.bdu_ids).ilike(like, escape="\\")))
    return q


def _severity_rank():
    return case(SEVERITY_RANK, value=FindingRow.severity, else_=-1)


def _order(sort: str, desc: bool):
    """ORDER BY для сортировки sort; desc меняет основное направление."""
    sev = _severity_rank()
    cvss = func.coalesce(FindingRow.cvss, -1)
    port = func.coalesce(FindingRow.port, 0)
    if sort == "severity":
        keys = [sev.desc(), cvss.desc(), FindingRow.host, port] if not desc else \
               [sev.asc(), cvss.asc(), FindingRow.host.desc(), port.desc()]
    elif sort == "cvss":
        keys = [cvss.desc(), sev.desc()] if not desc else [cvss.asc(), sev.asc()]
    elif sort == "host":
        keys = [FindingRow.host, port] if not desc else [FindingRow.host.desc(), port.desc()]
    elif sort == "title":
        keys = [FindingRow.title] if not desc else [FindingRow.title.desc()]
    elif sort == "module":
        keys = [FindingRow.module] if not desc else [FindingRow.module.desc()]
    else:                                     # id
        keys = []
    return [*keys, FindingRow.id.desc() if desc and sort == "id" else FindingRow.id]


def page_findings(session: Session, scan_run_id: int, engagement_id: int, f: FindingFilter,
                  *, sort: str = "severity", desc: bool = False, limit: int | None = None,
                  offset: int = 0, ranks: Mapping[str, int] | None = None
                  ) -> tuple[list[FindingRow], int]:
    """(строки страницы, всего по фильтру). limit=None — все строки.

    ranks — {dedup_key: ранг приоритета}, нужен только для sort="priority"
    (находки без ранга — info и ложные срабатывания — идут в конце)."""
    total = session.scalar(filtered(session, scan_run_id, engagement_id, f,
                                    columns=(func.count(FindingRow.id),))) or 0
    if sort == "priority":
        ranks = ranks or {}
        pairs = session.execute(filtered(session, scan_run_id, engagement_id, f,
                                         columns=(FindingRow.id, FindingRow.dedup_key))
                                .order_by(FindingRow.id)).all()
        big = len(pairs) + 10**9
        pairs.sort(key=lambda p: (ranks.get(p[1], big), p[0]), reverse=False)
        if desc:
            pairs.reverse()
        chosen = [p[0] for p in pairs[offset:None if limit is None else offset + limit]]
        if not chosen:
            return [], total
        rows = {r.id: r for r in session.scalars(
            select(FindingRow).where(FindingRow.id.in_(chosen)))}
        return [rows[i] for i in chosen if i in rows], total
    q = filtered(session, scan_run_id, engagement_id, f).order_by(*_order(sort, desc))
    if offset:
        q = q.offset(offset)
    if limit is not None:
        q = q.limit(limit)
    return list(session.scalars(q)), total


# ---------- сводка прогона ----------
def summary(session: Session, scan_run_id: int, engagement_id: int) -> dict:
    """Счётчики прогона для плашек фильтров, KPI и тепловой карты хостов.

    Ложные срабатывания в счётчики уровней/хостов не входят (как в отчёте),
    их число — отдельно. fixed — уязвимости предыдущего успешного прогона,
    которых нет в этом."""
    fp = _fp_exists(engagement_id)
    base = (FindingRow.scan_run_id == scan_run_id)
    by_sev = dict(session.execute(
        select(FindingRow.severity, func.count()).where(base, ~fp)
        .group_by(FindingRow.severity)).all())
    counts = {str(s): int(by_sev.get(str(s), 0)) for s in Severity}
    issue = and_(base, ~fp, FindingRow.severity != "info")
    modules = sorted(m for (m,) in session.execute(
        select(FindingRow.module).where(base).distinct()).all())
    statuses = dict(session.execute(
        select(FindingRow.status, func.count()).where(issue)
        .group_by(FindingRow.status)).all())
    fp_count = session.scalar(select(func.count(FindingRow.id)).where(base, fp)) or 0
    if _pg(session):
        has_bdu = func.cardinality(FindingRow.bdu_ids) > 0
        has_ref = or_(has_bdu, func.cardinality(FindingRow.cve_ids) > 0,
                      FindingRow.module == "vuln")
    else:
        has_bdu = cast(FindingRow.bdu_ids, String) != "[]"
        has_ref = or_(has_bdu, cast(FindingRow.cve_ids, String) != "[]",
                      FindingRow.module == "vuln")
    vulns = session.scalar(select(func.count(FindingRow.id)).where(issue, has_ref)) or 0
    with_bdu = session.scalar(select(func.count(FindingRow.id)).where(issue, has_bdu)) or 0

    hosts: dict[str, dict] = {}
    for host, sev, n in session.execute(
            select(FindingRow.host, FindingRow.severity, func.count())
            .where(base, ~fp).group_by(FindingRow.host, FindingRow.severity)).all():
        h = hosts.setdefault(str(host), {"host": str(host),
                                         "counts": {str(s): 0 for s in Severity}})
        h["counts"][sev] = int(n)
    # хосты, найденные discovery без находок, тоже считаются живыми
    for (host,) in session.execute(select(HostResult.host)
                                   .where(HostResult.scan_run_id == scan_run_id)).all():
        hosts.setdefault(str(host), {"host": str(host),
                                     "counts": {str(s): 0 for s in Severity}})
    for h in hosts.values():
        h["total"] = sum(v for k, v in h["counts"].items() if k != "info")

    fixed = unverified = 0
    comparability = None
    run = session.get(ScanRun, scan_run_id)
    cur_cov = repo.run_coverage(session, run) if run is not None else None
    prev_id = repo.previous_scan_run_id(session, scan_run_id, coverage=cur_cov)
    if prev_id is not None:
        prev = FindingRow.__table__.alias("prev")
        prev_fp = exists().where(FalsePositiveRow.engagement_id == engagement_id,
                                 FalsePositiveRow.dedup_key == prev.c.dedup_key)
        now = exists().where(FindingRow.scan_run_id == scan_run_id,
                             FindingRow.dedup_key == prev.c.dedup_key)
        # исчезнувшие находки базы — исправлены, только если хост этим модулем
        # в этом прогоне действительно проверен; иначе «не проверено»
        for host, module, n in session.execute(
                select(prev.c.host, prev.c.module, func.count()).select_from(prev)
                .where(prev.c.scan_run_id == prev_id, prev.c.severity != "info",
                       ~prev_fp, ~now)
                .group_by(prev.c.host, prev.c.module)).all():
            if cur_cov is None or cur_cov.covered(str(host), module):
                fixed += int(n)
            else:
                unverified += int(n)
        if cur_cov is not None:
            from scanner.core.coverage import comparability as _cmp
            comparability = _cmp(repo.run_coverage(session, prev_id), cur_cov).to_dict()
    return {
        "unverified": int(unverified),
        "comparability": comparability,
        "coverage": cur_cov.summary() if cur_cov is not None else None,
        "counts": counts,
        "open": sum(v for k, v in counts.items() if k != "info"),
        "hosts": len(hosts),
        "new": int(statuses.get("new", 0)),
        "regression": int(statuses.get("regression", 0)),
        "fixed": int(fixed),
        "false_positives": int(fp_count),
        "bdu_share": None if not vulns else with_bdu / vulns,
        "modules": modules,
        "statuses": {k: int(v) for k, v in statuses.items() if k},
        "previous_run_id": prev_id,
        "host_counts": sorted(hosts.values(), key=lambda h: (
            [-h["counts"][s] for s in ("critical", "high", "medium", "low")],
            _ip_key(h["host"]))),
    }


def _ip_key(host: str):
    try:
        ip = ipaddress.ip_address(host)
        return (ip.version, int(ip))
    except ValueError:
        return (9, 0)


# ---------- тренд по прогонам ----------
# Прогоны на графике «Сводки»: завершённые, кроме «Ошибка» (как в веб-интерфейсе).
TREND_STATUSES = ("done", "partial", "stopped", "interrupted")
TREND_LEVELS = ("critical", "high", "medium", "low")
TREND_LIMIT_MAX = 1000


def trend(session: Session, engagement_id: int, *, since: datetime | None = None,
          limit: int | None = None) -> list[dict]:
    """Открытые находки по уровням в каждом прогоне договора — одним запросом
    для графика «Сводки» за период. Как counts в summary: без ложных
    срабатываний и информационных. Старые прогоны первыми; since — начатые не
    раньше этого времени, limit — последние N из них."""
    when = func.coalesce(ScanRun.started_at, ScanRun.created_at)
    q = (select(ScanRun.id, ScanRun.status, when.label("ts"), ScanRun.finished_at)
         .where(ScanRun.engagement_id == engagement_id, ScanRun.status.in_(TREND_STATUSES)))
    if since is not None:
        q = q.where(when >= since)
    cap = min(int(limit or TREND_LIMIT_MAX), TREND_LIMIT_MAX)
    runs = list(session.execute(q.order_by(ScanRun.id.desc()).limit(cap)).all())[::-1]
    if not runs:
        return []
    by_run: dict[int, dict[str, int]] = {r.id: dict.fromkeys(TREND_LEVELS, 0) for r in runs}
    for rid, sev, n in session.execute(
            select(FindingRow.scan_run_id, FindingRow.severity, func.count())
            .where(FindingRow.scan_run_id.in_(list(by_run)), FindingRow.severity != "info",
                   ~_fp_exists(engagement_id))
            .group_by(FindingRow.scan_run_id, FindingRow.severity)).all():
        if sev in by_run[rid]:
            by_run[rid][sev] = int(n)
    return [{"scan_run_id": r.id, "status": r.status, "started_at": r.ts,
             "finished_at": r.finished_at, "counts": by_run[r.id]} for r in runs]


# ---------- прогоны договора ----------
def page_runs(session: Session, engagement_id: int, *, statuses: Iterable[str] = (),
              query: str | None = None, sort: str = "id", desc: bool = True,
              limit: int | None = None, offset: int = 0) -> tuple[list[ScanRun], int]:
    q = select(ScanRun).where(ScanRun.engagement_id == engagement_id)
    statuses = list(statuses)
    if statuses:
        q = q.where(ScanRun.status.in_(statuses))
    text = (query or "").strip()
    if text:
        like = _like(text)
        conds = [ScanRun.name.ilike(like, escape="\\")]
        if text.lstrip("№#").isdigit():
            conds.append(ScanRun.id == int(text.lstrip("№#")))
        q = q.where(or_(*conds))
    total = session.scalar(select(func.count()).select_from(q.subquery())) or 0
    col = getattr(ScanRun, sort if sort in RUN_SORTS else "id")
    q = q.order_by(col.desc().nulls_last() if desc else col.asc().nulls_last(),
                   ScanRun.id.desc() if desc else ScanRun.id)
    if offset:
        q = q.offset(offset)
    if limit is not None:
        q = q.limit(limit)
    return list(session.scalars(q)), total
