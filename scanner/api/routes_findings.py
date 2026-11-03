"""Разбор находок: отметка «ложное срабатывание» и её снятие.

Отметка ставится на находку хоста, но хранится на уровне договора по dedup_key
(хост+порт+vuln_id+модуль) — та же находка в следующих прогонах тоже считается
ложной. Каждое действие пишется в журнал аудита: кто, что, с каким обоснованием.
"""
from __future__ import annotations

import logging
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from scanner.api.deps import AuditDep, Principal, SessionDep, require
from scanner.api.rbac import Perm
from scanner.api.routes_engagements import get_engagement
from scanner.api.schemas import (
    FalsePositiveIn,
    FalsePositiveMarkOut,
    FalsePositiveOut,
    FindingOut,
    FixPlanOut,
    PriorityOut,
)
from scanner.core import findings_query as fq
from scanner.core import repository as repo
from scanner.core.db import AssetRow, FindingRow, HostPackageRow
from scanner.core.models import (
    FalsePositiveMark,
    Finding,
    FindingType,
    ServiceInfo,
    Severity,
)
from scanner.core.software import software_of
from scanner.reporting.risk import RiskAssessment

log = logging.getLogger(__name__)
router = APIRouter(tags=["findings"])

TriageUser = Annotated[Principal, Depends(require(Perm.TRIAGE_FINDINGS))]


def services_by_port(session: Session, scan_run_id: int) -> dict[tuple[str, int], ServiceInfo]:
    """Сервисы прогона по (хост, порт) — чтобы назвать ПО находки."""
    return {(s.host, s.port): s for s in repo.get_services(session, scan_run_id)}


# Приоритеты прогона считаются по всем его находкам (ранг — место в прогоне),
# поэтому для постраничного вывода они кэшируются: ключ — прогон и набор
# отметок «ложное срабатывание» и критичность активов (они меняют баллы и
# ранги), срок — PRIORITY_TTL (за это время подхватываются обновлённые EPSS/KEV).
# Большой прогон (расчёт дольше PRIORITY_SLOW_SECONDS, это сотни тысяч находок)
# не держит запрос: пока в фоне считается новый вариант, отдаётся последний
# посчитанный для этого прогона.
PRIORITY_TTL = 300.0
PRIORITY_SLOW_SECONDS = 2.0
_PRIORITY_CACHE_SIZE = 32


@dataclass(slots=True)
class _Cached:
    at: float
    cost: float
    out: dict[str, RiskAssessment]


_priority_cache: OrderedDict[tuple[int, int], _Cached] = OrderedDict()
_priority_latest: dict[int, _Cached] = {}        # прогон → последний расчёт
_priority_refreshing: set[tuple[int, int]] = set()
_priority_lock = threading.Lock()


def run_priorities(session: Session, scan_run_id: int, engagement_id: int,
                   marks: dict[str, FalsePositiveMark]) -> dict[str, RiskAssessment]:
    """{dedup_key: приоритет} по находкам прогона (без ложных срабатываний)."""
    # критичность активов входит в балл — её изменение тоже сбрасывает кэш
    assets = session.execute(select(AssetRow.address, AssetRow.criticality)
                             .where(AssetRow.engagement_id == engagement_id)).all()
    key = (scan_run_id, hash((frozenset(marks), frozenset((str(a), c) for a, c in assets))))
    now = time.monotonic()
    with _priority_lock:
        hit = _priority_cache.get(key)
        if hit is not None and now - hit.at < PRIORITY_TTL:
            _priority_cache.move_to_end(key)
            return hit.out
        last = _priority_latest.get(scan_run_id)
        if last is not None and last.cost >= PRIORITY_SLOW_SECONDS:
            if key not in _priority_refreshing:
                _priority_refreshing.add(key)
                threading.Thread(target=_refresh, daemon=True, name="priority-refresh",
                                 args=(session.get_bind(), key, engagement_id,
                                       dict(marks))).start()
            return last.out
    return _compute(session, key, engagement_id, marks)


def _compute(session: Session, key: tuple[int, int], engagement_id: int,
             marks: dict[str, FalsePositiveMark]) -> dict[str, RiskAssessment]:
    from scanner.reporting.risk import build_risk_context, rank_findings

    t0 = time.monotonic()
    findings = [f for f in _risk_findings(session, key[0]) if f.dedup_key() not in marks]
    out = rank_findings(findings, build_risk_context(session, findings, engagement_id))
    entry = _Cached(at=t0, cost=time.monotonic() - t0, out=out)
    with _priority_lock:
        _priority_cache[key] = entry
        _priority_cache.move_to_end(key)
        _priority_latest[key[0]] = entry
        while len(_priority_cache) > _PRIORITY_CACHE_SIZE:
            old_key, _ = _priority_cache.popitem(last=False)
            if not any(k[0] == old_key[0] for k in _priority_cache):
                _priority_latest.pop(old_key[0], None)
    return out


def _refresh(bind, key: tuple[int, int], engagement_id: int,
             marks: dict[str, FalsePositiveMark]) -> None:
    try:
        with Session(bind=bind) as session:
            _compute(session, key, engagement_id, marks)
    except Exception:                      # фоновый пересчёт не роняет процесс
        log.exception("priority refresh failed for run %s", key[0])
    finally:
        with _priority_lock:
            _priority_refreshing.discard(key)


def _risk_findings(session: Session, scan_run_id: int) -> list[Finding]:
    """Находки прогона только с полями, нужными для приоритета.

    На прогоне в миллион находок полные ORM-строки (evidence, remediation)
    читаются в разы дольше; адрес берётся текстом без разбора inet."""
    host = fq._host_text(session)
    rows = session.execute(select(
        FindingRow.module, host, FindingRow.finding_type, FindingRow.severity,
        FindingRow.port, FindingRow.vuln_id, FindingRow.cve_ids, FindingRow.bdu_ids,
        FindingRow.cvss).where(FindingRow.scan_run_id == scan_run_id)
        .order_by(FindingRow.id))
    return [Finding(module=m, host=str(h), finding_type=FindingType(t), title="",
                    severity=Severity(sev), port=port, vuln_id=vid,
                    cve_ids=list(cves or []), bdu_ids=list(bdus or []),
                    cvss=None if cvss is None else float(cvss))
            for m, h, t, sev, port, vid, cves, bdus, cvss in rows]


def warm_priorities(session_factory, scan_run_id: int) -> None:
    """Посчитать приоритеты завершённого прогона заранее (в потоке прогона),
    чтобы первое открытие большого прогона не ждало расчёта."""
    try:
        with session_factory() as session:
            run = repo.get_scan_run(session, scan_run_id)
            if run is not None:
                run_priorities(session, scan_run_id, run.engagement_id,
                               repo.false_positive_marks(session, run.engagement_id))
    except Exception:                      # приоритет вторичен, прогон уже сохранён
        log.exception("priority warm-up failed for run %s", scan_run_id)


def clear_priority_cache() -> None:
    with _priority_lock:
        _priority_cache.clear()
        _priority_latest.clear()
        _fix_plan_cache.clear()


def finding_out(row: FindingRow, marks: dict[str, FalsePositiveMark],
                services: dict[tuple[str, int], ServiceInfo] | None = None,
                priorities: dict[str, RiskAssessment] | None = None) -> FindingOut:
    f = repo.row_to_finding(row)
    mark = marks.get(row.dedup_key)
    sw = software_of(f, services)
    return FindingOut(
        id=row.id, dedup_key=row.dedup_key, module=f.module, host=f.host, port=f.port,
        finding_type=str(f.finding_type), title=f.title, severity=str(f.severity),
        vuln_id=f.vuln_id, cve_ids=f.cve_ids, bdu_ids=f.bdu_ids, cvss=f.cvss,
        evidence=f.evidence, status=row.status, detected_at=f.detected_at,
        software=sw.name if sw else None, software_version=sw.version if sw else None,
        software_source=sw.source if sw else None,
        priority=_priority_out((priorities or {}).get(row.dedup_key)),
        false_positive=None if mark is None else FalsePositiveMarkOut(
            reason=mark.reason, marked_by=mark.marked_by, marked_at=mark.marked_at))


def _priority_out(a: RiskAssessment | None) -> PriorityOut | None:
    return None if a is None else PriorityOut(**a.to_dict())


def _get_finding(session: Session, finding_id: int) -> FindingRow:
    row = session.get(FindingRow, finding_id)
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "finding not found")
    return row


def _details(row: FindingRow, **extra) -> dict:
    return {"finding_id": row.id, "scan_run_id": row.scan_run_id,
            "host": str(row.host), "port": row.port, "vuln_id": row.vuln_id,
            "module": row.module, "title": row.title[:300], **extra}


@router.put("/findings/{finding_id}/false-positive", response_model=FindingOut)
def mark_false_positive(finding_id: int, body: FalsePositiveIn, user: TriageUser,
                        session: SessionDep, audit: AuditDep) -> FindingOut:
    row = _get_finding(session, finding_id)
    repo.mark_false_positive(session, row, reason=body.reason, marked_by=user.id)
    session.commit()
    audit.record(subject=user.subject, action="false_positive_mark",
                 target=f"engagement:{row.engagement_id}", result="ok",
                 details=_details(row, reason=body.reason))
    marks = repo.false_positive_marks(session, row.engagement_id)
    return finding_out(row, marks, services_by_port(session, row.scan_run_id),
                       run_priorities(session, row.scan_run_id, row.engagement_id, marks))


@router.delete("/findings/{finding_id}/false-positive", response_model=FindingOut)
def unmark_false_positive(finding_id: int, user: TriageUser, session: SessionDep,
                          audit: AuditDep) -> FindingOut:
    row = _get_finding(session, finding_id)
    removed = repo.unmark_false_positive(session, row.engagement_id, row.dedup_key)
    if removed is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND,
                            "finding is not marked as false positive")
    reason = removed.reason
    session.commit()
    audit.record(subject=user.subject, action="false_positive_unmark",
                 target=f"engagement:{row.engagement_id}", result="ok",
                 details=_details(row, previous_reason=reason))
    marks = repo.false_positive_marks(session, row.engagement_id)
    return finding_out(row, marks, services_by_port(session, row.scan_run_id),
                       run_priorities(session, row.scan_run_id, row.engagement_id, marks))


@router.get("/engagements/{engagement_id}/false-positives",
            response_model=list[FalsePositiveOut])
def list_false_positives(engagement_id: int,
                         _: Annotated[Principal, Depends(require(Perm.VIEW_REPORT))],
                         session: SessionDep) -> list[FalsePositiveOut]:
    get_engagement(session, engagement_id)
    marks = repo.false_positive_marks(session, engagement_id)
    return [FalsePositiveOut(
                dedup_key=r.dedup_key, host=str(r.host), port=r.port, vuln_id=r.vuln_id,
                module=r.module, title=r.title, reason=r.reason,
                marked_by=marks[r.dedup_key].marked_by, marked_at=r.marked_at)
            for r in repo.list_false_positives(session, engagement_id)]


@router.get("/findings/{finding_id}", response_model=FindingOut)
def read_finding(finding_id: int,
                 _: Annotated[Principal, Depends(require(Perm.VIEW_REPORT))],
                 session: SessionDep) -> FindingOut:
    """Одна находка — для карточки из плана исправлений (отметка ложного срабатывания)."""
    row = _get_finding(session, finding_id)
    marks = repo.false_positive_marks(session, row.engagement_id)
    return finding_out(row, marks, services_by_port(session, row.scan_run_id),
                       run_priorities(session, row.scan_run_id, row.engagement_id, marks))


# --- план исправлений («Находки» → «Что исправить») ---------------------------
# Строится по всем находкам прогона, поэтому кэшируется так же, как приоритеты:
# ключ — прогон и набор отметок «ложное срабатывание».
FIX_PLAN_TTL = 300.0
_FIX_PLAN_CACHE_SIZE = 16
_fix_plan_cache: OrderedDict[tuple[int, int], tuple[float, list, int]] = OrderedDict()


def _host_managers(session: Session, scan_run_id: int) -> dict[str, str]:
    rows = session.execute(select(HostPackageRow.host, HostPackageRow.manager)
                           .where(HostPackageRow.scan_run_id == scan_run_id)
                           .distinct()).all()
    return {str(h): m for h, m in rows}


def fix_plan(request: Request, session: Session, scan_run_id: int, engagement_id: int,
             cacheable: bool = True):
    """(действия исправления, исключено ложных срабатываний) по прогону.
    cacheable=False — прогон ещё идёт, находки добавляются: без кэша."""
    from scanner.reporting.fixplan import build_fix_plan

    marks = repo.false_positive_marks(session, engagement_id)
    key = (scan_run_id, hash(frozenset(marks)))
    now = time.monotonic()
    with _priority_lock:
        hit = _fix_plan_cache.get(key)
        if cacheable and hit is not None and now - hit[0] < FIX_PLAN_TTL:
            _fix_plan_cache.move_to_end(key)
            return hit[1], hit[2]
    rows = repo.get_finding_rows(session, scan_run_id)
    items, fps = [], 0
    for r in rows:
        if r.dedup_key in marks:
            fps += 1
            continue
        items.append((r.id, repo.row_to_finding(r)))
    findings = [f for _, f in items]
    resolver = request.app.state.resolver_factory(findings)
    # ОС хостов без учётки — из инвентаря договора; ОС из прогона точнее
    resolver.add_host_os(repo.host_os_names(session, engagement_id), override=False)
    tasks = build_fix_plan(
        items, resolver=resolver, managers=_host_managers(session, scan_run_id),
        services=services_by_port(session, scan_run_id),
        priorities=run_priorities(session, scan_run_id, engagement_id, marks))
    if not cacheable:
        return tasks, fps
    with _priority_lock:
        _fix_plan_cache[key] = (now, tasks, fps)
        _fix_plan_cache.move_to_end(key)
        while len(_fix_plan_cache) > _FIX_PLAN_CACHE_SIZE:
            _fix_plan_cache.popitem(last=False)
    return tasks, fps


@router.get("/runs/{run_id}/fixes", response_model=FixPlanOut)
def list_fixes(run_id: int, request: Request,
               _: Annotated[Principal, Depends(require(Perm.VIEW_REPORT))],
               session: SessionDep,
               severity: Annotated[list[str] | None, Query()] = None,
               kind: Annotated[list[str] | None, Query()] = None,
               os: Annotated[list[str] | None, Query()] = None,
               host: Annotated[str | None, Query(max_length=64)] = None,
               q: Annotated[str | None, Query(max_length=200)] = None,
               limit: Annotated[int, Query(ge=1, le=500)] = 50,
               offset: Annotated[int, Query(ge=0)] = 0) -> dict:
    """План исправлений прогона для администраторов: находки, собранные в
    действия («обновить пакет P до версии V на ОС X»), с командами для менеджера
    пакетов ОС хоста, проверкой результата и списком хостов. Ложные
    срабатывания не входят. Порядок — по приоритету (R6), затем по уровню.
    os — подпись ОС («Debian 12»); «-» — действия без привязки к ОС."""
    from scanner.api.routes_runs import FINISHED, _get_run
    from scanner.reporting.fixplan import KINDS

    run = _get_run(session, run_id)
    tasks, fps = fix_plan(request, session, run_id, run.engagement_id,
                          cacheable=run.status in FINISHED)
    hosts = {h.host for t in tasks for h in t.hosts}
    out = {"tasks": len(tasks), "hosts": len(hosts),
           "findings": sum(t.findings for t in tasks), "false_positives": fps,
           "kinds": {}, "os": {}, "severities": {}}
    for t in tasks:
        out["kinds"][t.kind] = out["kinds"].get(t.kind, 0) + 1
        out["os"][t.os or "-"] = out["os"].get(t.os or "-", 0) + 1
        out["severities"][str(t.severity)] = out["severities"].get(str(t.severity), 0) + 1
    out["kinds"] = {k: out["kinds"][k] for k in KINDS if k in out["kinds"]}
    sel = tasks
    if severity:
        sel = [t for t in sel if str(t.severity) in severity]
    if kind:
        kinds = set(kind)
        if "package" in kinds:             # «обновление пакета» — с версией и без
            kinds.add("package_upgrade")
        sel = [t for t in sel if t.kind in kinds]
    if os:
        sel = [t for t in sel if (t.os or "-") in os]
    if host:
        h = host.strip()
        sel = [t for t in sel if any(x.host == h for x in t.hosts)]
    if q and q.strip():
        needle = q.strip().lower()
        sel = [t for t in sel if needle in t.search_text()]
    out["total"] = len(sel)
    out["items"] = [t.to_dict() for t in sel[offset:offset + limit]]
    return out
