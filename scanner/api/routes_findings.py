"""Разбор находок: отметка «ложное срабатывание» и её снятие.

Отметка ставится на находку хоста, но хранится на уровне договора по dedup_key
(хост+порт+vuln_id+модуль) — та же находка в следующих прогонах тоже считается
ложной. Каждое действие пишется в журнал аудита: кто, что, с каким обоснованием.
"""
from __future__ import annotations

import ipaddress
import logging
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
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
    PriorityOut,
    SoftwareFalsePositiveIn,
    SoftwareFalsePositiveOut,
)
from scanner.core import findings_query as fq
from scanner.core import repository as repo
from scanner.core.db import AssetRow, FindingRow
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


# В журнал аудита массового действия — не больше стольких находок поимённо.
AUDIT_FINDINGS_LIMIT = 200


def _software_rows(session: Session, run_id: int,
                   body: SoftwareFalsePositiveIn) -> list[FindingRow]:
    """Уязвимости прогона (без info), относящиеся к указанному ПО."""
    q = select(FindingRow).where(FindingRow.scan_run_id == run_id,
                                 FindingRow.severity != Severity.INFO.value)
    if not body.all_hosts:
        try:
            q = q.where(FindingRow.host == str(ipaddress.ip_address(body.host)))
        except ValueError:
            raise HTTPException(422, "host must be an IP address") from None
    services = services_by_port(session, run_id)
    name = body.software.casefold()
    out = []
    for row in session.scalars(q.order_by(FindingRow.id)):
        sw = software_of(repo.row_to_finding(row), services)
        if sw is not None and sw.name.casefold() == name and \
                (sw.version or None) == body.version:
            out.append(row)
    return out


def _software_fp(run_id: int, body: SoftwareFalsePositiveIn, user: Principal,
                 session: Session, audit, *, mark: bool) -> SoftwareFalsePositiveOut:
    run = repo.get_scan_run(session, run_id)
    if run is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "scan run not found")
    rows = _software_rows(session, run_id, body)
    marks = repo.false_positive_marks(session, run.engagement_id)
    # одна отметка на dedup_key; меняем только то, что ещё не в нужном состоянии
    todo: dict[str, FindingRow] = {}
    for r in rows:
        if (r.dedup_key in marks) != mark:
            todo.setdefault(r.dedup_key, r)
    result = SoftwareFalsePositiveOut(matched=len(rows), changed=len(todo),
                                      hosts=len({str(r.host) for r in rows}),
                                      dry_run=body.dry_run)
    if body.dry_run or not todo:
        return result
    for r in todo.values():
        if mark:
            repo.mark_false_positive(session, r, reason=body.reason, marked_by=user.id)
        else:
            repo.unmark_false_positive(session, run.engagement_id, r.dedup_key)
    session.commit()
    changed = list(todo.values())
    audit.record(
        subject=user.subject,
        action="false_positive_mark_software" if mark else "false_positive_unmark_software",
        target=f"engagement:{run.engagement_id}", result="ok",
        details={"scan_run_id": run_id, "software": body.software,
                 "version": body.version,
                 "host": "*" if body.all_hosts else body.host,
                 "reason": body.reason if mark else None,
                 "count": len(changed), "hosts": result.hosts,
                 "findings": [{"host": str(r.host), "port": r.port,
                               "vuln_id": r.vuln_id, "module": r.module}
                              for r in changed[:AUDIT_FINDINGS_LIMIT]]})
    return result


@router.post("/runs/{run_id}/false-positives/by-software",
             response_model=SoftwareFalsePositiveOut)
def mark_software_false_positive(run_id: int, body: SoftwareFalsePositiveIn,
                                 user: TriageUser, session: SessionDep,
                                 audit: AuditDep) -> SoftwareFalsePositiveOut:
    """Все уязвимости ПО на хосте (или на всех хостах прогона) — в ложные
    срабатывания одним действием. Уже отмеченные не трогаются (их обоснование
    сохраняется). Действие пишется в аудит одной записью со списком находок."""
    return _software_fp(run_id, body, user, session, audit, mark=True)


@router.post("/runs/{run_id}/false-positives/by-software/unmark",
             response_model=SoftwareFalsePositiveOut)
def unmark_software_false_positive(run_id: int, body: SoftwareFalsePositiveIn,
                                   user: TriageUser, session: SessionDep,
                                   audit: AuditDep) -> SoftwareFalsePositiveOut:
    """Снять отметку «ложное срабатывание» со всех уязвимостей ПО."""
    return _software_fp(run_id, body, user, session, audit, mark=False)
