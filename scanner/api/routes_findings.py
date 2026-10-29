"""Разбор находок: отметка «ложное срабатывание» и её снятие.

Отметка ставится на находку хоста, но хранится на уровне договора по dedup_key
(хост+порт+vuln_id+модуль) — та же находка в следующих прогонах тоже считается
ложной. Каждое действие пишется в журнал аудита: кто, что, с каким обоснованием.
"""
from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from scanner.api.deps import AuditDep, Principal, SessionDep, require
from scanner.api.rbac import Perm
from scanner.api.routes_engagements import get_engagement
from scanner.api.schemas import (
    FalsePositiveIn,
    FalsePositiveMarkOut,
    FalsePositiveOut,
    FindingOut,
)
from scanner.core import repository as repo
from scanner.core.db import FindingRow
from scanner.core.models import FalsePositiveMark

router = APIRouter(tags=["findings"])

TriageUser = Annotated[Principal, Depends(require(Perm.TRIAGE_FINDINGS))]


def finding_out(row: FindingRow, marks: dict[str, FalsePositiveMark]) -> FindingOut:
    f = repo.row_to_finding(row)
    mark = marks.get(row.dedup_key)
    return FindingOut(
        id=row.id, dedup_key=row.dedup_key, module=f.module, host=f.host, port=f.port,
        finding_type=str(f.finding_type), title=f.title, severity=str(f.severity),
        vuln_id=f.vuln_id, cve_ids=f.cve_ids, bdu_ids=f.bdu_ids, cvss=f.cvss,
        evidence=f.evidence, status=row.status, detected_at=f.detected_at,
        false_positive=None if mark is None else FalsePositiveMarkOut(
            reason=mark.reason, marked_by=mark.marked_by, marked_at=mark.marked_at))


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
    return finding_out(row, repo.false_positive_marks(session, row.engagement_id))


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
    return finding_out(row, repo.false_positive_marks(session, row.engagement_id))


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
