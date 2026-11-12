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

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response, status
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
    SoftwareFalsePositiveIn,
    SoftwareFalsePositiveOut,
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
    from scanner.core.confidence import infer
    source, confidence = infer(f)      # у находок до миграции 0020 — по модулю
    return FindingOut(
        id=row.id, dedup_key=row.dedup_key, module=f.module, host=f.host, port=f.port,
        finding_type=str(f.finding_type), title=f.title, severity=str(f.severity),
        vuln_id=f.vuln_id, cve_ids=f.cve_ids, bdu_ids=f.bdu_ids, cvss=f.cvss,
        evidence=f.evidence, status=row.status, detected_at=f.detected_at,
        software=sw.name if sw else None, software_version=sw.version if sw else None,
        software_source=sw.source if sw else None,
        priority=_priority_out((priorities or {}).get(row.dedup_key)),
        confidence=confidence, source=source,
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

    run = _get_run(session, run_id)
    tasks, fps = fix_plan(request, session, run_id, run.engagement_id,
                          cacheable=run.status in FINISHED)
    return _fix_plan_out(tasks, fps, severity=severity, kind=kind, os=os, host=host,
                         q=q, limit=limit, offset=offset)


def _fix_plan_out(tasks: list, fps: int, *, severity: list[str] | None, kind: list[str] | None,
                  os: list[str] | None, host: str | None, q: str | None,
                  limit: int, offset: int) -> dict:
    """Ответ FixPlanOut: счётчики по всему плану, фильтры, страница действий."""
    from scanner.reporting.fixplan import KINDS

    hosts = {h.host for t in tasks for h in t.hosts}
    out = {"tasks": len(tasks), "hosts": len(hosts),
           "findings": sum(t.findings for t in tasks), "false_positives": fps,
           "kinds": {}, "os": {}, "severities": {}}
    for t in tasks:
        out["kinds"][t.kind] = out["kinds"].get(t.kind, 0) + 1
        out["os"][t.os or "-"] = out["os"].get(t.os or "-", 0) + 1
        out["severities"][str(t.severity)] = out["severities"].get(str(t.severity), 0) + 1
    out["kinds"] = {k: out["kinds"][k] for k in KINDS if k in out["kinds"]}
    sel = _filter_tasks(tasks, severity=severity, kind=kind, os=os, host=host, q=q)
    out["total"] = len(sel)
    out["items"] = [t.to_dict() for t in sel[offset:offset + limit]]
    return out


def _filter_tasks(tasks: list, *, severity: list[str] | None, kind: list[str] | None,
                  os: list[str] | None, host: str | None, q: str | None) -> list:
    """Действия плана по фильтрам экрана «Что исправить» (порядок сохраняется)."""
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
    return sel


@router.get("/engagements/{engagement_id}/hosts/{host}/fixes", response_model=FixPlanOut)
def host_fixes(engagement_id: int, host: str, request: Request,
               _: Annotated[Principal, Depends(require(Perm.VIEW_REPORT))],
               session: SessionDep,
               severity: Annotated[list[str] | None, Query()] = None,
               kind: Annotated[list[str] | None, Query()] = None,
               q: Annotated[str | None, Query(max_length=200)] = None,
               limit: Annotated[int, Query(ge=1, le=500)] = 50,
               offset: Annotated[int, Query(ge=0)] = 0) -> dict:
    """План исправлений одного актива по последним известным данным: находки
    хоста по каждому виду проверки — из последнего прогона, где она хост
    проверила (как GET /engagements/{id}/hosts/{host}/latest). Карточка актива
    в «Активах» без выбранного прогона. Ложные срабатывания не входят."""
    tasks, fps = _host_fix_plan(request, session, engagement_id, host)
    return _fix_plan_out(tasks, fps, severity=severity, kind=kind, os=None, host=None,
                         q=q, limit=limit, offset=offset)


def _host_key(host: str) -> str:
    try:
        return str(ipaddress.ip_address(host.strip()))
    except ValueError as e:
        raise HTTPException(422, f"invalid host: {host}") from e


def _host_fix_plan(request: Request, session: Session, engagement_id: int, host: str):
    """(действия, исключено ложных) по последним известным данным хоста."""
    from scanner.core import host_latest
    from scanner.reporting.fixplan import build_fix_plan

    get_engagement(session, engagement_id)
    key = _host_key(host)
    lt, rows = host_latest.latest_findings(session, engagement_id, key)
    marks = repo.false_positive_marks(session, engagement_id)
    items, fps = [], 0
    for r in rows:
        if r.dedup_key in marks:
            fps += 1
            continue
        items.append((r.id, repo.row_to_finding(r)))
    managers: dict[str, str] = {}
    services: dict = {}
    priorities: dict[str, RiskAssessment] = {}
    # от старых прогонов к новым: данные последнего прогона важнее
    for rid in sorted(lt.run_ids):
        managers.update({h: m for h, m in _host_managers(session, rid).items()
                         if _same_host(h, key)})
        services.update({k: v for k, v in services_by_port(session, rid).items()
                         if _same_host(k[0], key)})
        priorities.update(run_priorities(session, rid, engagement_id, marks))
    resolver = request.app.state.resolver_factory([f for _, f in items])
    resolver.add_host_os(repo.host_os_names(session, engagement_id), override=False)
    tasks = build_fix_plan(items, resolver=resolver, managers=managers,
                           services=services, priorities=priorities)
    return tasks, fps


FIX_SHEETS = ("tasks", "hosts")


def _fixes_file(fmt_value: str, sheet: str, tasks: list, info_pairs: list, stem: str,
                *, user: Principal, audit, target: str):
    from scanner.api.routes_runs import table_response
    from scanner.reporting import tabular
    from scanner.reporting.export import fix_plan_sheets

    fmt = tabular.TableFormat(fmt_value)
    main, per_host = fix_plan_sheets(tasks)
    if fmt is tabular.TableFormat.CSV and sheet == "hosts":
        main, per_host = per_host, main
        stem += "-hosts"
    body = tabular.render(fmt, main, per_host, info=tabular.info_sheet(info_pairs))
    audit.record(subject=user.subject, action="export", target=target, result="ok",
                 details={"table": "fixes", "format": fmt.value, "tasks": len(tasks),
                          "sheet": sheet if fmt is tabular.TableFormat.CSV else None})
    return table_response(fmt, body, stem)


@router.get("/runs/{run_id}/fixes/export")
def export_fixes(run_id: int, request: Request,
                 user: Annotated[Principal, Depends(require(Perm.VIEW_REPORT))],
                 session: SessionDep, audit: AuditDep,
                 format: Annotated[str, Query(pattern="^(csv|xlsx)$")] = "xlsx",
                 sheet: Annotated[str, Query(pattern="^(tasks|hosts)$")] = "tasks",
                 severity: Annotated[list[str] | None, Query()] = None,
                 kind: Annotated[list[str] | None, Query()] = None,
                 os: Annotated[list[str] | None, Query()] = None,
                 host: Annotated[str | None, Query(max_length=64)] = None,
                 q: Annotated[str | None, Query(max_length=200)] = None) -> Response:
    """«Что исправить» в CSV или Excel — с фильтрами экрана, весь план без страниц.
    XLSX: лист действий (команды, проверка, хосты, CVE/БДУ, ссылки), лист
    «По хостам» (строка на действие × хост — удобно раздать администраторам) и
    «Сведения». CSV — один лист: sheet=tasks (по умолчанию) или sheet=hosts.
    Сроков устранения нет."""
    from scanner.api.routes_runs import FINISHED, _export_info, _get_run, labeled
    from scanner.reporting.export import SEVERITY_BY_VALUE
    from scanner.reporting.fixplan import KIND_LABELS

    run = _get_run(session, run_id)
    tasks, fps = fix_plan(request, session, run_id, run.engagement_id,
                          cacheable=run.status in FINISHED)
    sel = _filter_tasks(tasks, severity=severity, kind=kind, os=os, host=host, q=q)
    eng = get_engagement(session, run.engagement_id)
    info = _export_info(eng, run, user, rows=len(sel), filters={
        "Уровень": labeled(severity, SEVERITY_BY_VALUE),
        "Действие": labeled(kind, KIND_LABELS), "ОС": os, "Хост": host, "Поиск": q,
        "Исключено ложных срабатываний": fps or None})
    return _fixes_file(format, sheet, sel, info, f"fixes-run-{run_id}", user=user,
                       audit=audit, target=f"scan_run:{run_id}")


@router.get("/engagements/{engagement_id}/hosts/{host}/fixes/export")
def export_host_fixes(engagement_id: int, host: str, request: Request,
                      user: Annotated[Principal, Depends(require(Perm.VIEW_REPORT))],
                      session: SessionDep, audit: AuditDep,
                      format: Annotated[str, Query(pattern="^(csv|xlsx)$")] = "xlsx",
                      sheet: Annotated[str, Query(pattern="^(tasks|hosts)$")] = "tasks",
                      severity: Annotated[list[str] | None, Query()] = None,
                      kind: Annotated[list[str] | None, Query()] = None,
                      q: Annotated[str | None, Query(max_length=200)] = None) -> Response:
    """План исправлений одного актива (последние данные хоста) в CSV или Excel."""
    from scanner.api.routes_runs import _export_info, labeled
    from scanner.reporting.export import SEVERITY_BY_VALUE
    from scanner.reporting.fixplan import KIND_LABELS

    tasks, fps = _host_fix_plan(request, session, engagement_id, host)
    sel = _filter_tasks(tasks, severity=severity, kind=kind, os=None, host=None, q=q)
    key = _host_key(host)
    eng = get_engagement(session, engagement_id)
    info = _export_info(eng, None, user, rows=len(sel),
                        source=f"Хост {key}: последние данные по каждому виду проверки",
                        filters={"Уровень": labeled(severity, SEVERITY_BY_VALUE),
                                 "Действие": labeled(kind, KIND_LABELS), "Поиск": q,
                                 "Исключено ложных срабатываний": fps or None})
    return _fixes_file(format, sheet, sel, info, f"fixes-host-{key.replace(':', '_')}",
                       user=user, audit=audit, target=f"engagement:{engagement_id}")


def _same_host(a: object, b: str) -> bool:
    try:
        return str(ipaddress.ip_address(str(a).split("/")[0])) == b
    except ValueError:
        return False


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
