"""Прогоны: запуск/остановка, находки, инвентарь, отчёты."""
from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from scanner.api.deps import AuditDep, Principal, SessionDep, deny, require
from scanner.api.rbac import MODULE_PERMISSIONS, Perm
from scanner.api.routes_engagements import get_engagement
from scanner.api.schemas import (
    DeniedTargetOut,
    FindingOut,
    InventoryHostOut,
    PackageOut,
    RunCreate,
    RunCreated,
    RunOut,
    ServiceOut,
)
from scanner.core import repository as repo
from scanner.core.audit import AuditSink
from scanner.core.db import ScanRun
from scanner.core.orchestrator import (
    VULN_ENGINES,
    RunService,
    TargetPlan,
    order_modules,
)
from scanner.core.ratelimit import PROFILES

router = APIRouter(tags=["runs"])

FINISHED = {"done", "failed", "stopped"}


def _runs(request: Request) -> RunService:
    return request.app.state.runs


def _get_run(session: Session, run_id: int) -> ScanRun:
    run = repo.get_scan_run(session, run_id)
    if run is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "scan run not found")
    return run


@router.post("/engagements/{engagement_id}/runs", response_model=RunCreated,
             status_code=202)
def start_run(engagement_id: int, body: RunCreate, request: Request,
              user: Annotated[Principal, Depends(require(Perm.RUN_SCAN))],
              session: SessionDep,
              audit: AuditDep,
              runs: Annotated[RunService, Depends(_runs)]) -> RunCreated:
    get_engagement(session, engagement_id)
    modules = with_engine(body.modules, body.vuln_engine)
    check_run_options(engagement_id, modules=modules, rate_profile=body.rate_profile,
                      credential_ids=body.credential_ids, user=user, request=request,
                      audit=audit, runs=runs)
    plan, denied = check_targets(engagement_id, body.targets, user=user, audit=audit,
                                 runs=runs)

    session.commit()   # отпустить транзакцию запроса до работы исполнителя
    run_id = runs.submit(engagement_id=engagement_id, modules=modules,
                         rate_profile=body.rate_profile, requested_targets=body.targets,
                         actor=user.subject, started_by=user.id,
                         credential_ids=body.credential_ids, name=body.name)
    session.expire_all()
    run = _get_run(session, run_id)
    return RunCreated(**RunOut.model_validate(run).model_dump(),
                      accepted_targets=len(plan.allowed), denied_targets=denied)


def check_run_options(engagement_id: int, *, modules: list[str], rate_profile: str,
                      credential_ids: list[int], user: Principal, request: Request,
                      audit: AuditSink, runs: RunService) -> None:
    """Модули, профиль, права и учётки прогона — до постановки (и сохранения
    расписания). Ошибки — HTTPException 422/403."""
    unknown = [m for m in modules if m not in runs.registry]
    if unknown:
        raise HTTPException(422,
                            f"unknown modules: {', '.join(unknown)}; "
                            f"available: {', '.join(runs.known_modules())}")
    if rate_profile not in PROFILES:
        raise HTTPException(422,
                            f"unknown rate profile: {rate_profile}; "
                            f"available: {', '.join(PROFILES)}")
    # Права на отдельные модули — до постановки прогона в очередь.
    missing = missing_permissions(user, modules, credential_ids)
    if missing:
        deny(audit, user, request, missing)
    try:
        runs.check_credentials(engagement_id, modules, credential_ids)
    except ValueError as e:
        raise HTTPException(422, str(e)) from e


def missing_permissions(user: Principal, modules: list[str],
                        credential_ids: list[int]) -> list[str]:
    """Права, которых не хватает пользователю для такого прогона (кроме run_scan)."""
    missing = {str(MODULE_PERMISSIONS[m]) for m in modules
               if m in MODULE_PERMISSIONS and not user.has(MODULE_PERMISSIONS[m])}
    if credential_ids and not user.has(Perm.HOST_CREDENTIALS):
        missing.add(str(Perm.HOST_CREDENTIALS))
    return sorted(missing)


def check_targets(engagement_id: int, targets: list[str], *, user: Principal,
                  audit: AuditSink, runs: RunService
                  ) -> tuple[TargetPlan, list[DeniedTargetOut]]:
    """Цели через allowlist договора; ни одной разрешённой — 422 с перечнем отказов."""
    plan = runs.preview(engagement_id, targets)
    denied = [DeniedTargetOut(target=d.target, reason=d.reason, count=d.count)
              for d in plan.denied]
    if not plan.allowed:
        audit.record(subject=user.subject, action="scan_request",
                     target=f"engagement:{engagement_id}", result="rejected_no_targets",
                     details={"denied": [d.model_dump() for d in denied]})
        raise HTTPException(422,
                            {"message": "no requested target is in the engagement "
                                        "allowlist",
                             "denied_targets": [d.model_dump() for d in denied]})
    return plan, denied


def with_engine(modules: list[str], engine: str | None) -> list[str]:
    """Модули прогона с учётом выбранного движка поиска уязвимостей."""
    if engine is None:
        return list(modules)
    engine_modules = {m for ms in VULN_ENGINES.values() for m in ms}
    return order_modules([*(m for m in modules if m not in engine_modules),
                          *VULN_ENGINES[engine]])


@router.get("/engagements/{engagement_id}/runs", response_model=list[RunOut])
def list_runs(engagement_id: int, _: Annotated[Principal, Depends(require(Perm.VIEW_REPORT))],
              session: SessionDep) -> list[ScanRun]:
    get_engagement(session, engagement_id)
    return list(session.scalars(select(ScanRun).where(ScanRun.engagement_id == engagement_id)
                                .order_by(ScanRun.id)))


@router.get("/engagements/{engagement_id}/hosts", response_model=list[InventoryHostOut])
def list_hosts(engagement_id: int, _: Annotated[Principal, Depends(require(Perm.VIEW_REPORT))],
               session: SessionDep) -> list[InventoryHostOut]:
    """Инвентарь договора — не зависит от выбранного прогона."""
    get_engagement(session, engagement_id)
    return [InventoryHostOut(
                host=h["host"], os_guess=h["os_guess"], run_ids=h["run_ids"],
                services_run_id=h["services_run_id"],
                packages_run_id=h["packages_run_id"], package_count=h["package_count"],
                services=[ServiceOut(host=s.host, port=s.port, protocol=s.protocol,
                                     service=s.service, product=s.product,
                                     version=s.version, cpe=s.cpe)
                          for s in h["services"]])
            for h in repo.engagement_hosts(session, engagement_id)]


@router.get("/runs/{run_id}", response_model=RunOut)
def read_run(run_id: int, _: Annotated[Principal, Depends(require(Perm.VIEW_REPORT))],
             session: SessionDep) -> ScanRun:
    return _get_run(session, run_id)


@router.post("/runs/{run_id}/stop", response_model=RunOut)
def stop_run(run_id: int, user: Annotated[Principal, Depends(require(Perm.RUN_SCAN))],
             session: SessionDep,
             runs: Annotated[RunService, Depends(_runs)]) -> ScanRun:
    _get_run(session, run_id)
    session.commit()
    runs.request_stop(run_id, actor=user.subject)
    session.expire_all()
    return _get_run(session, run_id)


@router.get("/runs/{run_id}/findings", response_model=list[FindingOut])
def list_findings(run_id: int,
                  _: Annotated[Principal, Depends(require(Perm.VIEW_REPORT))],
                  session: SessionDep, module: str | None = None) -> list[FindingOut]:
    _get_run(session, run_id)
    statuses = repo.get_finding_statuses(session, run_id)
    return [FindingOut(module=f.module, host=f.host, port=f.port,
                       finding_type=str(f.finding_type), title=f.title,
                       severity=str(f.severity), vuln_id=f.vuln_id, cve_ids=f.cve_ids,
                       bdu_ids=f.bdu_ids, cvss=f.cvss, evidence=f.evidence,
                       status=statuses.get(f.dedup_key()), detected_at=f.detected_at)
            for f in repo.get_findings(session, run_id, module)]


@router.get("/runs/{run_id}/services", response_model=list[ServiceOut])
def list_services(run_id: int, _: Annotated[Principal, Depends(require(Perm.VIEW_REPORT))],
                  session: SessionDep) -> list[ServiceOut]:
    _get_run(session, run_id)
    return [ServiceOut(host=s.host, port=s.port, protocol=s.protocol, service=s.service,
                       product=s.product, version=s.version, cpe=s.cpe)
            for s in repo.get_services(session, run_id)]


@router.get("/runs/{run_id}/packages", response_model=list[PackageOut])
def list_packages(run_id: int, _: Annotated[Principal, Depends(require(Perm.VIEW_REPORT))],
                  session: SessionDep, host: str | None = None) -> list[PackageOut]:
    """Пакеты хостов, собранные инвентаризацией по учётной записи."""
    _get_run(session, run_id)
    try:
        rows = repo.get_packages(session, run_id, host)
    except ValueError as e:
        raise HTTPException(422, f"invalid host: {host}") from e
    return [PackageOut(host=h, manager=p.manager, name=p.name, version=p.version,
                       arch=p.arch) for h, p in rows]


@router.get("/runs/{run_id}/report")
def get_report(run_id: int, request: Request,
               user: Annotated[Principal, Depends(require(Perm.VIEW_REPORT))],
               session: SessionDep, audit: AuditDep,
               format: Annotated[str, Query(pattern="^(html|pdf|docx|json)$")] = "html",
               variant: Annotated[str, Query(pattern="^(full|brief)$")] = "full",
               compare_to: int | None = None) -> Response:
    """Отчёт по прогону. По умолчанию — только по этому прогону, без сравнения;
    compare_to=<id> — сравнить с выбранным более ранним прогоном договора.
    variant=brief — краткая версия: без плана устранения,
    по находкам вместо рекомендаций только ссылки на устранение."""
    from scanner.reporting.model import ReportContext, build_report
    from scanner.reporting.render import (
        CONTENT_TYPES,
        ReportFormat,
        ReportRenderer,
        ReportVariant,
    )

    run = _get_run(session, run_id)
    if run.status not in FINISHED:
        raise HTTPException(status.HTTP_409_CONFLICT,
                            f"scan run is {run.status}; report is available after it ends")
    eng = get_engagement(session, run.engagement_id)
    current = repo.get_findings(session, run_id)
    prev_id = None
    if compare_to is not None:
        try:
            prev_id = repo.comparison_baseline(session, run, compare_to).id
        except ValueError as e:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, str(e)) from e
    previous = repo.get_findings(session, prev_id) if prev_id is not None else None
    # regression — ключ был до базового прогона, в нём исчез и вернулся сейчас
    hist = (repo.historically_fixed_keys(session, eng.id, prev_id)
            if prev_id is not None else None)
    report = build_report(
        current, previous=previous, historically_fixed=hist,
        resolver=request.app.state.resolver_factory(current),
        context=ReportContext(customer=eng.client,
                              engagement=eng.contract_ref or eng.name,
                              run_id=run_id, previous_run_id=prev_id))
    fmt, var = ReportFormat(format), ReportVariant(variant)
    body = ReportRenderer().render(report, fmt, variant=var)
    audit.record(subject=user.subject, action="export", target=f"scan_run:{run_id}",
                 result="ok", details={"format": fmt.value, "variant": var.value,
                                       "previous_run_id": prev_id, "findings": len(current)})
    suffix = ("-brief" if var is ReportVariant.BRIEF else "") + (
        f"-vs-{prev_id}" if prev_id is not None else "")
    return Response(content=body, media_type=CONTENT_TYPES[fmt], headers={
        "Content-Disposition":
            f'attachment; filename="report-run-{run_id}{suffix}.{fmt.value}"'})
