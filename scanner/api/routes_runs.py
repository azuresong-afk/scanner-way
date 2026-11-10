"""Прогоны: запуск/остановка, находки, инвентарь, отчёты."""
from __future__ import annotations

import ipaddress
from collections.abc import Iterable
from datetime import UTC, datetime, timedelta
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from scanner.api.deps import AuditDep, Principal, SessionDep, deny, require
from scanner.api.rbac import MODULE_PERMISSIONS, Perm
from scanner.api.routes_engagements import get_engagement
from scanner.api.routes_findings import finding_out, run_priorities, services_by_port
from scanner.api.schemas import (
    CoverageOut,
    DeniedTargetOut,
    FindingOut,
    FindingsSummaryOut,
    HostLatestOut,
    InventoryHostOut,
    PackageOut,
    RunCreate,
    RunCreated,
    RunEventOut,
    RunOut,
    ServiceOut,
    TrendRunOut,
)
from scanner.core import findings_query as fq
from scanner.core import host_latest, run_events
from scanner.core import repository as repo
from scanner.core.audit import AuditSink
from scanner.core.db import ScanRun
from scanner.core.orchestrator import (
    RETRYABLE,
    VULN_ENGINES,
    RunService,
    TargetPlan,
    order_modules,
)
from scanner.core.ratelimit import PROFILES

router = APIRouter(tags=["runs"])

FINISHED = repo.FINISHED_RUN_STATUSES


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
    modules, _plan = run_plan(session, engagement_id, body, runs)
    check_run_options(engagement_id, modules=modules, rate_profile=body.rate_profile,
                      credential_ids=body.credential_ids, cred_set_ids=body.cred_set_ids,
                      user=user, request=request, audit=audit, runs=runs)
    plan, denied = check_targets(engagement_id, body.targets, user=user, audit=audit,
                                 runs=runs)
    try:
        runs.check_node(body.node_id, credential_ids=body.credential_ids,
                        cred_set_ids=body.cred_set_ids)
    except ValueError as e:
        raise HTTPException(422, str(e)) from e

    session.commit()   # отпустить транзакцию запроса до работы исполнителя
    run_id = runs.submit(engagement_id=engagement_id, modules=modules,
                         rate_profile=body.rate_profile, requested_targets=body.targets,
                         actor=user.subject, started_by=user.id,
                         credential_ids=body.credential_ids,
                         cred_set_ids=body.cred_set_ids, name=body.name,
                         options={"no_ping": body.no_ping, "profile": body.profile},
                         node_id=body.node_id)
    session.expire_all()
    run = _get_run(session, run_id)
    return RunCreated(**RunOut.model_validate(run).model_dump(),
                      accepted_targets=len(plan.allowed), denied_targets=denied)


def run_plan(session: Session, engagement_id: int, body: RunCreate, runs: RunService):
    """(модули к запуску, итоговый план с предупреждениями) — профиль, движок,
    неприменимые модули (WinRM-инвентаризация без WinRM-учётки и т. п.)."""
    from scanner.core.profiles import PROFILES as RUN_PROFILES
    from scanner.core.profiles import plan_modules
    if body.profile:
        prof = RUN_PROFILES.get(body.profile)
        if prof is None:
            raise HTTPException(422, f"unknown profile: {body.profile}; available: "
                                     f"{', '.join(RUN_PROFILES)}")
        modules = [m for m in prof.modules if m in runs.registry]
        auto = set(modules)
    else:
        modules = with_engine(body.modules, body.vuln_engine, runs.registry)
        auto = set(VULN_ENGINES[body.vuln_engine]) if body.vuln_engine else set()
    wanted = set(body.credential_ids)
    protocols = {r.protocol or "ssh" for r in repo.list_host_credentials(session, engagement_id)
                 if r.id in wanted}
    plan = plan_modules(modules, protocols=protocols, engine_modules=auto,
                        known=runs.registry, no_ping=body.no_ping)
    removed = {m.name for m in plan.removed}
    return [m for m in modules if m not in removed], plan


@router.post("/engagements/{engagement_id}/runs/plan")
def preview_run(engagement_id: int, body: RunCreate,
                _: Annotated[Principal, Depends(require(Perm.RUN_SCAN))],
                session: SessionDep,
                runs: Annotated[RunService, Depends(_runs)]) -> dict:
    """Итоговый состав прогона до запуска: модули (со спутниками), что убрано
    как неприменимое и предупреждения о неполной проверке. Ничего не запускает."""
    get_engagement(session, engagement_id)
    _, plan = run_plan(session, engagement_id, body, runs)
    targets = runs.preview(engagement_id, body.targets)
    return {**plan.to_dict(), "accepted_targets": len(targets.allowed),
            "denied_targets": [{"target": d.target, "reason": d.reason, "count": d.count}
                               for d in targets.denied]}


@router.get("/run-profiles")
def list_run_profiles(_: Annotated[Principal, Depends(require(Perm.VIEW_REPORT))]
                      ) -> list[dict]:
    """Готовые профили проверки («Полная проверка Linux» и др.)."""
    from scanner.core.profiles import PROFILES as RUN_PROFILES
    return [{"id": p.id, "title": p.title, "description": p.description,
             "modules": list(p.modules), "needs": list(p.needs)}
            for p in RUN_PROFILES.values()]


def check_run_options(engagement_id: int, *, modules: list[str], rate_profile: str,
                      credential_ids: list[int], user: Principal, request: Request,
                      audit: AuditSink, runs: RunService,
                      cred_set_ids: list[int] | None = None) -> None:
    """Модули, профиль, права, учётки и наборы проверки прогона — до постановки
    (и сохранения расписания). Ошибки — HTTPException 422/403."""
    cred_set_ids = cred_set_ids or []
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
    missing = missing_permissions(user, modules, credential_ids, cred_set_ids)
    if missing:
        deny(audit, user, request, missing)
    try:
        runs.check_credentials(engagement_id, modules, credential_ids)
        runs.check_cred_sets(engagement_id, cred_set_ids)
    except ValueError as e:
        raise HTTPException(422, str(e)) from e


def missing_permissions(user: Principal, modules: list[str],
                        credential_ids: list[int],
                        cred_set_ids: list[int] | None = None) -> list[str]:
    """Права, которых не хватает пользователю для такого прогона (кроме run_scan)."""
    missing = {str(MODULE_PERMISSIONS[m]) for m in modules
               if m in MODULE_PERMISSIONS and not user.has(MODULE_PERMISSIONS[m])}
    if credential_ids and not user.has(Perm.HOST_CREDENTIALS):
        missing.add(str(Perm.HOST_CREDENTIALS))
    # Выбор набора проверки учёток требует права cred_audit (как и сам модуль).
    if cred_set_ids and not user.has(Perm.CRED_AUDIT):
        missing.add(str(Perm.CRED_AUDIT))
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


def with_engine(modules: list[str], engine: str | None,
                known: Iterable[str] | None = None) -> list[str]:
    """Модули прогона с учётом выбранного движка поиска уязвимостей.

    known — реестр модулей: модуль движка вне реестра (сборка без модуля
    сетевого оборудования и т. п.) не добавляется."""
    if engine is None:
        return list(modules)
    engine_modules = {m for ms in VULN_ENGINES.values() for m in ms}
    allowed = None if known is None else set(known)
    return order_modules([*(m for m in modules if m not in engine_modules),
                          *(m for m in VULN_ENGINES[engine]
                            if allowed is None or m in allowed)])


@router.get("/engagements/{engagement_id}/runs", response_model=list[RunOut])
def list_runs(engagement_id: int, response: Response,
              _: Annotated[Principal, Depends(require(Perm.VIEW_REPORT))],
              session: SessionDep,
              status_: Annotated[list[str] | None, Query(alias="status")] = None,
              q: Annotated[str | None, Query(max_length=200)] = None,
              sort: Annotated[str, Query(pattern=f"^({'|'.join(fq.RUN_SORTS)})$")] = "id",
              order: Annotated[str | None, Query(pattern="^(asc|desc)$")] = None,
              limit: Annotated[int | None, Query(ge=1, le=500)] = None,
              offset: Annotated[int, Query(ge=0)] = 0) -> list[ScanRun]:
    """Прогоны договора. Без limit — все (как раньше, по возрастанию id); с
    limit — страница (по умолчанию новые сверху). Всего — в X-Total-Count."""
    get_engagement(session, engagement_id)
    paged = limit is not None or offset or status_ or q or order is not None
    if not paged and sort == "id":
        rows = list(session.scalars(select(ScanRun).where(
            ScanRun.engagement_id == engagement_id).order_by(ScanRun.id)))
        response.headers["X-Total-Count"] = str(len(rows))
        return rows
    rows, total = fq.page_runs(session, engagement_id, statuses=status_ or (), query=q,
                               sort=sort, desc=(order or "desc") == "desc",
                               limit=limit, offset=offset)
    response.headers["X-Total-Count"] = str(total)
    return rows


@router.get("/engagements/{engagement_id}/trend", response_model=list[TrendRunOut])
def runs_trend(engagement_id: int,
               _: Annotated[Principal, Depends(require(Perm.VIEW_REPORT))],
               session: SessionDep,
               days: Annotated[int | None, Query(ge=1, le=3660)] = None,
               limit: Annotated[int | None, Query(ge=1, le=fq.TREND_LIMIT_MAX)] = None,
               ) -> list[dict]:
    """Открытые уязвимости по уровням в каждом прогоне — для графика «Сводки»
    за период («10 прогонов», «3 месяца», «Год») одним запросом. days —
    прогоны, начатые за последние N дней; limit — последние N прогонов."""
    get_engagement(session, engagement_id)
    since = datetime.now(UTC) - timedelta(days=days) if days else None
    return fq.trend(session, engagement_id, since=since, limit=limit)


@router.get("/engagements/{engagement_id}/hosts", response_model=list[InventoryHostOut])
def list_hosts(engagement_id: int, _: Annotated[Principal, Depends(require(Perm.VIEW_REPORT))],
               session: SessionDep,
               os_family: Annotated[str | None, Query(max_length=32)] = None
               ) -> list[InventoryHostOut]:
    """Инвентарь договора — не зависит от выбранного прогона.

    `os_family` оставляет хосты одного семейства ОС (`unknown` — без ОС).
    `latest_*` — последние известные уязвимости хоста по всем прогонам
    (scanner.core.host_latest): непроверенное в новом прогоне не считается
    исправленным.
    """
    get_engagement(session, engagement_id)
    latest = host_latest.latest_counts(session, engagement_id)
    out = []
    for h in repo.engagement_hosts(session, engagement_id, os_family=os_family):
        lt = latest.get(h["host"])
        out.append(InventoryHostOut(
            host=h["host"], os_guess=h["os_guess"], run_ids=h["run_ids"],
            os_family=h["os_family"], os_family_label=h["os_family_label"],
            os_source=h["os_source"], os_accuracy=h["os_accuracy"],
            os_run_id=h["os_run_id"],
            services_run_id=h["services_run_id"],
            packages_run_id=h["packages_run_id"], package_count=h["package_count"],
            services=[ServiceOut(host=s.host, port=s.port, protocol=s.protocol,
                                 service=s.service, product=s.product,
                                 version=s.version, cpe=s.cpe)
                      for s in h["services"]],
            latest_counts=lt.counts if lt else {}, latest_total=lt.total if lt else 0,
            latest_run_ids=lt.run_ids if lt else [],
            checked_run_id=lt.checked_run_id if lt else None))
    return out


@router.get("/engagements/{engagement_id}/hosts/{host}/latest", response_model=HostLatestOut)
def host_latest_findings(engagement_id: int, host: str,
                         _: Annotated[Principal, Depends(require(Perm.VIEW_REPORT))],
                         session: SessionDep) -> HostLatestOut:
    """Последние известные находки хоста: по каждому модулю — из последнего
    прогона, где модуль хост действительно проверил. Ложные срабатывания — с
    полем false_positive, как в находках прогона."""
    get_engagement(session, engagement_id)
    try:
        key = str(ipaddress.ip_address(host.strip()))
    except ValueError as e:
        raise HTTPException(422, f"invalid host: {host}") from e
    lt, rows = host_latest.latest_findings(session, engagement_id, key)
    marks = repo.false_positive_marks(session, engagement_id)
    services, priorities = {}, {}
    for rid in lt.run_ids:
        services[rid] = services_by_port(session, rid)
        priorities[rid] = run_priorities(session, rid, engagement_id, marks)
    return HostLatestOut(
        host=key, run_ids=lt.run_ids, checked_run_id=lt.checked_run_id,
        module_runs=lt.module_runs,
        findings=[finding_out(r, marks, services.get(r.scan_run_id),
                              priorities.get(r.scan_run_id)) for r in rows])


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


@router.post("/runs/{run_id}/retry", response_model=RunCreated, status_code=202)
def retry_run(run_id: int, request: Request,
              user: Annotated[Principal, Depends(require(Perm.RUN_SCAN))],
              session: SessionDep, audit: AuditDep,
              runs: Annotated[RunService, Depends(_runs)]) -> RunCreated:
    """«Повторить»: новый прогон с параметрами прогона с ошибкой, прерванного или
    остановленного. Права, учётки и allowlist проверяются заново, как при
    обычном запуске; исходный прогон и его результаты не меняются."""
    run = _get_run(session, run_id)
    if run.status not in RETRYABLE:
        raise HTTPException(409, "повторить можно только прогон с ошибкой, частичный, прерванный "
                                 f"или остановленный (сейчас: {run.status})")
    modules = list(run.modules)
    check_run_options(run.engagement_id, modules=modules, rate_profile=run.rate_profile,
                      credential_ids=list(run.credential_ids or []),
                      cred_set_ids=list(run.cred_set_ids or []),
                      user=user, request=request, audit=audit, runs=runs)
    plan, denied = check_targets(run.engagement_id, list(run.targets or []), user=user,
                                 audit=audit, runs=runs)
    session.commit()
    try:
        new_id = runs.retry(run_id, actor=user.subject, started_by=user.id)
    except ValueError as e:
        raise HTTPException(409, str(e)) from e
    session.expire_all()
    new = _get_run(session, new_id)
    return RunCreated(**RunOut.model_validate(new).model_dump(),
                      accepted_targets=len(plan.allowed), denied_targets=denied)


@router.get("/runs/{run_id}/findings", response_model=list[FindingOut])
def list_findings(run_id: int, response: Response,
                  _: Annotated[Principal, Depends(require(Perm.VIEW_REPORT))],
                  session: SessionDep,
                  module: Annotated[list[str] | None, Query()] = None,
                  severity: Annotated[list[str] | None, Query()] = None,
                  status_: Annotated[list[str] | None, Query(alias="status")] = None,
                  host: Annotated[str | None, Query(max_length=64)] = None,
                  q: Annotated[str | None, Query(max_length=200)] = None,
                  bdu_only: bool = False,
                  include_info: bool = True,
                  false_positives: Annotated[str, Query(
                      pattern=f"^({'|'.join(fq.FP_MODES)})$")] = "include",
                  sort: Annotated[str | None, Query(
                      pattern=f"^({'|'.join(fq.FINDING_SORTS)})$")] = None,
                  order: Annotated[str, Query(pattern="^(asc|desc)$")] = "asc",
                  limit: Annotated[int | None, Query(ge=1, le=1000)] = None,
                  offset: Annotated[int, Query(ge=0)] = 0) -> list[FindingOut]:
    """Находки прогона; отмеченные как ложные срабатывания — с полем false_positive.

    Фильтры, сортировка и страницы выполняются в БД; всего по фильтру — в
    заголовке X-Total-Count. Без limit отдаются все подходящие находки (как
    раньше; без sort — в порядке сохранения). sort=severity — сначала опасные,
    priority — по рангу «что исправлять первым»; order=desc — обратный порядок."""
    run = _get_run(session, run_id)
    try:
        flt = fq.FindingFilter(severities=severity or [], modules=module or [],
                               statuses=status_ or [], host=host, query=q,
                               bdu_only=bdu_only, include_info=include_info,
                               false_positives=false_positives)
        if host:
            ipaddress.ip_address(host.strip())
    except ValueError as e:
        raise HTTPException(422, f"invalid host: {host}") from e
    marks = repo.false_positive_marks(session, run.engagement_id)
    priorities = run_priorities(session, run_id, run.engagement_id, marks)
    ranks = {k: p.rank for k, p in priorities.items()} if sort == "priority" else None
    rows, total = fq.page_findings(session, run_id, run.engagement_id, flt,
                                   sort=sort or "id", desc=order == "desc",
                                   limit=limit, offset=offset, ranks=ranks)
    services = services_by_port(session, run_id)
    response.headers["X-Total-Count"] = str(total)
    return [finding_out(r, marks, services, priorities) for r in rows]


@router.get("/runs/{run_id}/findings/summary", response_model=FindingsSummaryOut)
def findings_summary(run_id: int,
                     _: Annotated[Principal, Depends(require(Perm.VIEW_REPORT))],
                     session: SessionDep) -> FindingsSummaryOut:
    """Счётчики прогона (уровни, модули, статусы, хосты, новые/закрытые) — для
    плашек фильтров, KPI и тепловой карты без выгрузки всех находок."""
    run = _get_run(session, run_id)
    return FindingsSummaryOut(**fq.summary(session, run_id, run.engagement_id))


@router.get("/runs/{run_id}/coverage", response_model=CoverageOut)
def run_coverage(run_id: int,
                 _: Annotated[Principal, Depends(require(Perm.VIEW_REPORT))],
                 session: SessionDep) -> CoverageOut:
    """Что реально проверено: статус каждого модуля на каждом хосте
    (completed, unreachable, timeout, no_credentials, not_applicable, skipped,
    error) с причиной и рекомендацией."""
    from scanner.core.coverage import STATUS_LABELS
    from scanner.core.db import RunCoverageRow
    run = _get_run(session, run_id)
    legacy = session.scalar(select(RunCoverageRow.id)
                            .where(RunCoverageRow.scan_run_id == run_id).limit(1)) is None
    cov = repo.run_coverage(session, run)
    hosts = []
    for h in cov.hosts():
        per = {e.module: {"status": e.status, "label": STATUS_LABELS[e.status],
                          "reason": e.reason}
               for e in cov.entries() if e.host == h}
        hosts.append({"host": h, "status": cov.host_status(h), "modules": per})
    return CoverageOut(scan_run_id=run_id, status=run.status, summary=cov.summary(),
                       hosts=hosts, entries=cov.to_dicts(), legacy=legacy)


@router.get("/runs/{run_id}/events", response_model=list[RunEventOut])
def run_events_feed(run_id: int,
                    _: Annotated[Principal, Depends(require(Perm.VIEW_REPORT))],
                    session: SessionDep,
                    limit: Annotated[int, Query(ge=1, le=run_events.LIST_LIMIT_MAX)] = 50,
                    ) -> list[RunEventOut]:
    """Лента прогона для «Сводки», новые сверху: начат/завершён, модули,
    по хосту — новые и вернувшиеся уязвимости, закрытые, хост не проверен."""
    _get_run(session, run_id)
    return [RunEventOut.model_validate(r)
            for r in run_events.list_events(session, run_id, limit)]


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
               compare_to: int | None = None,
               group_id: int | None = None,
               plan: bool = True,
               details: bool = True,
               compliance: Annotated[str | None, Query(
                   max_length=300, pattern=r"^[a-z0-9,-]*$")] = None) -> Response:
    """Отчёт по прогону. По умолчанию — только по этому прогону, без сравнения;
    compare_to=<id> — сравнить с выбранным более ранним прогоном договора.
    group_id=<id> — разрез по группе активов: только хосты группы.
    variant=brief — краткая версия: без плана устранения,
    по находкам вместо рекомендаций только ссылки на устранение.
    plan=false — без раздела «План устранения» (рекомендации по находкам остаются).
    details=false — без раздела «Детальные результаты для инженеров».
    compliance — профили соответствия в отчёте через запятую (fstec-117,cis-benchmark);
    пусто или none — без раздела «Соответствие требованиям»; не задан — профили
    договора с признаком «в отчёт»."""
    from scanner.reporting.model import ReportContext, build_report
    from scanner.reporting.render import (
        CONTENT_TYPES,
        ReportFormat,
        ReportRenderer,
        ReportVariant,
    )
    from scanner.reporting.risk import build_risk_context

    run = _get_run(session, run_id)
    if run.status not in FINISHED:
        raise HTTPException(status.HTTP_409_CONFLICT,
                            f"scan run is {run.status}; report is available after it ends")
    eng = get_engagement(session, run.engagement_id)
    profiles = _report_profiles(compliance)
    group = hosts = None
    if group_id is not None:
        from scanner.core import assets as asset_svc
        group = asset_svc.get_group(session, eng.id, group_id)
        if group is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "asset group not found")
        hosts = asset_svc.group_hosts(session, group_id)
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
    resolver = request.app.state.resolver_factory(current)
    # ОС хостов без учётки — из инвентаря договора (баннеры); ОС из прогона точнее
    resolver.add_host_os(repo.host_os_names(session, eng.id), override=False)
    report = build_report(
        current, previous=previous, historically_fixed=hist,
        resolver=resolver,
        context=ReportContext(customer=eng.client,
                              engagement=eng.contract_ref or eng.name,
                              run_id=run_id, previous_run_id=prev_id,
                              group=group.name if group else None),
        false_positives=repo.false_positive_marks(session, eng.id), hosts=hosts,
        risk=build_risk_context(session, current, eng.id),
        compliance=_compliance_sections(session, run_id, eng.id, hosts, profiles),
        with_plan=plan, with_details=details,
        coverage=repo.run_coverage(session, run),
        previous_coverage=(repo.run_coverage(session, prev_id)
                           if prev_id is not None else None),
        run_status=run.status, warnings=list(run.warnings or []))
    fmt, var = ReportFormat(format), ReportVariant(variant)
    body = ReportRenderer().render(report, fmt, variant=var)
    audit.record(subject=user.subject, action="export", target=f"scan_run:{run_id}",
                 result="ok", details={"format": fmt.value, "variant": var.value,
                                       "previous_run_id": prev_id, "findings": len(current),
                                       "group_id": group_id, "plan": report.show_plan,
                                       "details": report.show_details,
                                       "compliance": [c["profile"]["id"]
                                                      for c in report.compliance]})
    suffix = (f"-group-{group_id}" if group_id is not None else "") + (
        "-brief" if var is ReportVariant.BRIEF else "") + (
        f"-vs-{prev_id}" if prev_id is not None else "")
    return Response(content=body, media_type=CONTENT_TYPES[fmt], headers={
        "Content-Disposition":
            f'attachment; filename="report-run-{run_id}{suffix}.{fmt.value}"'})


def _report_profiles(compliance: str | None) -> list[str] | None:
    """Параметр compliance отчёта -> список профилей (None — по настройкам договора)."""
    if compliance is None:
        return None
    from scanner.compliance.catalog import default_catalog
    ids = [x for x in dict.fromkeys(compliance.split(",")) if x and x != "none"]
    unknown = [x for x in ids if x not in default_catalog().profiles]
    if unknown:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT,
                            f"unknown compliance profile: {', '.join(unknown)}")
    return ids


def _compliance_sections(session: Session, run_id: int, engagement_id: int,
                         hosts: set[str] | None,
                         profiles: list[str] | None = None) -> list[dict]:
    """Сводки соответствия (R5): по выбранным для отчёта профилям, а если выбор не
    передан — по профилям договора с признаком «в отчёт»."""
    from scanner.compliance import store as compliance_store
    from scanner.compliance.catalog import default_catalog
    if profiles is None:
        profiles = [r.profile for r in compliance_store.list_profiles(session, engagement_id)
                    if r.in_report]
    if not profiles or not compliance_store.has_results(session, run_id):
        return []
    catalog = default_catalog()
    return [compliance_store.run_summary(session, run_id, engagement_id,
                                         catalog.profiles[p], catalog=catalog, hosts=hosts)
            for p in profiles if p in catalog.profiles]
