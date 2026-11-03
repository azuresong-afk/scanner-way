"""Проверка сетевой доступности — вкладка «Доступность».

Какие хосты в сети и какие TCP-порты на них открыты — без полного прогона
(`scanner.core.netscan`, nmap). Ограничители те же, что у прогона:

  * запуск и остановка — право `run_scan` (admin не сканирует — разделение
    обязанностей); просмотр — `view_report`;
  * цели — адреса, подсети и диапазоны, развёрнутые и пропущенные через
    allowlist договора в момент запуска (и ещё раз перед каждой пачкой);
    имена хостов не принимаются (без DNS); не больше `portscan_max_targets`;
  * интенсивность — профиль прогона (`--max-rate`, `--max-parallelism`);
    частота запусков ограничена на пользователя, одновременно у пользователя —
    не больше `portscan_max_active` заданий;
  * журнал аудита: запуск (с отказами), каждый вызов nmap, итог, остановка.

Живые хосты заносятся в «Активы» (без учётных записей).
"""
from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy import func, select

from scanner.api.deps import AuditDep, Principal, SessionDep, require
from scanner.api.rbac import Perm
from scanner.api.routes_engagements import get_engagement
from scanner.api.schemas import PortScanCreated, PortScanDetail, PortScanIn, PortScanOut
from scanner.core import portspec
from scanner.core import repository as repo
from scanner.core.db import PortScanRow
from scanner.core.netscan import ACTIVE, MODE_LIST, MODE_TOP, TOP_PORTS
from scanner.core.orchestrator import plan_targets
from scanner.core.ratelimit import PROFILES

router = APIRouter(tags=["reachability"])

ACTION = "port_scan"


def _out(row: PortScanRow, cls=PortScanOut, **extra):
    data = {c: getattr(row, c) for c in cls.model_fields if hasattr(row, c)}
    data["requested_targets"] = list(row.requested_targets or [])
    if row.port_mode == MODE_LIST and row.ports:
        data["port_count"] = portspec.count(portspec.subtract(
            portspec.parse_ports(row.ports), portspec.parse_ports(row.exclude_ports or "")))
    elif row.port_mode == MODE_TOP:
        data["port_count"] = TOP_PORTS
    if cls is PortScanDetail:
        data["results"] = list(row.results or [])
    return cls(**{**data, **extra})


def _scan(session, scan_id: int) -> PortScanRow:
    row = session.get(PortScanRow, scan_id)
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "port scan not found")
    return row


@router.post("/engagements/{engagement_id}/port-scans", response_model=PortScanCreated,
             status_code=202)
def start_port_scan(engagement_id: int, body: PortScanIn, request: Request,
                    user: Annotated[Principal, Depends(require(Perm.RUN_SCAN))],
                    session: SessionDep, audit: AuditDep) -> PortScanCreated:
    get_engagement(session, engagement_id)
    settings = request.app.state.portscan_settings
    target_ref = f"engagement:{engagement_id}"

    def reject(code: int, result: str, message: str, **details) -> HTTPException:
        audit.record(subject=user.subject, action=ACTION, target=target_ref,
                     result=result, details={"targets": body.targets[:20], **details})
        return HTTPException(code, message)

    try:
        ports = portspec.parse_ports(body.ports or "")
        exclude = portspec.parse_ports(body.exclude_ports or "")
    except portspec.PortSpecError as e:
        raise reject(422, "rejected_bad_ports", f"ports: {e}") from None
    if body.port_mode == MODE_LIST:
        if not ports:
            raise reject(422, "rejected_bad_ports", "ports: укажите порты для проверки")
        if not portspec.subtract(ports, exclude):
            raise reject(422, "rejected_bad_ports",
                         "ports: после исключений не осталось ни одного порта")
    if body.rate_profile not in PROFILES:
        raise reject(422, "rejected_bad_profile",
                     f"unknown rate profile: {body.rate_profile}")

    plan = plan_targets(repo.load_allowlist_gate(session, engagement_id), body.targets,
                        max_targets=settings["max_targets"])
    denied = [{"target": d.target, "reason": d.reason, "count": d.count}
              for d in plan.denied]
    if not plan.allowed:
        raise reject(422, "rejected_not_in_allowlist",
                     "no target passed the engagement allowlist", denied=denied)

    active = session.scalar(select(func.count()).select_from(PortScanRow).where(
        PortScanRow.started_by == user.id, PortScanRow.status.in_(ACTIVE)))
    if active >= settings["max_active"]:
        raise reject(status.HTTP_429_TOO_MANY_REQUESTS, "rate_limited",
                     "too many port scans in progress, wait for one to finish")
    if not request.app.state.portscan_throttle.allow(user.subject):
        raise reject(status.HTTP_429_TOO_MANY_REQUESTS, "rate_limited",
                     "too many port scans, try again in a minute")

    row = PortScanRow(
        engagement_id=engagement_id, status="queued",
        requested_targets=[t.strip() for t in body.targets], targets=plan.allowed,
        port_mode=body.port_mode,
        ports=portspec.to_text(ports) if body.port_mode == MODE_LIST else None,
        exclude_ports=portspec.to_text(exclude) or None,
        no_ping=body.no_ping, service_detection=body.service_detection,
        rate_profile=body.rate_profile, hosts_total=len(plan.allowed), results=[],
        actor=user.subject, started_by=user.id)
    session.add(row)
    session.commit()
    audit.record(subject=user.subject, action=ACTION, target=f"port_scan:{row.id}",
                 result="queued",
                 details={"engagement_id": engagement_id, "hosts": len(plan.allowed),
                          "port_mode": row.port_mode, "ports": row.ports,
                          "exclude_ports": row.exclude_ports, "no_ping": row.no_ping,
                          "service_detection": row.service_detection,
                          "rate_profile": row.rate_profile, "denied": denied})
    request.app.state.portscans.submit(row.id)
    session.expire_all()
    return _out(_scan(session, row.id), PortScanCreated, denied_targets=denied)


@router.get("/engagements/{engagement_id}/port-scans", response_model=list[PortScanOut])
def list_port_scans(engagement_id: int,
                    _: Annotated[Principal, Depends(require(Perm.VIEW_REPORT))],
                    session: SessionDep,
                    limit: Annotated[int, Query(ge=1, le=100)] = 20) -> list[PortScanOut]:
    get_engagement(session, engagement_id)
    rows = session.scalars(select(PortScanRow)
                           .where(PortScanRow.engagement_id == engagement_id)
                           .order_by(PortScanRow.id.desc()).limit(limit))
    return [_out(r) for r in rows]


@router.get("/port-scans/{scan_id}", response_model=PortScanDetail)
def read_port_scan(scan_id: int,
                   _: Annotated[Principal, Depends(require(Perm.VIEW_REPORT))],
                   session: SessionDep) -> PortScanDetail:
    return _out(_scan(session, scan_id), PortScanDetail)


@router.post("/port-scans/{scan_id}/stop", response_model=PortScanOut)
def stop_port_scan(scan_id: int, request: Request,
                   user: Annotated[Principal, Depends(require(Perm.RUN_SCAN))],
                   session: SessionDep, audit: AuditDep) -> PortScanOut:
    row = _scan(session, scan_id)
    if row.status not in ACTIVE:
        raise HTTPException(status.HTTP_409_CONFLICT, "port scan is not running")
    request.app.state.portscans.stop(scan_id)
    audit.record(subject=user.subject, action=ACTION, target=f"port_scan:{scan_id}",
                 result="stop_requested")
    session.expire_all()
    return _out(_scan(session, scan_id))
