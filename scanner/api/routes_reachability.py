"""Проверка доступности хоста без запуска прогона.

Те же ограничители, что у прогона: право `run_scan` (admin не сканирует —
разделение обязанностей), только литеральный IP из allowlist договора, каждая
попытка — в журнале аудита (в т.ч. отказы), частота ограничена на пользователя.
"""
from __future__ import annotations

import ipaddress
from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, status

from scanner.api.deps import AuditDep, Principal, SessionDep, require
from scanner.api.rbac import Perm
from scanner.api.routes_engagements import get_engagement
from scanner.api.schemas import PortStateOut, ReachabilityIn, ReachabilityOut
from scanner.core import repository as repo
from scanner.core.reachability import DEFAULT_PORTS

router = APIRouter(tags=["reachability"])

ACTION = "reachability_check"


@router.post("/engagements/{engagement_id}/reachability", response_model=ReachabilityOut)
def check_reachability(engagement_id: int, body: ReachabilityIn, request: Request,
                       user: Annotated[Principal, Depends(require(Perm.RUN_SCAN))],
                       session: SessionDep, audit: AuditDep) -> ReachabilityOut:
    get_engagement(session, engagement_id)
    target_ref = f"engagement:{engagement_id}"
    spec = body.target.strip()

    def reject(code: int, result: str, message: str, **details) -> HTTPException:
        audit.record(subject=user.subject, action=ACTION, target=target_ref,
                     result=result, details={"host": spec, **details})
        return HTTPException(code, message)

    try:
        host = str(ipaddress.ip_address(spec))
    except ValueError:
        # подсети и имена не принимаем: проверка — по одному хосту, без DNS
        raise reject(422, "rejected_not_an_ip",
                     "target must be a single IP address") from None
    ports = sorted(set(body.ports or DEFAULT_PORTS))
    if any(not 1 <= p <= 65535 for p in ports):
        raise reject(422, "rejected_bad_ports", "ports must be in 1..65535")
    # allowlist — в момент проверки, как и у прогона
    if not repo.load_allowlist_gate(session, engagement_id).is_allowed(host):
        raise reject(422, "rejected_not_in_allowlist",
                     "target is not in the engagement allowlist")
    if not request.app.state.reach_throttle.allow(user.subject):
        raise reject(status.HTTP_429_TOO_MANY_REQUESTS, "rate_limited",
                     "too many reachability checks, try again in a minute")
    session.commit()   # отпустить транзакцию на время сетевых проб

    r = request.app.state.reach_check(host, ports)
    audit.record(subject=user.subject, action=ACTION, target=target_ref,
                 result="reachable" if r.reachable else "unreachable",
                 details={"host": host, "ports": ports, "methods": r.methods,
                          "open_ports": [p.port for p in r.ports if p.state == "open"]})
    return ReachabilityOut(
        target=host, reachable=r.reachable, methods=r.methods,
        icmp_available=r.icmp.available, icmp_alive=r.icmp.alive,
        icmp_rtt_ms=r.icmp.rtt_ms,
        ports=[PortStateOut(port=p.port, state=p.state, rtt_ms=p.rtt_ms) for p in r.ports],
        elapsed_ms=r.elapsed_ms, checked_at=datetime.now(UTC))
