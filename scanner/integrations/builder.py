"""Сборка события по итогам прогона: сводка находок, приоритет R6, активы R7.

Использует то, что прогон уже посчитал: статусы new/regression/open в findings
(diff с предыдущим прогоном), ранжирование `scanner.reporting.risk` (EPSS, KEV,
критичность актива), группы и владельцы активов. Находки, помеченные ложными
срабатываниями, в уведомления не попадают.
"""
from __future__ import annotations

import logging
from collections import defaultdict

from sqlalchemy import select
from sqlalchemy.orm import Session

from scanner.core import repository as repo
from scanner.core.db import (
    AssetGroupRow,
    AssetRow,
    Engagement,
    HostResult,
    asset_group_members,
)
from scanner.core.models import Finding
from scanner.integrations.events import RUN_FINISHED, Event, HostInfo, Item
from scanner.reporting.risk import normalize_host, rank_findings

log = logging.getLogger(__name__)


def _risk(session: Session, findings: list[Finding], engagement_id: int):
    try:
        from scanner.reporting.risk import build_risk_context
        return rank_findings(findings, build_risk_context(session, findings, engagement_id))
    except Exception:  # справочники недоступны — ранжируем по CVSS/опасности
        log.warning("notification: risk context unavailable", exc_info=True)
        return rank_findings(findings)


def _assets(session: Session, engagement_id: int) -> dict[str, HostInfo]:
    out: dict[str, HostInfo] = {}
    ids: dict[int, str] = {}
    for aid, addr, owner in session.execute(
            select(AssetRow.id, AssetRow.address, AssetRow.owner)
            .where(AssetRow.engagement_id == engagement_id)):
        key = normalize_host(addr)
        ids[aid] = key
        out[key] = HostInfo(host=key, owner=owner or None)
    if ids:
        groups: dict[int, list[str]] = defaultdict(list)
        for aid, name in session.execute(
                select(asset_group_members.c.asset_id, AssetGroupRow.name)
                .join(AssetGroupRow, AssetGroupRow.id == asset_group_members.c.group_id)
                .where(asset_group_members.c.asset_id.in_(list(ids)))
                .order_by(AssetGroupRow.name)):
            groups[aid].append(name)
        for aid, key in ids.items():
            out[key].groups = groups.get(aid, [])
    return out


def build_run_event(session: Session, scan_run_id: int, public_url: str = "") -> Event:
    run = repo.get_scan_run(session, scan_run_id)
    if run is None:
        raise LookupError(f"scan_run {scan_run_id} not found")
    eng = session.get(Engagement, run.engagement_id)
    rows = repo.get_finding_rows(session, scan_run_id)
    marks = repo.false_positive_marks(session, run.engagement_id)
    rows = [r for r in rows if r.dedup_key not in marks]
    findings = [repo.row_to_finding(r) for r in rows]
    ranks = _risk(session, findings, run.engagement_id)
    assets = _assets(session, run.engagement_id)

    items: list[Item] = []
    for r, f in zip(rows, findings, strict=True):
        a = ranks.get(r.dedup_key)
        info = assets.get(normalize_host(r.host))
        items.append(Item(
            dedup_key=r.dedup_key, host=normalize_host(r.host), port=r.port, title=f.title,
            severity=str(f.severity), status=r.status, vuln_id=r.vuln_id,
            cve_ids=list(f.cve_ids), bdu_ids=list(f.bdu_ids),
            priority=a.label if a else None, score=a.score if a else None,
            rank=a.rank if a else None, in_kev=bool(a and a.factors.in_kev),
            owner=info.owner if info else None, groups=list(info.groups) if info else []))

    seen = [normalize_host(h) for h in session.scalars(
        select(HostResult.host).where(HostResult.scan_run_id == scan_run_id))]
    hosts: dict[str, HostInfo] = {}
    for h in dict.fromkeys(seen + [i.host for i in items]):
        hosts[h] = assets.get(h) or HostInfo(host=h)

    fixed = None
    prev = repo.previous_scan_run_id(session, scan_run_id)
    if prev is None:
        # первый прогон договора: сравнивать не с чем — все находки для оператора новые
        for i in items:
            if i.status == "open":
                i.status = "new"
    else:
        prev_keys = set(repo.get_finding_statuses(session, prev)) - set(marks)
        fixed = len(prev_keys - {r.dedup_key for r in rows})
    return Event(
        kind=RUN_FINISHED, title=run.name or f"Прогон №{run.id}",
        engagement_id=run.engagement_id, engagement_name=eng.name if eng else None,
        scan_run_id=run.id, run_name=run.name, run_status=run.status,
        link=f"{public_url.rstrip('/')}/runs/{run.id}" if public_url else None,
        hosts=list(hosts.values()), items=items, fixed_total=fixed)
