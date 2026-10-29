"""Репозиторий: сохранение и чтение прогонов, инвентаря, находок, allowlist.

Функции принимают открытую `Session` и не коммитят сами — границы транзакции
задаёт вызывающий код (`session_scope`). Преобразование ORM <-> доменные модели
(`scanner.core.models`) живёт только здесь.
"""
from __future__ import annotations

import ipaddress
from collections.abc import Iterable, Mapping
from datetime import UTC, datetime
from decimal import Decimal

from sqlalchemy import select
from sqlalchemy.orm import Session

from scanner.core.allowlist import AllowlistGate
from scanner.core.db import (
    AllowlistEntry,
    Engagement,
    FindingRow,
    HostResult,
    ScanRun,
    ServiceResult,
)
from scanner.core.models import (
    Finding,
    FindingStatus,
    FindingType,
    ServiceInfo,
    Severity,
)

RUN_STATUSES = {"pending", "running", "done", "failed", "stopped"}


# ========== Engagement + allowlist ==========
def create_engagement(session: Session, *, name: str, client: str | None = None,
                      contract_ref: str | None = None,
                      created_by: int | None = None) -> int:
    e = Engagement(name=name, client=client, contract_ref=contract_ref,
                   created_by=created_by)
    session.add(e)
    session.flush()
    return e.id


def add_allowlist_entry(session: Session, *, engagement_id: int, cidr: str,
                        note: str | None = None, added_by: int | None = None) -> int:
    """Добавить цель в allowlist договора. CIDR валидируется и нормализуется."""
    net = ipaddress.ip_network(cidr, strict=False)  # ValueError на мусоре
    entry = AllowlistEntry(engagement_id=engagement_id, cidr=str(net), note=note,
                           added_by=added_by)
    session.add(entry)
    session.flush()
    return entry.id


def list_allowlist(session: Session, engagement_id: int) -> list[str]:
    rows = session.scalars(
        select(AllowlistEntry.cidr)
        .where(AllowlistEntry.engagement_id == engagement_id)
        .order_by(AllowlistEntry.id))
    return [str(c) for c in rows]


def load_allowlist_gate(session: Session, engagement_id: int) -> AllowlistGate:
    """AllowlistGate из БД. Пустой allowlist = запрещено всё."""
    return AllowlistGate(list_allowlist(session, engagement_id))


# ========== Прогоны ==========
def create_scan_run(session: Session, *, engagement_id: int, modules: list[str],
                    rate_profile: str = "gentle", started_by: int | None = None) -> int:
    run = ScanRun(engagement_id=engagement_id, modules=list(modules),
                  rate_profile=rate_profile, started_by=started_by, status="pending")
    session.add(run)
    session.flush()
    return run.id


def set_scan_run_status(session: Session, scan_run_id: int, status: str) -> None:
    if status not in RUN_STATUSES:
        raise ValueError(f"unknown scan run status: {status}")
    run = session.get(ScanRun, scan_run_id)
    if run is None:
        raise LookupError(f"scan_run {scan_run_id} not found")
    now = datetime.now(UTC)
    run.status = status
    if status == "running" and run.started_at is None:
        run.started_at = now
    if status in {"done", "failed", "stopped"}:
        run.finished_at = now
    session.flush()


def get_scan_run(session: Session, scan_run_id: int) -> ScanRun | None:
    return session.get(ScanRun, scan_run_id)


def previous_scan_run_id(session: Session, scan_run_id: int) -> int | None:
    """Предыдущий завершённый прогон того же договора (для diff)."""
    run = session.get(ScanRun, scan_run_id)
    if run is None:
        return None
    return session.scalar(
        select(ScanRun.id)
        .where(ScanRun.engagement_id == run.engagement_id,
               ScanRun.id < run.id, ScanRun.status == "done")
        .order_by(ScanRun.id.desc())
        .limit(1))


# ========== Инвентарь ==========
def save_host(session: Session, *, scan_run_id: int, host: str, state: str | None = "up",
              os_guess: str | None = None, os_accuracy: int | None = None) -> int:
    h = HostResult(scan_run_id=scan_run_id, host=str(ipaddress.ip_address(host)),
                   state=state, os_guess=os_guess, os_accuracy=os_accuracy)
    session.add(h)
    session.flush()
    return h.id


def save_services(session: Session, *, scan_run_id: int,
                  services: Iterable[ServiceInfo]) -> dict[str, int]:
    """Сохранить сервисы; host_results создаются по необходимости.

    Возвращает {host: host_result_id}.
    """
    existing = {
        str(h.host): h.id for h in session.scalars(
            select(HostResult).where(HostResult.scan_run_id == scan_run_id))
    }
    for s in services:
        host = str(ipaddress.ip_address(s.host))
        if host not in existing:
            existing[host] = save_host(session, scan_run_id=scan_run_id, host=host)
        session.add(ServiceResult(host_id=existing[host], port=s.port,
                                  protocol=s.protocol, service=s.service,
                                  product=s.product, version=s.version, cpe=s.cpe))
    session.flush()
    return existing


def get_services(session: Session, scan_run_id: int) -> list[ServiceInfo]:
    rows = session.execute(
        select(HostResult.host, ServiceResult)
        .join(ServiceResult, ServiceResult.host_id == HostResult.id)
        .where(HostResult.scan_run_id == scan_run_id)
        .order_by(ServiceResult.id))
    return [ServiceInfo(host=str(host), port=s.port, protocol=s.protocol,
                        service=s.service, product=s.product, version=s.version,
                        cpe=s.cpe)
            for host, s in rows]


def engagement_hosts(session: Session, engagement_id: int) -> list[dict]:
    """Инвентарь договора: все хосты, встречавшиеся в любом прогоне.

    Хост попадает в инвентарь по результатам discovery (host_results) или по
    находкам. Сервисы и ОС — из последнего прогона, где они были. Для каждого
    хоста — список прогонов, в которых он встречался (`run_ids`, по возрастанию).
    """
    run_ids = list(session.scalars(
        select(ScanRun.id).where(ScanRun.engagement_id == engagement_id)))
    if not run_ids:
        return []
    hosts: dict[str, dict] = {}

    def get(host: object) -> dict:
        key = str(ipaddress.ip_address(str(host).split("/")[0]))
        if key not in hosts:
            hosts[key] = {"host": key, "os_guess": None, "run_ids": set(),
                          "services": [], "services_run_id": None}
        return hosts[key]

    for h in session.scalars(select(HostResult).where(HostResult.scan_run_id.in_(run_ids))
                             .order_by(HostResult.scan_run_id)):
        row = get(h.host)
        row["run_ids"].add(h.scan_run_id)
        if h.os_guess:
            row["os_guess"] = h.os_guess
    for host, rid in session.execute(
            select(FindingRow.host, FindingRow.scan_run_id).distinct()
            .where(FindingRow.scan_run_id.in_(run_ids))):
        get(host)["run_ids"].add(rid)
    rows = session.execute(
        select(HostResult.host, HostResult.scan_run_id, ServiceResult)
        .join(ServiceResult, ServiceResult.host_id == HostResult.id)
        .where(HostResult.scan_run_id.in_(run_ids))
        .order_by(HostResult.scan_run_id.desc(), ServiceResult.id))
    for host, rid, s in rows:
        row = get(host)
        if row["services_run_id"] is None:
            row["services_run_id"] = rid
        if row["services_run_id"] == rid:
            row["services"].append(ServiceInfo(
                host=row["host"], port=s.port, protocol=s.protocol, service=s.service,
                product=s.product, version=s.version, cpe=s.cpe))
    out = []
    for row in hosts.values():
        row["run_ids"] = sorted(row["run_ids"])
        row["services"].sort(key=lambda s: (s.port, s.protocol))
        out.append(row)
    return sorted(out, key=lambda r: (ipaddress.ip_address(r["host"]).version,
                                      int(ipaddress.ip_address(r["host"]))))


# ========== Находки ==========
def save_findings(session: Session, *, engagement_id: int, scan_run_id: int,
                  findings: Iterable[Finding],
                  statuses: Mapping[str, FindingStatus | str] | None = None) -> int:
    """Сохранить находки прогона. statuses — {dedup_key: status} из diff_runs."""
    statuses = statuses or {}
    n = 0
    for f in findings:
        key = f.dedup_key()
        session.add(FindingRow(
            engagement_id=engagement_id, scan_run_id=scan_run_id,
            module=f.module, finding_type=str(f.finding_type),
            host=str(ipaddress.ip_address(f.host)), port=f.port, vuln_id=f.vuln_id,
            cve_ids=list(f.cve_ids), bdu_ids=list(f.bdu_ids), title=f.title,
            severity=str(f.severity),
            cvss=None if f.cvss is None else Decimal(str(f.cvss)),
            evidence=f.evidence, status=str(statuses.get(key, FindingStatus.OPEN)),
            dedup_key=key, detected_at=_aware(f.detected_at)))
        n += 1
    session.flush()
    return n


def _row_to_finding(r: FindingRow) -> Finding:
    return Finding(
        module=r.module, host=str(r.host), finding_type=FindingType(r.finding_type),
        title=r.title, severity=Severity(r.severity), port=r.port, vuln_id=r.vuln_id,
        cve_ids=list(r.cve_ids or []), bdu_ids=list(r.bdu_ids or []),
        cvss=None if r.cvss is None else float(r.cvss), evidence=r.evidence,
        detected_at=r.detected_at)


def get_findings(session: Session, scan_run_id: int,
                 module: str | None = None) -> list[Finding]:
    """Находки прогона (опционально — одного модуля) для diff/отчётов."""
    q = select(FindingRow).where(FindingRow.scan_run_id == scan_run_id)
    if module is not None:
        q = q.where(FindingRow.module == module)
    return [_row_to_finding(r) for r in session.scalars(q.order_by(FindingRow.id))]


def get_finding_statuses(session: Session, scan_run_id: int) -> dict[str, str]:
    """{dedup_key: status} находок прогона."""
    rows = session.execute(
        select(FindingRow.dedup_key, FindingRow.status)
        .where(FindingRow.scan_run_id == scan_run_id))
    return {k: s for k, s in rows}


def historically_fixed_keys(session: Session, engagement_id: int,
                            before_run_id: int) -> set[str]:
    """Ключи находок, которые когда-либо были в прогонах до before_run_id.

    Используется как historically_fixed в diff_runs: если ключ был раньше, исчез
    и снова появился — это regression. Ключи из непосредственно предыдущего
    прогона diff_runs отработает как open, поэтому пересечение безопасно.
    """
    rows = session.scalars(
        select(FindingRow.dedup_key).distinct()
        .where(FindingRow.engagement_id == engagement_id,
               FindingRow.scan_run_id < before_run_id))
    return set(rows)


def _aware(dt: datetime) -> datetime:
    # Finding.detected_at создаётся через datetime.utcnow() (naive UTC).
    return dt if dt.tzinfo else dt.replace(tzinfo=UTC)
