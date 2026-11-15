"""Открытые порты и сервисы актива по последним данным.

Карточка актива и отчёт по активу без выбранного прогона показывают последнее,
что известно о портах хоста. Источников два:

* прогон — разведка nmap (-sV) сохраняет сервисы в host_results/service_results;
* «Доступность» (port_scans) — проверка портов без прогона; результаты по хосту
  лежат в JSON задания (`results`), версии ПО — только если был включён -sV.

Берётся самый свежий источник, где хост был виден. Если свежее — проверка
доступности без определения версий, продукт и версия по тем же портам
подставляются из последнего прогона (и это указывается в подписи источника).
Проверка доступности по явному списку портов охватывает не все порты, поэтому
она дополняет данные прогона по своим портам, а не заменяет их целиком.
"""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field, replace
from datetime import datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from scanner.core.db import HostResult, PortScanRow, ScanRun, ServiceResult
from scanner.core.models import ServiceInfo

# сколько последних заданий «Доступности» просматривать (results — JSON по всем хостам)
PORT_SCAN_LOOKBACK = 50


@dataclass(slots=True)
class HostPorts:
    host: str
    services: list[ServiceInfo] = field(default_factory=list)
    source: str | None = None          # "run" | "port_scan" | None — сведений нет
    run_id: int | None = None          # прогон, из которого порты (или версии)
    port_scan_id: int | None = None
    seen_at: datetime | None = None
    versions_from_run: bool = False    # версии ПО подставлены из прогона
    ports_from_run: bool = False       # проверка по списку портов дополнена прогоном

    @property
    def label(self) -> str:
        """Подпись источника для карточки и отчёта."""
        when = f" от {self.seen_at:%d.%m.%Y}" if self.seen_at else ""
        if self.source == "run":
            return f"прогон {self.run_id}{when}"
        if self.source == "port_scan":
            text = f"проверка доступности {self.port_scan_id}{when}"
            if self.ports_from_run and self.run_id is not None:
                text += f"; остальные порты — из прогона {self.run_id}"
            if self.versions_from_run and self.run_id is not None:
                text += f"; версии ПО — из прогона {self.run_id}"
            return text
        return "нет сведений"

    def to_dict(self) -> dict:
        return {"host": self.host, "source": self.source, "label": self.label,
                "run_id": self.run_id, "port_scan_id": self.port_scan_id,
                "seen_at": self.seen_at.isoformat() if self.seen_at else None,
                "versions_from_run": self.versions_from_run,
                "ports_from_run": self.ports_from_run,
                "services": [{"host": s.host, "port": s.port, "protocol": s.protocol,
                              "service": s.service, "product": s.product,
                              "version": s.version, "cpe": s.cpe} for s in self.services]}


def _key(host: object) -> str:
    return str(ipaddress.ip_address(str(host).strip().split("/")[0]))


def _naive(dt: datetime | None) -> datetime | None:
    """Сравнение времени из SQLite (без зоны) и PostgreSQL (с зоной)."""
    return dt.replace(tzinfo=None) if dt is not None and dt.tzinfo else dt


def _run_services(session: Session, engagement_id: int, key: str
                  ) -> tuple[int | None, datetime | None, list[ServiceInfo]]:
    """Сервисы хоста из последнего прогона договора, где они были."""
    rows = session.execute(
        select(HostResult.scan_run_id, ServiceResult)
        .join(ServiceResult, ServiceResult.host_id == HostResult.id)
        .join(ScanRun, ScanRun.id == HostResult.scan_run_id)
        .where(ScanRun.engagement_id == engagement_id, HostResult.host == key)
        .order_by(HostResult.scan_run_id.desc(), ServiceResult.id)).all()
    if not rows:
        return None, None, []
    rid = rows[0][0]
    run = session.get(ScanRun, rid)
    at = (run.finished_at or run.started_at or run.created_at) if run else None
    out = [ServiceInfo(host=key, port=s.port, protocol=s.protocol, service=s.service,
                       product=s.product, version=s.version, cpe=s.cpe)
           for r, s in rows if r == rid]
    return rid, at, out


def _scan_services(session: Session, engagement_id: int, key: str):
    """(задание, время, сервисы, с -sV, полный охват) последней проверки
    доступности, где хост был доступен; None — таких нет."""
    scans = session.scalars(
        select(PortScanRow).where(PortScanRow.engagement_id == engagement_id,
                                  PortScanRow.status != "queued")
        .order_by(PortScanRow.id.desc()).limit(PORT_SCAN_LOOKBACK))
    for scan in scans:
        for r in scan.results or []:
            try:
                same = _key(r.get("host")) == key
            except ValueError:
                continue
            if not same or not r.get("up"):
                continue
            services = [ServiceInfo(host=key, port=int(p["port"]),
                                    protocol=p.get("protocol") or "tcp",
                                    service=p.get("service"), product=p.get("product"),
                                    version=p.get("version"))
                        for p in r.get("ports") or []]
            at = scan.finished_at or scan.started_at or scan.created_at
            return scan.id, at, services, bool(scan.service_detection), scan.port_mode != "list"
    return None


def latest_ports(session: Session, engagement_id: int, host: str) -> HostPorts:
    key = _key(host)
    rid, run_at, run_svc = _run_services(session, engagement_id, key)
    out = HostPorts(host=key)
    if rid is not None:
        out = HostPorts(host=key, services=run_svc, source="run", run_id=rid, seen_at=run_at)
    scan = _scan_services(session, engagement_id, key)
    if scan is None:
        return out
    sid, scan_at, scan_svc, with_versions, full = scan
    if rid is not None and _naive(run_at) is not None and _naive(scan_at) is not None \
            and _naive(scan_at) <= _naive(run_at):
        return out                                    # прогон свежее
    by_port = {(s.port, s.protocol): s for s in run_svc}
    enriched = False
    merged: dict[tuple[int, str], ServiceInfo] = {} if full else dict(by_port)
    for s in scan_svc:
        old = by_port.get((s.port, s.protocol))
        if not with_versions and old is not None and (old.product or old.version):
            s = replace(s, product=old.product, version=old.version, cpe=old.cpe,
                        service=s.service or old.service)
            enriched = True
        merged[(s.port, s.protocol)] = s
    return HostPorts(host=key, services=[merged[k] for k in sorted(merged)],
                     source="port_scan", port_scan_id=sid, seen_at=scan_at,
                     run_id=rid if (enriched or (not full and run_svc)) else None,
                     versions_from_run=enriched, ports_from_run=not full and bool(run_svc))
