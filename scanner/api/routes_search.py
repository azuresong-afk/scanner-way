"""Быстрый поиск по проекту (поле в шапке и палитра Ctrl+K).

Один запрос — пять групп результатов по текущему проекту (договору):

* **hosts** — активы проекта по адресу, имени, владельцу и заметкам, а также
  хосты, на которых установлено найденное ПО;
* **software** — пакеты (последняя инвентаризация каждого хоста) и ПО сервисов
  (баннеры nmap -sV) прогона: сколько версий и хостов, сколько уязвимо;
* **vulns** — CVE и БДУ из находок прогона (без info и ложных срабатываний),
  сгруппированные по уязвимости;
* **actions** — действия плана исправлений прогона («Что исправить»);
* **commands** — команды этих действий (для копирования).

Прогон — последний завершённый (как на вкладке «Находки» без выбора) либо
переданный в run_id. Новых таблиц нет: читаются активы, инвентаризация,
находки и кэшированный план исправлений. Только чтение, без записи в аудит.
"""
from __future__ import annotations

import ipaddress
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel
from sqlalchemy import String, cast, func, select

from scanner.api.deps import Principal, SessionDep, require
from scanner.api.rbac import Perm
from scanner.api.routes_engagements import get_engagement
from scanner.core import findings_query as fq
from scanner.core import repository as repo
from scanner.core.assets import host_key
from scanner.core.db import (
    AssetRow,
    FindingRow,
    HostPackageRow,
    HostResult,
    ScanRun,
    ServiceResult,
)

router = APIRouter(prefix="/engagements", tags=["search"])

# Сколько строк находок/пакетов читать на один запрос: поиск — подсказка, а не
# выгрузка; полный список открывается переходом на страницу раздела.
ROW_CAP = 5000
_SEV_ORDER = ("critical", "high", "medium", "low", "info")
_SEV_RANK = {s: i for i, s in enumerate(_SEV_ORDER)}


class SearchHost(BaseModel):
    host: str
    hostname: str | None = None
    os: str | None = None
    criticality: str | None = None
    vulns: int = 0
    max_severity: str | None = None
    match: str | None = None          # «openssh-server 1:9.2p1-2» — найдено по ПО


class SearchSoftware(BaseModel):
    name: str
    versions: list[str]
    host_count: int
    vulnerable_hosts: int
    vulns: int
    hosts: list[str]                  # первые хосты (для перехода, если хост один)
    source: str                       # package | service


class SearchVuln(BaseModel):
    id: str
    title: str
    cves: list[str]
    bdu_ids: list[str]
    severity: str
    host_count: int
    hosts: list[str]


class SearchAction(BaseModel):
    key: str
    title: str
    kind_label: str
    severity: str
    os: str | None = None
    host_count: int
    finding_count: int
    priority: int | None = None


class SearchCommand(BaseModel):
    key: str                          # действие, к которому относится команда
    title: str
    os: str | None = None
    command: str                      # главная команда (показывается)
    commands: list[str]               # все шаги (копируются)


class SearchCounts(BaseModel):
    hosts: int = 0
    software: int = 0
    vulns: int = 0
    actions: int = 0
    commands: int = 0


class SearchOut(BaseModel):
    q: str
    run_id: int | None
    run_name: str | None
    assets: int                       # хостов в проекте
    findings: int                     # находок в прогоне (без info)
    counts: SearchCounts              # всего совпадений по группам
    hosts: list[SearchHost]
    software: list[SearchSoftware]
    vulns: list[SearchVuln]
    actions: list[SearchAction]
    commands: list[SearchCommand]


def default_run(session, engagement_id: int) -> ScanRun | None:
    """Последний завершённый прогон, неудачный — только если других нет."""
    runs = list(session.scalars(
        select(ScanRun).where(ScanRun.engagement_id == engagement_id,
                              ScanRun.status.in_(repo.FINISHED_RUN_STATUSES))
        .order_by(ScanRun.id.desc())))
    return next((r for r in runs if r.status != "failed"), runs[0] if runs else None)


def _host_sort(h: str):
    ip = ipaddress.ip_address(h)
    return (ip.version, int(ip))


def _worse(a: str | None, b: str) -> str:
    return b if a is None or _SEV_RANK.get(b, 9) < _SEV_RANK.get(a, 9) else a


def _main_command(commands: list[str], packages: list[str]) -> str:
    """Команда, которая что-то меняет: с именем пакета, иначе последняя."""
    for c in reversed(commands):
        if any(p in c for p in packages):
            return c
    return commands[-1]


@router.get("/{engagement_id}/search", response_model=SearchOut)
def search(engagement_id: int, request: Request,
           _: Annotated[Principal, Depends(require(Perm.VIEW_REPORT))],
           session: SessionDep,
           q: Annotated[str, Query(min_length=1, max_length=100)],
           run_id: int | None = None,
           limit: Annotated[int, Query(ge=1, le=20)] = 5) -> dict:
    from scanner.api.routes_findings import fix_plan
    from scanner.api.routes_runs import FINISHED

    get_engagement(session, engagement_id)
    needle = q.strip().casefold()
    if not needle:
        raise HTTPException(422, "q: empty")
    like = fq._like(q.strip())

    if run_id is not None:
        run = session.get(ScanRun, run_id)
        if run is None or run.engagement_id != engagement_id:
            raise HTTPException(404, "scan run not found")
    else:
        run = default_run(session, engagement_id)
    run_ids = list(session.scalars(select(ScanRun.id).where(ScanRun.engagement_id == engagement_id)))

    # --- действия плана исправлений (из них же — уязвимость ПО и команды) ---
    tasks = []
    if run is not None:
        tasks, _fps = fix_plan(request, session, run.id, engagement_id,
                               cacheable=run.status in FINISHED)
    matched_tasks = [t for t in tasks if needle in t.search_text().casefold()]
    cmd_tasks = [t for t in tasks if t.commands and (
        t in matched_tasks or any(needle in c.casefold() for c in t.commands))]

    # --- ПО: пакеты последней инвентаризации каждого хоста + сервисы прогона ---
    latest_pkg: dict[str, int] = {}
    for h, rid in session.execute(
            select(HostPackageRow.host, func.max(HostPackageRow.scan_run_id))
            .where(HostPackageRow.scan_run_id.in_(run_ids)).group_by(HostPackageRow.host)):
        latest_pkg[host_key(h)] = rid
    soft: dict[tuple[str, str], dict] = {}
    host_match: dict[str, str] = {}
    if latest_pkg:
        rows = session.execute(
            select(HostPackageRow.host, HostPackageRow.scan_run_id, HostPackageRow.name,
                   HostPackageRow.version)
            .where(HostPackageRow.scan_run_id.in_(set(latest_pkg.values())),
                   HostPackageRow.name.ilike(like, escape="\\"))
            .limit(ROW_CAP))
        for h, rid, name, ver in rows:
            h = host_key(h)
            if latest_pkg.get(h) != rid:
                continue
            s = soft.setdefault(("package", name), {"versions": set(), "hosts": set()})
            s["versions"].add(ver)
            s["hosts"].add(h)
            host_match.setdefault(h, f"{name} {ver}")
    if run is not None:
        prod = ServiceResult.product
        rows = session.execute(
            select(HostResult.host, prod, ServiceResult.version)
            .join(ServiceResult, ServiceResult.host_id == HostResult.id)
            .where(HostResult.scan_run_id == run.id, prod.is_not(None),
                   prod.ilike(like, escape="\\"))
            .limit(ROW_CAP))
        for h, product, ver in rows:
            h = host_key(h)
            s = soft.setdefault(("service", product), {"versions": set(), "hosts": set()})
            if ver:
                s["versions"].add(ver)
            s["hosts"].add(h)
            host_match.setdefault(h, " ".join(x for x in (product, ver) if x))
    software = []
    for (source, name), s in soft.items():
        key = name.casefold()
        vuln_hosts: set[str] = set()
        vulns = 0
        for t in tasks:
            if key in (p.casefold() for p in t.packages) or \
                    (t.software and t.software.casefold().startswith(key)):
                vuln_hosts |= {x.host for x in t.hosts}
                vulns += t.findings
        software.append({"name": name, "versions": sorted(s["versions"]),
                         "host_count": len(s["hosts"]), "vulnerable_hosts": len(vuln_hosts),
                         "vulns": vulns, "hosts": sorted(s["hosts"], key=_host_sort)[:3],
                         "source": source})
    # сначала уязвимое и точное совпадение имени, потом распространённое
    software.sort(key=lambda x: (-x["vulns"], x["name"].casefold() != needle,
                                 -x["host_count"], x["name"]))

    # --- находки прогона: уязвимости по CVE/БДУ и счётчики хостов ---
    total_findings = 0
    host_vulns: dict[str, list] = {}
    vuln_groups: dict[str, dict] = {}
    if run is not None:
        base = fq.FindingFilter(include_info=False, false_positives="exclude")
        cnt = select(func.count()).select_from(
            fq.filtered(session, run.id, engagement_id, base).subquery())
        total_findings = session.scalar(cnt) or 0
        hcol = fq._host_text(session)
        for h, sev, n in session.execute(
                fq.filtered(session, run.id, engagement_id, base,
                            columns=(cast(hcol, String), FindingRow.severity, func.count()))
                .group_by(cast(hcol, String), FindingRow.severity)):
            e = host_vulns.setdefault(host_key(h), [0, None])
            e[0] += n
            e[1] = _worse(e[1], sev)
        flt = fq.FindingFilter(include_info=False, false_positives="exclude", query=q.strip())
        rows = session.scalars(fq.filtered(session, run.id, engagement_id, flt)
                               .order_by(FindingRow.id).limit(ROW_CAP))
        for r in rows:
            ids = [*r.cve_ids, *r.bdu_ids, r.vuln_id]
            if not any(needle in (i or "").casefold() for i in ids) and \
                    needle not in (r.title or "").casefold():
                continue                 # совпал только адрес хоста — это группа «Хосты»
            g = vuln_groups.setdefault(r.vuln_id, {
                "id": r.vuln_id, "title": r.title, "cves": [], "bdu_ids": [],
                "severity": r.severity, "hosts": set()})
            g["cves"] = sorted(set(g["cves"]) | set(r.cve_ids))
            g["bdu_ids"] = sorted(set(g["bdu_ids"]) | set(r.bdu_ids))
            g["severity"] = _worse(g["severity"], r.severity)
            g["hosts"].add(host_key(r.host))
    vulns = [{**g, "host_count": len(g["hosts"]),
              "hosts": sorted(g["hosts"], key=_host_sort)[:3]} for g in vuln_groups.values()]
    vulns.sort(key=lambda v: (_SEV_RANK.get(v["severity"], 9),
                              needle not in v["id"].casefold(), -v["host_count"], v["id"]))

    # --- хосты: активы по адресу/имени/владельцу и хосты с найденным ПО ---
    assets = list(session.scalars(select(AssetRow).where(AssetRow.engagement_id == engagement_id)))
    by_addr = {host_key(a.address): a for a in assets}
    os_names: dict[str, str] = {}
    if run_ids:
        for h, os_guess in session.execute(
                select(HostResult.host, HostResult.os_guess)
                .where(HostResult.scan_run_id.in_(run_ids), HostResult.os_guess.is_not(None))
                .order_by(HostResult.scan_run_id)):
            os_names[host_key(h)] = os_guess
    direct = [h for h, a in by_addr.items() if needle in " ".join(
        filter(None, [h, a.hostname, a.owner, a.notes])).casefold()]
    found = set(direct)
    by_software = [h for h in sorted(host_match, key=_host_sort) if h not in found]
    # хосты с найденным ПО — сначала уязвимые
    by_software.sort(key=lambda h: _SEV_RANK.get((host_vulns.get(h) or [0, None])[1] or "", 9))
    hosts = []
    for h in sorted(direct, key=_host_sort) + by_software:
        a = by_addr.get(h)
        v = host_vulns.get(h) or [0, None]
        hosts.append({"host": h, "hostname": a.hostname if a else None,
                      "os": os_names.get(h), "criticality": a.criticality if a else None,
                      "vulns": v[0], "max_severity": v[1],
                      "match": None if h in found else host_match.get(h)})

    actions = [{"key": t.key, "title": t.title, "kind_label": t.to_dict()["kind_label"],
                "severity": str(t.severity), "os": t.os, "host_count": len(t.hosts),
                "finding_count": t.findings,
                "priority": round(t.priority.score) if t.priority else None}
               for t in matched_tasks[:limit]]
    commands = [{"key": t.key, "title": t.title, "os": t.os,
                 "command": _main_command(t.commands, t.packages),
                 "commands": list(t.commands)} for t in cmd_tasks[:limit]]
    return {
        "q": q.strip(), "run_id": run.id if run else None,
        "run_name": run.name if run else None,
        "assets": len(by_addr), "findings": total_findings,
        "counts": {"hosts": len(hosts), "software": len(software), "vulns": len(vulns),
                   "actions": len(matched_tasks), "commands": len(cmd_tasks)},
        "hosts": hosts[:limit], "software": software[:limit], "vulns": vulns[:limit],
        "actions": actions, "commands": commands,
    }
