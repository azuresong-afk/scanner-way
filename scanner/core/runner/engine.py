"""Чистое ядро прогона: allowlist-гейт + последовательный запуск модулей над
готовым AllowlistGate (без БД). Каждый отказ и запуск пишется в аудит."""
from __future__ import annotations

import ipaddress
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field

from scanner.core import coverage as cv
from scanner.core import run_events as ev
from scanner.core.allowlist import AllowlistGate
from scanner.core.audit import AuditSink
from scanner.core.credentials import HostCredential
from scanner.core.models import Finding, HostInventory, HostOs, ServiceInfo
from scanner.core.ratelimit import RateProfile
from scanner.core.runner.progress import RunProgress
from scanner.core.runner.targets import DeniedTarget, plan_targets
from scanner.modules.base import ScanContext, ScanModule


# ========== Ядро ==========
@dataclass(slots=True)
class RunOutcome:
    findings: list[Finding] = field(default_factory=list)
    services: list[ServiceInfo] = field(default_factory=list)
    hosts: list[HostOs] = field(default_factory=list)
    inventory: list[HostInventory] = field(default_factory=list)
    allowed: list[str] = field(default_factory=list)
    denied: list[DeniedTarget] = field(default_factory=list)
    errors: dict[str, str] = field(default_factory=dict)   # модуль -> ошибка
    stopped: bool = False
    # Факты для профилей соответствия (R5): какие проверки на хосте выполнялись.
    compliance_facts: dict[str, dict] = field(default_factory=dict)
    # Покрытие: что реально проверено на каждом хосте каждым модулем.
    coverage: cv.Coverage = field(default_factory=cv.Coverage)
    # Ограничения достоверности результата (нет бюллетеней, только баннеры…).
    warnings: list[dict] = field(default_factory=list)


def finalize_coverage(ctx: ScanContext, module_names: Iterable[str],
                      errors: Mapping[str, str], ran: set[str]) -> None:
    """Достраивает покрытие тем, чего модули не отметили сами.

    Ошибка модуля (исключение) — его находки потеряны, поэтому все хосты по
    нему error (кроме более точных unreachable/timeout); модуль, до которого
    прогон не дошёл (остановка), — skipped; хост, который discovery не нашёл, —
    unreachable; остальное — completed."""
    hosts = []
    for t in ctx.targets:
        try:
            hosts.append(str(ipaddress.ip_address(t.strip())))
        except ValueError:
            continue
    alive = ctx.alive_hosts()
    for m in module_names:
        for h in hosts:
            cur = ctx.coverage.get(h, m)
            if m in errors:
                if cur is None or cur.status in (cv.COMPLETED, cv.NOT_APPLICABLE,
                                                 cv.SKIPPED):
                    ctx.coverage.mark(h, m, cv.ERROR, f"ошибка модуля: {errors[m]}"[:500],
                                      force=True)
                continue
            if cur is not None:
                continue
            if m not in ran:
                ctx.coverage.mark(h, m, cv.SKIPPED, "прогон остановлен до этого модуля")
            elif m != "discovery" and alive is not None and h not in alive:
                ctx.coverage.mark(h, m, cv.UNREACHABLE,
                                  "хост не обнаружен (нет открытых портов) — "
                                  "модуль на нём не выполнялся")
            else:
                ctx.coverage.mark(h, m, cv.COMPLETED)



class Orchestrator:
    def __init__(self, gate: AllowlistGate, audit: AuditSink, *,
                 should_stop: Callable[[], bool] | None = None,
                 events: Callable[[ev.Event], None] | None = None):
        self.gate = gate
        self.audit = audit
        self.should_stop = should_stop or (lambda: False)
        # лента событий прогона для «Сводки» (scanner.core.run_events)
        self.events = events or (lambda _e: None)

    def run(self, *, engagement_id: int, scan_run_id: int, requested_targets: list[str],
            modules: list[ScanModule], rate: RateProfile,
            credentials: list[HostCredential] | None = None,
            cred_candidates: list[tuple[str, str]] | None = None) -> list[Finding]:
        return self.run_detailed(engagement_id=engagement_id, scan_run_id=scan_run_id,
                                 requested_targets=requested_targets, modules=modules,
                                 rate=rate, credentials=credentials,
                                 cred_candidates=cred_candidates).findings

    def run_detailed(self, *, engagement_id: int, scan_run_id: int,
                     requested_targets: list[str], modules: list[ScanModule],
                     rate: RateProfile,
                     credentials: list[HostCredential] | None = None,
                     cred_candidates: list[tuple[str, str]] | None = None,
                     options: Mapping[str, object] | None = None,
                     progress: Callable[[dict], None] | None = None,
                     progress_history: Mapping[str, float] | None = None) -> RunOutcome:
        """Гейт + модули по порядку. Ошибка модуля не прерывает остальные."""
        plan = plan_targets(self.gate, requested_targets)
        out = RunOutcome(allowed=plan.allowed, denied=plan.denied)
        for d in plan.denied:
            self.audit.record(subject="scanner", action="deny", target=d.target,
                              result=d.reason,
                              details={"scan_run_id": scan_run_id, "count": d.count})
        self.events(ev.run_start(len(plan.allowed), [m.name for m in modules]))
        if not plan.allowed:
            return out

        ctx = ScanContext(engagement_id=engagement_id, scan_run_id=scan_run_id,
                          targets=list(plan.allowed), rate=rate, audit=self.audit,
                          credentials=list(credentials or []),
                          cred_candidates=list(cred_candidates or []),
                          options=dict(options or {}))
        tracker = (RunProgress(progress, [m.name for m in modules], len(ctx.targets),
                               history=progress_history)
                   if progress is not None else None)
        if tracker is not None:
            ctx.coverage.listener = tracker.mark
        ran: set[str] = set()
        for module in modules:
            if self.should_stop():
                out.stopped = True
                self.audit.record(subject="scanner", action="module_skip",
                                  target=module.name, result="stopped",
                                  details={"scan_run_id": scan_run_id})
                self.events(ev.module_skip(module.name))
                break
            ran.add(module.name)
            if tracker is not None:
                tracker.begin(module.name)
            self.audit.record(subject="scanner", action="module_start",
                              target=module.name, result="ok",
                              details={"scan_run_id": scan_run_id,
                                       "targets": len(ctx.targets), "rate": rate.name})
            self.events(ev.module_start(module.name, len(ctx.targets)))
            try:
                found = module.run(ctx)
            except Exception as e:  # noqa: BLE001 — модуль сторонний, прогон продолжается
                if tracker is not None:
                    tracker.end_stage(ctx.targets)
                out.errors[module.name] = f"{type(e).__name__}: {e}"[:500]
                self.audit.record(subject="scanner", action="module_finish",
                                  target=module.name, result="error",
                                  details={"scan_run_id": scan_run_id,
                                           "error": out.errors[module.name]})
                self.events(ev.module_error(module.name, out.errors[module.name]))
                continue
            if tracker is not None:
                tracker.end_stage(ctx.targets)
            out.findings.extend(found)
            ctx.completed.add(module.name)
            self.audit.record(subject="scanner", action="module_finish",
                              target=module.name, result="ok",
                              details={"scan_run_id": scan_run_id,
                                       "findings": len(found)})
            self.events(ev.module_finish(module.name, len(found)))
        ctx.coverage.listener = None
        if tracker is not None:
            tracker.saving()
        finalize_coverage(ctx, [m.name for m in modules], out.errors, ran)
        out.coverage = ctx.coverage
        from scanner.core.confidence import (
            apply_confidence,
            supersede_banner,
            warnings_for,
        )
        out.findings, superseded = supersede_banner(out.findings, ctx.assessed_cves)
        if superseded:
            self.audit.record(subject="scanner", action="banner_superseded",
                              target=f"scan_run:{scan_run_id}", result="ok",
                              details={"findings": len(superseded),
                                       "ids": [f.vuln_id for f in superseded][:50]})
        apply_confidence(out.findings)
        out.warnings = warnings_for(out.findings, ctx.run_notes, ctx.coverage)
        cov_sum = ctx.coverage.summary()
        self.audit.record(subject="scanner", action="coverage", target=f"scan_run:{scan_run_id}",
                          result="gaps" if cov_sum["gaps"] else "ok",
                          details={k: cov_sum[k] for k in ("hosts", "hosts_checked",
                                                           "hosts_partial",
                                                           "hosts_unreachable", "gaps")})
        out.services = list(ctx.services or [])
        out.hosts = list(ctx.hosts.values())
        out.inventory = list(ctx.inventory.values())
        from scanner.compliance.facts import merge_run_facts
        out.compliance_facts = merge_run_facts(
            ctx.compliance_facts, completed=ctx.completed,
            discovered={s.host for s in out.services} | set(ctx.hosts),
            inventory=ctx.inventory, policy_hosts=set(ctx.host_policy_configs),
            targets=ctx.targets)
        return out
