"""Оркестратор прогона: allowlist-гейт -> модули -> находки.

Единственное место, где цели фильтруются через allowlist; модули получают уже
безопасный список. Каждый отказ и запуск пишется в аудит.

Два уровня:
  * `Orchestrator` — чистое ядро: гейт + последовательный запуск модулей над
    уже готовым AllowlistGate (без БД);
  * `RunService` — прогон, сохранённый в БД (`scan_runs`): читает allowlist
    договора из БД в момент запуска, исполняет `Orchestrator`, сохраняет
    инвентарь и находки (со статусами относительно предыдущего прогона) и ведёт
    статус pending -> running -> done | failed | stopped.

Остановка кооперативная: статус `stopped` выставляется в БД сразу, а
исполняющийся прогон проверяет его между модулями (модуль, уже начавший работу,
доводится до конца — прервать nmap посреди пачки нельзя без риска потерять
аудит его действий).
"""
from __future__ import annotations

import ipaddress
import logging
from collections.abc import Callable, Iterable, Mapping
from concurrent.futures import Executor, ThreadPoolExecutor
from dataclasses import dataclass, field

from sqlalchemy.orm import Session, sessionmaker

from scanner.core import repository as repo
from scanner.core.allowlist import AllowlistGate
from scanner.core.audit import AuditSink
from scanner.core.db import session_scope
from scanner.core.models import Finding, ServiceInfo
from scanner.core.ratelimit import PROFILES, RateProfile, get_profile
from scanner.modules.base import ScanContext, ScanModule
from scanner.reporting.diff import diff_runs

# Порядок исполнения: discovery первым — его сервисы (ctx.services) нужны
# остальным модулям.
MODULE_ORDER: tuple[str, ...] = ("discovery", "vuln", "config_audit", "cred_audit")

# Защита от опечатки вида 10.0.0.0/8 в запросе: столько адресов за прогон
# с запасом покрывает «десятки–сотни хостов».
MAX_TARGETS_PER_RUN = 4096

ModuleFactory = Callable[[], ScanModule]

log = logging.getLogger(__name__)


def default_module_registry() -> dict[str, ModuleFactory]:
    """Имя модуля -> фабрика. Импорт ленивый: модули тянут свои зависимости."""
    def discovery() -> ScanModule:
        from scanner.modules.discovery import DiscoveryModule
        return DiscoveryModule()

    def vuln() -> ScanModule:
        from scanner.modules.vuln import VulnModule
        return VulnModule()

    def config_audit() -> ScanModule:
        from scanner.modules.config_audit import ConfigAuditModule
        return ConfigAuditModule()

    def cred_audit() -> ScanModule:
        from scanner.modules.cred_audit import CredentialAuditModule
        return CredentialAuditModule()

    return {"discovery": discovery, "vuln": vuln, "config_audit": config_audit,
            "cred_audit": cred_audit}


def order_modules(names: Iterable[str]) -> list[str]:
    """Уникальные имена модулей в порядке исполнения (неизвестные — в конце)."""
    uniq = list(dict.fromkeys(names))
    rank = {m: i for i, m in enumerate(MODULE_ORDER)}
    return sorted(uniq, key=lambda m: (rank.get(m, len(rank)), uniq.index(m)))


# ========== Цели ==========
@dataclass(slots=True)
class DeniedTarget:
    target: str
    reason: str          # not_in_allowlist | not_an_ip | too_many_targets
    count: int = 1       # для подсети — сколько адресов отброшено


@dataclass(slots=True)
class TargetPlan:
    allowed: list[str] = field(default_factory=list)
    denied: list[DeniedTarget] = field(default_factory=list)


def plan_targets(gate: AllowlistGate, requested: Iterable[str], *,
                 max_targets: int = MAX_TARGETS_PER_RUN) -> TargetPlan:
    """Разворачивает запрошенные цели в адреса и пропускает их через allowlist.

    IP — как есть; подсеть (CIDR) — в адреса хостов, каждый проверяется
    отдельно (подсеть, частично выходящая за allowlist, урезается до
    разрешённой части). Имена хостов отклоняются: резолв DNS — сетевое
    действие, а гейт работает только с литеральными адресами.
    """
    plan = TargetPlan()
    seen: set[str] = set()
    for raw in requested:
        spec = raw.strip()
        try:
            hosts = [str(ipaddress.ip_address(spec))]
        except ValueError:
            try:
                net = ipaddress.ip_network(spec, strict=False)
            except ValueError:
                plan.denied.append(DeniedTarget(spec, "not_an_ip"))
                continue
            if net.num_addresses > max_targets + 2:
                plan.denied.append(DeniedTarget(spec, "too_many_targets",
                                                net.num_addresses))
                continue
            # hosts() для /31, /32 (и /127, /128) отдаёт оба/единственный адрес
            hosts = [str(h) for h in net.hosts()]
        allowed, denied = gate.filter(hosts)
        if denied:
            plan.denied.append(DeniedTarget(spec, "not_in_allowlist", len(denied)))
        for h in allowed:
            if h not in seen:
                seen.add(h)
                plan.allowed.append(h)
    if len(plan.allowed) > max_targets:
        extra = plan.allowed[max_targets:]
        plan.allowed = plan.allowed[:max_targets]
        plan.denied.append(DeniedTarget(f"{extra[0]}…", "too_many_targets", len(extra)))
    return plan


# ========== Ядро ==========
@dataclass(slots=True)
class RunOutcome:
    findings: list[Finding] = field(default_factory=list)
    services: list[ServiceInfo] = field(default_factory=list)
    allowed: list[str] = field(default_factory=list)
    denied: list[DeniedTarget] = field(default_factory=list)
    errors: dict[str, str] = field(default_factory=dict)   # модуль -> ошибка
    stopped: bool = False


class Orchestrator:
    def __init__(self, gate: AllowlistGate, audit: AuditSink, *,
                 should_stop: Callable[[], bool] | None = None):
        self.gate = gate
        self.audit = audit
        self.should_stop = should_stop or (lambda: False)

    def run(self, *, engagement_id: int, scan_run_id: int, requested_targets: list[str],
            modules: list[ScanModule], rate: RateProfile) -> list[Finding]:
        return self.run_detailed(engagement_id=engagement_id, scan_run_id=scan_run_id,
                                 requested_targets=requested_targets, modules=modules,
                                 rate=rate).findings

    def run_detailed(self, *, engagement_id: int, scan_run_id: int,
                     requested_targets: list[str], modules: list[ScanModule],
                     rate: RateProfile) -> RunOutcome:
        """Гейт + модули по порядку. Ошибка модуля не прерывает остальные."""
        plan = plan_targets(self.gate, requested_targets)
        out = RunOutcome(allowed=plan.allowed, denied=plan.denied)
        for d in plan.denied:
            self.audit.record(subject="scanner", action="deny", target=d.target,
                              result=d.reason,
                              details={"scan_run_id": scan_run_id, "count": d.count})
        if not plan.allowed:
            return out

        ctx = ScanContext(engagement_id=engagement_id, scan_run_id=scan_run_id,
                          targets=list(plan.allowed), rate=rate, audit=self.audit)
        for module in modules:
            if self.should_stop():
                out.stopped = True
                self.audit.record(subject="scanner", action="module_skip",
                                  target=module.name, result="stopped",
                                  details={"scan_run_id": scan_run_id})
                break
            self.audit.record(subject="scanner", action="module_start",
                              target=module.name, result="ok",
                              details={"scan_run_id": scan_run_id,
                                       "targets": len(ctx.targets), "rate": rate.name})
            try:
                found = module.run(ctx)
            except Exception as e:  # noqa: BLE001 — модуль сторонний, прогон продолжается
                out.errors[module.name] = f"{type(e).__name__}: {e}"[:500]
                self.audit.record(subject="scanner", action="module_finish",
                                  target=module.name, result="error",
                                  details={"scan_run_id": scan_run_id,
                                           "error": out.errors[module.name]})
                continue
            out.findings.extend(found)
            self.audit.record(subject="scanner", action="module_finish",
                              target=module.name, result="ok",
                              details={"scan_run_id": scan_run_id,
                                       "findings": len(found)})
        out.services = list(ctx.services or [])
        return out


# ========== Прогон из БД ==========
class _InlineExecutor(Executor):
    """Синхронный исполнитель (тесты, CLI)."""

    def submit(self, fn, /, *args, **kwargs):
        from concurrent.futures import Future
        fut: Future = Future()
        try:
            fut.set_result(fn(*args, **kwargs))
        except BaseException as e:  # noqa: BLE001
            fut.set_exception(e)
        return fut


def inline_executor() -> Executor:
    return _InlineExecutor()


class RunService:
    """Постановка, исполнение и остановка прогонов, сохранённых в БД."""

    def __init__(self, session_factory: sessionmaker[Session], audit: AuditSink, *,
                 registry: Mapping[str, ModuleFactory] | None = None,
                 executor: Executor | None = None):
        self.sessions = session_factory
        self.audit = audit
        self.registry = dict(registry if registry is not None
                             else default_module_registry())
        self.executor = executor or ThreadPoolExecutor(max_workers=2,
                                                       thread_name_prefix="scan-run")

    # --- проверки до постановки --------------------------------------------
    def known_modules(self) -> list[str]:
        return order_modules(self.registry)

    def preview(self, engagement_id: int, requested_targets: list[str]) -> TargetPlan:
        """Что пропустит гейт прямо сейчас (для ответа API до постановки)."""
        with session_scope(self.sessions) as s:
            gate = repo.load_allowlist_gate(s, engagement_id)
        return plan_targets(gate, requested_targets)

    # --- жизненный цикл ----------------------------------------------------
    def submit(self, *, engagement_id: int, modules: list[str], rate_profile: str,
               requested_targets: list[str], actor: str,
               started_by: int | None = None) -> int:
        """Создаёт прогон (pending) и отдаёт его исполнителю. Права проверяет API."""
        unknown = [m for m in modules if m not in self.registry]
        if unknown:
            raise ValueError(f"unknown modules: {', '.join(unknown)}")
        if rate_profile not in PROFILES:
            raise ValueError(f"unknown rate profile: {rate_profile}")
        names = order_modules(modules)
        with session_scope(self.sessions) as s:
            run_id = repo.create_scan_run(s, engagement_id=engagement_id, modules=names,
                                          rate_profile=rate_profile,
                                          started_by=started_by)
        self.audit.record(subject=actor, action="scan_queue", target=f"scan_run:{run_id}",
                          result="ok",
                          details={"engagement_id": engagement_id, "modules": names,
                                   "rate_profile": rate_profile,
                                   "requested_targets": requested_targets[:100]})
        self.executor.submit(self.execute, run_id, list(requested_targets))
        return run_id

    def request_stop(self, scan_run_id: int, *, actor: str) -> str:
        """Останавливает pending/running прогон; возвращает итоговый статус."""
        with session_scope(self.sessions) as s:
            run = repo.get_scan_run(s, scan_run_id)
            if run is None:
                raise LookupError(f"scan_run {scan_run_id} not found")
            before = run.status
            if before in {"pending", "running"}:
                repo.set_scan_run_status(s, scan_run_id, "stopped")
            status = run.status
        self.audit.record(subject=actor, action="scan_stop", target=f"scan_run:{scan_run_id}",
                          result="ok" if before in {"pending", "running"} else "noop",
                          details={"status_before": before})
        return status

    def _status(self, scan_run_id: int) -> str | None:
        with session_scope(self.sessions) as s:
            run = repo.get_scan_run(s, scan_run_id)
            return None if run is None else run.status

    def execute(self, scan_run_id: int, requested_targets: list[str]) -> str:
        """Исполняет прогон. Возвращает финальный статус. Не бросает исключений."""
        try:
            return self._execute(scan_run_id, requested_targets)
        except Exception as e:  # noqa: BLE001 — исполнитель фоновый, ошибку фиксируем
            self.audit.record(subject="scanner", action="scan_finish",
                              target=f"scan_run:{scan_run_id}", result="failed",
                              details={"error": f"{type(e).__name__}: {e}"[:500]})
            try:
                with session_scope(self.sessions) as s:
                    run = repo.get_scan_run(s, scan_run_id)
                    if run is not None and run.status in {"pending", "running"}:
                        repo.set_scan_run_status(s, scan_run_id, "failed")
            except Exception:  # БД недоступна; след уже в аудите
                log.exception("scan_run %s: cannot mark as failed", scan_run_id)
            return "failed"

    def _execute(self, scan_run_id: int, requested_targets: list[str]) -> str:
        with session_scope(self.sessions) as s:
            run = repo.get_scan_run(s, scan_run_id)
            if run is None:
                raise LookupError(f"scan_run {scan_run_id} not found")
            if run.status != "pending":      # остановлен до старта
                return run.status
            engagement_id = run.engagement_id
            names = list(run.modules)
            rate = get_profile(run.rate_profile)
            # allowlist читается в момент запуска, а не постановки
            gate = repo.load_allowlist_gate(s, engagement_id)
            repo.set_scan_run_status(s, scan_run_id, "running")
        self.audit.record(subject="scanner", action="scan_start",
                          target=f"scan_run:{scan_run_id}", result="ok",
                          details={"engagement_id": engagement_id, "modules": names,
                                   "rate_profile": rate.name})

        modules = [self.registry[n]() for n in names]
        orch = Orchestrator(gate, self.audit,
                            should_stop=lambda: self._status(scan_run_id) == "stopped")
        out = orch.run_detailed(engagement_id=engagement_id, scan_run_id=scan_run_id,
                                requested_targets=requested_targets, modules=modules,
                                rate=rate)

        with session_scope(self.sessions) as s:
            if out.services:
                repo.save_services(s, scan_run_id=scan_run_id, services=out.services)
            prev_id = repo.previous_scan_run_id(s, scan_run_id)
            statuses = {}
            if prev_id is not None:
                d = diff_runs(repo.get_findings(s, prev_id), out.findings,
                              repo.historically_fixed_keys(s, engagement_id, scan_run_id))
                statuses = {f.dedup_key(): st for st, items in
                            (("open", d.open), ("new", d.new),
                             ("regression", d.regression)) for f in items}
            repo.save_findings(s, engagement_id=engagement_id, scan_run_id=scan_run_id,
                               findings=out.findings, statuses=statuses)
            run = repo.get_scan_run(s, scan_run_id)
            s.refresh(run)
            if out.stopped or run.status == "stopped":
                final = "stopped"
            elif not out.allowed or out.errors:
                final = "failed"
            else:
                final = "done"
            if run.status != final:
                repo.set_scan_run_status(s, scan_run_id, final)
        self.audit.record(subject="scanner", action="scan_finish",
                          target=f"scan_run:{scan_run_id}", result=final,
                          details={"targets": len(out.allowed),
                                   "denied": len(out.denied),
                                   "findings": len(out.findings),
                                   "errors": out.errors or None})
        return final
