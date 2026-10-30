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
from scanner.core.credentials import CredentialVault, HostCredential, load_vault
from scanner.core.db import session_scope
from scanner.core.models import Finding, HostInventory, HostOs, ServiceInfo
from scanner.core.naming import clean_name, run_title
from scanner.core.ratelimit import PROFILES, RateProfile, get_profile
from scanner.modules.base import ScanContext, ScanModule
from scanner.reporting.diff import diff_runs

# Порядок исполнения: discovery первым — его сервисы (ctx.services) нужны
# остальным модулям.
MODULE_ORDER: tuple[str, ...] = ("discovery", "vuln", "auth_inventory", "win_inventory",
                                 "config_audit", "password_policy", "cred_audit")

# Движки поиска уязвимостей (выбор оператора): сетевые проверки Nuclei без
# учётной записи и/или инвентаризация по учётной записи — пакеты Linux
# (auth_inventory) и обновления/ПО Windows по WinRM (win_inventory). Каждый
# модуль инертен там, где у него нет подходящей учётки, поэтому в смешанной
# сети «По учётной записи» покрывает и Linux, и Windows.
VULN_ENGINES: dict[str, tuple[str, ...]] = {
    "nuclei": ("vuln",),
    "credentialed": ("auth_inventory", "win_inventory"),
    "both": ("vuln", "auth_inventory", "win_inventory"),
}
# Модули, которые входят на хосты по учётным записям договора (ctx.credentials).
CREDENTIAL_MODULES = frozenset({"auth_inventory", "win_inventory", "config_audit"})
# Модули-спутники: ставятся в прогон вместе с основным. password_policy оценивает
# парольную политику, которую собирает config_audit (ctx.host_policy_configs);
# сам по себе в сеть не ходит и без config_audit инертен.
COMPANION_MODULES: dict[str, tuple[str, ...]] = {"config_audit": ("password_policy",)}

# Защита от опечатки вида 10.0.0.0/8 в запросе: столько адресов за прогон
# с запасом покрывает «десятки–сотни хостов».
MAX_TARGETS_PER_RUN = 4096

ModuleFactory = Callable[[], ScanModule]

log = logging.getLogger(__name__)


def default_module_registry(matcher: object | None = None) -> dict[str, ModuleFactory]:
    """Имя модуля -> фабрика. Импорт ленивый: модули тянут свои зависимости.

    matcher — слой сопоставления CVE/БДУ (feeds.matcher.VulnMatcher). Когда он
    задан, модуль vuln обогащает находки CVE/БДУ ФСТЭК, а auth_inventory
    сопоставляет с ними версии пакетов; без него (matcher=None)
    находки остаются без привязки к справочникам — поэтому в реальном прогоне
    RunService всегда передаёт matcher над справочниками из БД.
    """
    def discovery() -> ScanModule:
        from scanner.modules.discovery import DiscoveryModule
        return DiscoveryModule()

    def vuln() -> ScanModule:
        from scanner.modules.vuln import VulnModule
        return VulnModule(matcher=matcher)

    def auth_inventory() -> ScanModule:
        from scanner.core.sshexec import options_from_env
        from scanner.modules.auth_inventory import (
            AuthInventoryModule,
            AuthInventoryOptions,
        )
        return AuthInventoryModule(AuthInventoryOptions(ssh=options_from_env()),
                                   matcher=matcher, advisories=_advisory_store(matcher))

    def win_inventory() -> ScanModule:
        from scanner.core.winexec import options_from_env
        from scanner.modules.win_inventory import (
            WinInventoryModule,
            WinInventoryOptions,
        )
        return WinInventoryModule(WinInventoryOptions(winrm=options_from_env()),
                                  matcher=matcher)

    def config_audit() -> ScanModule:
        from scanner.modules.config_audit import ConfigAuditModule, options_from_env
        return ConfigAuditModule(options_from_env())

    def password_policy() -> ScanModule:
        from scanner.modules.password_policy import PasswordPolicyModule
        return PasswordPolicyModule()

    def cred_audit() -> ScanModule:
        from scanner.modules.authenticators import build_default_authenticator
        from scanner.modules.cred_audit import CredentialAuditModule
        # Бэкенды проверки подключаются по умолчанию (SSH на paramiko); модуль всё
        # равно инертен без согласованного набора проверки (ctx.cred_candidates).
        return CredentialAuditModule(authenticator=build_default_authenticator())

    return {"discovery": discovery, "vuln": vuln, "auth_inventory": auth_inventory,
            "win_inventory": win_inventory, "config_audit": config_audit,
            "password_policy": password_policy, "cred_audit": cred_audit}


def _advisory_store(matcher: object | None):
    """Бюллетени дистрибутивов (R2) из той же БД, что и справочники matcher."""
    engine = getattr(getattr(matcher, "store", None), "engine", None)
    if engine is None:
        return None
    from scanner.feeds.advisories.store import SqlAdvisoryStore
    return SqlAdvisoryStore(engine)


def with_companions(names: Iterable[str], known: Iterable[str] | None = None) -> list[str]:
    """Модули прогона плюс их спутники (COMPANION_MODULES); known — реестр,
    спутник вне его не добавляется."""
    names = list(names)
    allowed = None if known is None else set(known)
    extra = [c for m in names for c in COMPANION_MODULES.get(m, ())
             if c not in names and (allowed is None or c in allowed)]
    return list(dict.fromkeys([*names, *extra]))


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
    hosts: list[HostOs] = field(default_factory=list)
    inventory: list[HostInventory] = field(default_factory=list)
    allowed: list[str] = field(default_factory=list)
    denied: list[DeniedTarget] = field(default_factory=list)
    errors: dict[str, str] = field(default_factory=dict)   # модуль -> ошибка
    stopped: bool = False
    # Факты для профилей соответствия (R5): какие проверки на хосте выполнялись.
    compliance_facts: dict[str, dict] = field(default_factory=dict)


class Orchestrator:
    def __init__(self, gate: AllowlistGate, audit: AuditSink, *,
                 should_stop: Callable[[], bool] | None = None):
        self.gate = gate
        self.audit = audit
        self.should_stop = should_stop or (lambda: False)

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
                     cred_candidates: list[tuple[str, str]] | None = None) -> RunOutcome:
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
                          targets=list(plan.allowed), rate=rate, audit=self.audit,
                          credentials=list(credentials or []),
                          cred_candidates=list(cred_candidates or []))
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
            ctx.completed.add(module.name)
            self.audit.record(subject="scanner", action="module_finish",
                              target=module.name, result="ok",
                              details={"scan_run_id": scan_run_id,
                                       "findings": len(found)})
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
                 executor: Executor | None = None,
                 reference_store: object | None = None,
                 vault: CredentialVault | None = None):
        self.sessions = session_factory
        self.audit = audit
        # Ключ шифрования учётных записей; None — учётки недоступны.
        self.vault = vault if vault is not None else load_vault()
        # Без явного реестра строим стандартный и подключаем к vuln сопоставление
        # с CVE/БДУ ФСТЭК над справочниками из той же БД — иначе находки реального
        # прогона остались бы без привязки к БДУ (ключевая функция продукта).
        if registry is not None:
            self.registry = dict(registry)
        else:
            self.registry = dict(default_module_registry(
                matcher=self._build_matcher(reference_store)))
        self.executor = executor or ThreadPoolExecutor(max_workers=2,
                                                       thread_name_prefix="scan-run")

    def _build_matcher(self, reference_store: object | None):
        """VulnMatcher над справочниками БД; None, если БД/справочники недоступны."""
        store = reference_store
        if store is None:
            engine = getattr(self.sessions, "kw", {}).get("bind")
            if engine is None:
                return None
            try:
                from scanner.feeds.store import SqlReferenceStore
                store = SqlReferenceStore(engine)
            except Exception:
                log.exception("cannot build reference store; vuln findings won't be enriched")
                return None
        from scanner.feeds.matcher import VulnMatcher
        return VulnMatcher(store)

    # --- проверки до постановки --------------------------------------------
    def known_modules(self) -> list[str]:
        return order_modules(self.registry)

    def preview(self, engagement_id: int, requested_targets: list[str]) -> TargetPlan:
        """Что пропустит гейт прямо сейчас (для ответа API до постановки)."""
        with session_scope(self.sessions) as s:
            gate = repo.load_allowlist_gate(s, engagement_id)
        return plan_targets(gate, requested_targets)

    # --- жизненный цикл ----------------------------------------------------
    def check_credentials(self, engagement_id: int, modules: list[str],
                          credential_ids: list[int]) -> None:
        """Учётки прогона: нужны модулям из CREDENTIAL_MODULES, принадлежат договору.

        ValueError — понятная оператору причина отказа (API отдаёт её как 422).
        """
        needs = [m for m in modules if m in CREDENTIAL_MODULES]
        if not credential_ids:
            if needs:
                raise ValueError(f"модулю {needs[0]} нужна учётная запись: "
                                 "выберите хотя бы одну")
            return
        if not needs:
            raise ValueError("учётные записи используются только модулями "
                             f"{', '.join(sorted(CREDENTIAL_MODULES))}: выберите один из "
                             "них или уберите учётки")
        if self.vault is None:
            raise ValueError("не задан ключ шифрования учётных записей "
                             "(SCANNER_CREDENTIALS_KEY или SCANNER_API_SECRET)")
        with session_scope(self.sessions) as s:
            known = {r.id for r in repo.list_host_credentials(s, engagement_id)}
        missing = sorted(set(credential_ids) - known)
        if missing:
            raise ValueError(f"учётные записи не найдены в договоре: "
                             f"{', '.join(map(str, missing))}")

    def check_cred_sets(self, engagement_id: int, cred_set_ids: list[int]) -> None:
        """Наборы проверки учёток принадлежат договору. ValueError — иначе (422).

        Отсутствие набора НЕ ошибка: модуль cred_audit без набора лишь пишет
        осознанный пропуск (см. его инертность по умолчанию)."""
        if not cred_set_ids:
            return
        if self.vault is None:
            raise ValueError("не задан ключ шифрования учётных записей "
                             "(SCANNER_CREDENTIALS_KEY или SCANNER_API_SECRET)")
        with session_scope(self.sessions) as s:
            known = {r.id for r in repo.list_cred_audit_sets(s, engagement_id)}
        missing = sorted(set(cred_set_ids) - known)
        if missing:
            raise ValueError(f"наборы проверки учёток не найдены в договоре: "
                             f"{', '.join(map(str, missing))}")

    def submit(self, *, engagement_id: int, modules: list[str], rate_profile: str,
               requested_targets: list[str], actor: str,
               started_by: int | None = None,
               credential_ids: list[int] | None = None,
               cred_set_ids: list[int] | None = None,
               name: str | None = None, schedule_id: int | None = None) -> int:
        """Создаёт прогон (pending) и отдаёт его исполнителю. Права проверяет API.

        name — имя, заданное оператором; без него имя строится по модулям и целям.
        """
        unknown = [m for m in modules if m not in self.registry]
        if unknown:
            raise ValueError(f"unknown modules: {', '.join(unknown)}")
        if rate_profile not in PROFILES:
            raise ValueError(f"unknown rate profile: {rate_profile}")
        names = order_modules(with_companions(modules, self.registry))
        cred_ids = list(dict.fromkeys(credential_ids or []))
        set_ids = list(dict.fromkeys(cred_set_ids or []))
        self.check_credentials(engagement_id, names, cred_ids)
        self.check_cred_sets(engagement_id, set_ids)
        # имя — по выбору оператора, без автоматически добавленных спутников
        title = clean_name(name) or run_title(order_modules(modules), requested_targets)
        with session_scope(self.sessions) as s:
            run_id = repo.create_scan_run(s, engagement_id=engagement_id, modules=names,
                                          rate_profile=rate_profile,
                                          started_by=started_by, credential_ids=cred_ids,
                                          cred_set_ids=set_ids,
                                          name=title, targets=requested_targets[:1024],
                                          schedule_id=schedule_id)
        self.audit.record(subject=actor, action="scan_queue", target=f"scan_run:{run_id}",
                          result="ok",
                          details={"engagement_id": engagement_id, "name": title,
                                   "schedule_id": schedule_id, "modules": names,
                                   "rate_profile": rate_profile,
                                   "credential_ids": cred_ids,
                                   "cred_set_ids": set_ids,
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

    def _save_compliance(self, scan_run_id: int, out: RunOutcome) -> None:
        """Статусы мер профилей соответствия (R5) по итогам прогона. Ошибка
        расчёта не влияет на итог прогона: она в аудите, а результаты можно
        пересчитать позже (POST /runs/{id}/compliance/recompute)."""
        if not out.compliance_facts and not out.findings:
            return
        try:
            from scanner.compliance import store as compliance_store
            from scanner.compliance.catalog import default_catalog
            from scanner.compliance.engine import evaluate_run
            rows = evaluate_run(default_catalog(), out.compliance_facts, out.findings,
                                out.services)
            with session_scope(self.sessions) as s:
                n = compliance_store.save_run(s, scan_run_id, out.compliance_facts, rows)
            self.audit.record(subject="scanner", action="compliance_eval",
                              target=f"scan_run:{scan_run_id}", result="ok",
                              details={"rows": n, "hosts": len(out.compliance_facts)})
        except Exception as e:  # соответствие вторично к находкам
            log.exception("scan_run %s: compliance evaluation failed", scan_run_id)
            self.audit.record(subject="scanner", action="compliance_eval",
                              target=f"scan_run:{scan_run_id}", result="error",
                              details={"error": f"{type(e).__name__}: {e}"[:500]})

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
            # учётки расшифровываются только на время прогона, в памяти процесса
            cred_ids = list(run.credential_ids or [])
            set_ids = list(run.cred_set_ids or [])
            credentials = []
            cred_candidates: list[tuple[str, str]] = []
            if (cred_ids or set_ids) and self.vault is None:
                raise RuntimeError("не задан ключ шифрования учётных записей")
            if cred_ids:
                credentials = repo.load_host_credentials(s, self.vault, engagement_id,
                                                         cred_ids)
            if set_ids:
                cred_candidates = repo.load_cred_set_entries(s, self.vault,
                                                             engagement_id, set_ids)
            repo.set_scan_run_status(s, scan_run_id, "running")
        self.audit.record(subject="scanner", action="scan_start",
                          target=f"scan_run:{scan_run_id}", result="ok",
                          details={"engagement_id": engagement_id, "modules": names,
                                   "rate_profile": rate.name,
                                   "credentials": [c.describe() for c in credentials]
                                   or None,
                                   "cred_set_ids": set_ids or None,
                                   "cred_candidates": len(cred_candidates) or None})

        modules = [self.registry[n]() for n in names]
        orch = Orchestrator(gate, self.audit,
                            should_stop=lambda: self._status(scan_run_id) == "stopped")
        out = orch.run_detailed(engagement_id=engagement_id, scan_run_id=scan_run_id,
                                requested_targets=requested_targets, modules=modules,
                                rate=rate, credentials=credentials,
                                cred_candidates=cred_candidates)
        del credentials, cred_candidates    # секреты больше не нужны

        with session_scope(self.sessions) as s:
            if out.hosts:
                repo.save_hosts(s, scan_run_id=scan_run_id, hosts=out.hosts)
            if out.services:
                repo.save_services(s, scan_run_id=scan_run_id, services=out.services)
            if out.inventory:
                repo.save_inventory(s, scan_run_id=scan_run_id, inventories=out.inventory)
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
        self._save_compliance(scan_run_id, out)
        with session_scope(self.sessions) as s:
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
