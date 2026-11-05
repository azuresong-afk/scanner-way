"""Оркестратор прогона: allowlist-гейт -> модули -> находки.

Единственное место, где цели фильтруются через allowlist; модули получают уже
безопасный список. Каждый отказ и запуск пишется в аудит.

Два уровня:
  * `Orchestrator` — чистое ядро: гейт + последовательный запуск модулей над
    уже готовым AllowlistGate (без БД);
  * `RunService` — прогон, сохранённый в БД (`scan_runs`): читает allowlist
    договора из БД в момент запуска, исполняет `Orchestrator`, сохраняет
    инвентарь и находки (со статусами относительно предыдущего прогона) и ведёт
    статус pending -> running -> done | failed | stopped | interrupted.

Восстановление после сбоя: процесс, который ведёт прогоны (pending в своей
очереди и running), раз в `heartbeat_seconds` обновляет у них `heartbeat_at`.
Сторож (`RunService.start()` — в API) при старте и затем периодически ищет
осиротевшие прогоны: их процесс умер (тот же хост, pid не существует или это
прошлый запуск контейнера) или отметка не обновлялась дольше `stale_seconds`.
Осиротевший running становится `interrupted` с понятной причиной (повторить —
`RunService.retry`), осиротевший pending ставится в очередь заново: сеть он
ещё не трогал. Результаты прогона пишутся одной транзакцией вместе с очисткой
прежних строк этого прогона, поэтому повторное исполнение не плодит дублей.

Остановка кооперативная: статус `stopped` выставляется в БД сразу, а
исполняющийся прогон проверяет его между модулями (модуль, уже начавший работу,
доводится до конца — прервать nmap посреди пачки нельзя без риска потерять
аудит его действий).
"""
from __future__ import annotations

import ipaddress
import logging
import os
import socket
import threading
import uuid
from collections.abc import Callable, Iterable, Mapping
from concurrent.futures import Executor, ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

from sqlalchemy import func, select, update
from sqlalchemy.orm import Session, sessionmaker

from scanner.core import assets
from scanner.core import coverage as cv
from scanner.core import repository as repo
from scanner.core import run_events as ev
from scanner.core.allowlist import AllowlistGate
from scanner.core.audit import AuditSink
from scanner.core.credentials import CredentialVault, HostCredential, load_vault
from scanner.core.db import FindingRow, ScanRun, session_scope
from scanner.core.models import Finding, HostInventory, HostOs, ServiceInfo
from scanner.core.naming import clean_name, run_title
from scanner.core.ratelimit import PROFILES, RateProfile, get_profile
from scanner.core.targetspec import is_range, parse_target, range_hosts
from scanner.modules.base import ScanContext, ScanModule
from scanner.reporting.diff import diff_runs

# Порядок исполнения: discovery первым — его сервисы (ctx.services) нужны
# остальным модулям.
MODULE_ORDER: tuple[str, ...] = ("discovery", "vuln", "auth_inventory", "win_inventory",
                                 "netdev_audit", "config_audit", "password_policy",
                                 "cred_audit")

# Движки поиска уязвимостей (выбор оператора): сетевые проверки Nuclei без
# учётной записи и/или инвентаризация по учётной записи — пакеты Linux
# (auth_inventory), обновления/ПО Windows по WinRM (win_inventory) и сетевое
# оборудование по SSH-CLI/SNMP (netdev_audit). Каждый модуль инертен там, где у
# него нет подходящей учётки, поэтому в смешанной сети «По учётной записи»
# покрывает и Linux, и Windows, и коммутаторы/маршрутизаторы.
VULN_ENGINES: dict[str, tuple[str, ...]] = {
    "nuclei": ("vuln",),
    "credentialed": ("auth_inventory", "win_inventory", "netdev_audit"),
    "both": ("vuln", "auth_inventory", "win_inventory", "netdev_audit"),
}
# Модули, которые входят на хосты по учётным записям договора (ctx.credentials).
CREDENTIAL_MODULES = frozenset({"auth_inventory", "win_inventory", "netdev_audit",
                                "config_audit"})
# Модули-спутники: ставятся в прогон вместе с основным. password_policy оценивает
# парольную политику, которую собирает config_audit (ctx.host_policy_configs);
# сам по себе в сеть не ходит и без config_audit инертен.
# auth_inventory едет с config_audit всегда: раз оператор дал SSH-учётку, пакеты
# хоста сверяются с бюллетенями вендора (CVE → БДУ ФСТЭК) по той же учётке.
# Иначе при движке «Nuclei» + аудит конфигураций уязвимости ПО на хосте
# оставались непроверенными и единственным сигналом о пакетах был Lynis
# (PKGS-7392, без CVE/БДУ). Lynis/OpenSCAP — источник аудита конфигураций,
# не уязвимостей.
COMPANION_MODULES: dict[str, tuple[str, ...]] = {
    "config_audit": ("auth_inventory", "password_policy")}

# Защита от опечатки вида 10.0.0.0/8 в запросе: столько адресов за прогон
# с запасом покрывает «десятки–сотни хостов».
MAX_TARGETS_PER_RUN = 4096

ModuleFactory = Callable[[], ScanModule]

# Какие прогоны можно повторить кнопкой «Повторить».
RETRYABLE = frozenset({"failed", "interrupted", "stopped", "partial"})

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
                                   matcher=matcher, advisories=_advisory_store(matcher),
                                   fetch_advisories=_advisory_fetcher(matcher))

    def win_inventory() -> ScanModule:
        from scanner.core.winexec import options_from_env
        from scanner.modules.win_inventory import (
            WinInventoryModule,
            WinInventoryOptions,
        )
        return WinInventoryModule(WinInventoryOptions(winrm=options_from_env()),
                                  matcher=matcher)

    def netdev_audit() -> ScanModule:
        from scanner.modules.netdev_audit import NetdevAuditModule, options_from_env
        return NetdevAuditModule(options_from_env(), matcher=matcher)

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
            "win_inventory": win_inventory, "netdev_audit": netdev_audit,
            "config_audit": config_audit,
            "password_policy": password_policy, "cred_audit": cred_audit}


def _advisory_store(matcher: object | None):
    """Бюллетени дистрибутивов (R2) из той же БД, что и справочники matcher."""
    engine = getattr(getattr(matcher, "store", None), "engine", None)
    if engine is None:
        return None
    from scanner.feeds.advisories.store import SqlAdvisoryStore
    return SqlAdvisoryStore(engine)


def _advisory_fetcher(matcher: object | None):
    """Подгрузка бюллетеней выпусков ОС, встреченных в прогоне (см.
    feeds.advisories.ondemand). None — выключено (ADVISORY_ON_DEMAND=0) или нет БД."""
    from scanner.core.config import settings
    mode = (settings.advisory_on_demand or "auto").strip().lower()
    engine = getattr(getattr(matcher, "store", None), "engine", None)
    if engine is None or mode in ("0", "false", "no", "off"):
        return None
    from pathlib import Path

    from scanner.feeds.advisories.ondemand import AdvisoryFetcher
    from scanner.feeds.advisories.store import SqlAdvisoryStore

    def allow_network() -> bool:
        if mode in ("1", "true", "yes", "on"):
            return True
        # auto: согласие оператора = включённое автообновление бюллетеней
        from sqlalchemy import select

        from scanner.core.db import FeedSync
        with Session(engine) as s:
            return bool(s.scalar(select(FeedSync.enabled)
                                 .where(FeedSync.source == "advisories")))

    directory = Path(settings.advisory_dir) if settings.advisory_dir else None
    return AdvisoryFetcher(SqlAdvisoryStore(engine), directory=directory,
                           urls=settings.advisory_urls(), allow_network=allow_network)


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

    IP — как есть; диапазон «начало-конец» — во все его адреса;
    подсеть (CIDR) — в адреса хостов, каждый проверяется
    отдельно (подсеть, частично выходящая за allowlist, урезается до
    разрешённой части). Имена хостов отклоняются: резолв DNS — сетевое
    действие, а гейт работает только с литеральными адресами.
    """
    plan = TargetPlan()
    seen: set[str] = set()
    for raw in requested:
        spec = raw.strip()
        if is_range(spec):
            try:
                rng = parse_target(spec)
            except ValueError:
                plan.denied.append(DeniedTarget(spec, "not_an_ip"))
                continue
            if rng.num_addresses > max_targets:
                plan.denied.append(DeniedTarget(spec, "too_many_targets",
                                                rng.num_addresses))
                continue
            hosts = range_hosts(rng)
        else:
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


# ========== Прогресс прогона ==========
STAGE_SAVING = "saving"      # после модулей: запись результатов, сравнение, нормативы
PROGRESS_MIN_INTERVAL = 2.0  # секунд между записями прогресса в БД
ETA_MIN_PERCENT = 5          # оценка «по общей скорости» — не раньше этого процента


def stage_history(progress_rows: Iterable[Mapping | None]) -> dict[str, float]:
    """Секунд на хост по этапам из снимков прогресса прошлых прогонов (новые
    первыми): для каждого модуля берётся самый свежий замер."""
    out: dict[str, float] = {}
    for p in progress_rows:
        if not p:
            continue
        n = p.get("hosts_total") or 0
        secs = p.get("stage_seconds") or {}
        if n <= 0 or not isinstance(secs, Mapping):
            continue
        for m, v in secs.items():
            if m not in out and isinstance(v, (int, float)) and v > 0:
                out[m] = float(v) / n
    return out


class RunProgress:
    """Ход прогона для интерфейса: текущий этап (модуль), сколько хостов он
    уже отработал из всех хостов прогона, и общий процент.

    Хост этапа считается готовым, когда модуль отметил его в покрытии
    (completed / unreachable / timeout / …). Процент — доля пар
    «этап × хост»: (этапов позади × хостов + готово на этапе) / (этапов ×
    хостов), до конца прогона не больше 99. Снимки уходят в ``sink`` не чаще
    ``min_interval`` секунд; смена этапа и его конец отправляются сразу.
    Ошибка ``sink`` поглощается — прогресс не влияет на итог прогона."""

    def __init__(self, sink: Callable[[dict], None], stages: list[str], hosts: int, *,
                 min_interval: float = PROGRESS_MIN_INTERVAL,
                 clock: Callable[[], float] | None = None,
                 history: Mapping[str, float] | None = None):
        import time
        self.sink = sink
        # Секунд на хост по этапам из прошлых прогонов проекта (stage_history).
        self.history = {m: float(v) for m, v in (history or {}).items() if v and v > 0}
        self.stages = list(stages)
        self.hosts = max(int(hosts), 0)
        self.min_interval = min_interval
        self.clock = clock or time.monotonic
        self._lock = threading.Lock()
        self._index = 0           # 0 — ещё не начат ни один этап
        self._stage: str | None = None
        self._done: set[str] = set()
        self._last = float("-inf")
        self._t0 = self.clock()
        self._stage_t0 = self._t0
        self._stage_secs: dict[str, float] = {}   # длительность завершённых этапов

    def snapshot(self) -> dict:
        k = max(len(self.stages), 1)
        n = self.hosts
        if self._stage == STAGE_SAVING:
            percent, done = 99, n
        elif n == 0:
            percent, done = int(100 * max(self._index - 1, 0) / k), 0
        else:
            done = min(len(self._done), n)
            percent = int(100 * ((max(self._index - 1, 0)) * n + done) / (k * n))
        now = self.clock()
        eta = self._eta(now, done)
        if eta is None and self._stage != STAGE_SAVING and percent >= ETA_MIN_PERCENT:
            # нет ни истории, ни замеров по этапам — по общей скорости прогона
            eta = (now - self._t0) * (100 - percent) / percent
        return {"stage": self._stage, "stage_index": min(self._index, len(self.stages)),
                "stages": len(self.stages), "hosts_done": done, "hosts_total": n,
                "percent": min(percent, 99),
                "elapsed_seconds": int(now - self._t0),
                "eta_seconds": None if eta is None else round(eta),
                "stage_seconds": {m: round(v, 1) for m, v in self._stage_secs.items()},
                "updated_at": datetime.now(UTC).isoformat(timespec="seconds")}

    def _eta(self, now: float, done: int) -> float | None:
        """Сколько примерно осталось, с.

        Текущий этап — по его собственной скорости (сек на готовый хост), пока
        готовых хостов мало — вперемешку с прошлыми прогонами; будущие этапы —
        по прошлым прогонам проекта (сек на хост × хостов), а без истории — по
        средней скорости уже пройденных этапов этого прогона. Ничего нет —
        None (тогда снимок берёт общую скорость прогона)."""
        n = self.hosts
        if self._stage is None or self._stage == STAGE_SAVING or n == 0:
            return None
        observed = [v / n for v in self._stage_secs.values()]
        avg = sum(observed) / len(observed) if observed else None
        el = max(now - self._stage_t0, 0.0)
        left = n - done
        hist = self.history.get(self._stage)
        prior = hist if hist is not None else avg
        if done > 0 and el > 0:
            live = el / done * left
            enough = max(2.0, n * 0.2)
            if prior is not None and done < enough:
                w = done / enough
                cur = w * live + (1 - w) * max(prior * n - el, 0.0)
            else:
                cur = live
        elif prior is not None:
            cur = max(prior * n - el, 0.0)
        else:
            return None
        total = cur
        for m in self.stages[self._index:]:
            per_host = self.history.get(m, avg)
            if per_host is None:
                return None
            total += per_host * n
        return total

    def _emit(self, force: bool) -> None:
        now = self.clock()
        if not force and now - self._last < self.min_interval:
            return
        self._last = now
        try:
            self.sink(self.snapshot())
        except Exception:
            log.exception("scan run progress update failed")

    def begin(self, module: str) -> None:
        with self._lock:
            self._index += 1
            self._stage = module
            self._stage_t0 = self.clock()
            self._done = set()
            self._emit(True)

    def mark(self, host: str, module: str) -> None:
        with self._lock:
            if module != self._stage or host in self._done:
                return
            self._done.add(host)
            self._emit(False)

    def end_stage(self, hosts: Iterable[str]) -> None:
        """Этап закончился: все хосты прогона для него отработаны."""
        with self._lock:
            self._done = set(hosts)
            if self._stage and self._stage != STAGE_SAVING:
                self._stage_secs[self._stage] = self.clock() - self._stage_t0
            self._emit(True)

    def saving(self) -> None:
        with self._lock:
            self._stage = STAGE_SAVING
            self._index = len(self.stages)
            self._emit(True)


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


# Отметка «жив» и порог, после которого прогон без неё считается осиротевшим.
HEARTBEAT_SECONDS = 30
STALE_SECONDS = 180

MSG_INTERRUPTED = ("Прогон прерван: служба сканера была остановлена или "
                   "перезапущена во время выполнения. Результаты прогона не "
                   "сохранены — запустите его повторно (кнопка «Повторить»).")
MSG_INTERRUPTED_SAVED = ("Прогон прерван после сохранения находок: служба сканера "
                         "остановилась до его штатного завершения (расчёт "
                         "соответствия мог не выполниться). Находки доступны; "
                         "для полного результата повторите прогон.")
MSG_NO_TARGETS = ("Ни одна цель не прошла allowlist договора на момент запуска "
                  "(allowlist мог измениться после постановки прогона).")


def make_worker_id() -> str:
    """Кто ведёт прогон: хост, pid и метка запуска процесса."""
    return f"{socket.gethostname()}:{os.getpid()}:{uuid.uuid4().hex[:12]}"


def _aware(ts: datetime | None) -> datetime | None:
    if ts is None:
        return None
    return ts if ts.tzinfo is not None else ts.replace(tzinfo=UTC)


def owner_is_dead(worker_id: str | None, me: str) -> bool:
    """Процесс worker_id точно не существует (проверяемо только на своём хосте).

    В контейнере API после перезапуска снова pid 1, поэтому кроме pid
    сравнивается метка запуска: тот же pid с другой меткой — прошлый процесс.
    Прогоны с другого хоста (или без worker_id) оцениваются только по
    давности отметки «жив»."""
    if not worker_id:
        return False
    try:
        host, pid_s, boot = worker_id.rsplit(":", 2)
        pid = int(pid_s)
    except ValueError:
        return False
    my_host, my_pid, my_boot = me.rsplit(":", 2)
    if host != my_host:
        return False
    if pid == int(my_pid):
        return boot != my_boot
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return True
    except OSError:          # процесс есть, но чужой (EPERM)
        return False
    return False


def seen_hosts(out: RunOutcome) -> list[str]:
    """Хосты, которые прогон действительно обнаружил: хоть один модуль на них
    отработал (покрытие completed), найден открытый порт или выполнена
    инвентаризация. Адрес, который nmap с -Pn «видит» без единого открытого
    порта, и недоступные цели активами не становятся."""
    found = {e.host for e in out.coverage.entries() if e.status == cv.COMPLETED}
    found |= {s.host for s in out.services}
    found |= {i.host for i in out.inventory}
    return sorted(found)


# Опции прогона, которые понимает сканер (остальное отбрасывается).
RUN_OPTION_KEYS = {"no_ping": bool, "profile": str}


def clean_run_options(options: Mapping[str, object] | None) -> dict:
    out: dict = {}
    for k, typ in RUN_OPTION_KEYS.items():
        v = (options or {}).get(k)
        if v in (None, "", False):
            continue
        out[k] = bool(v) if typ is bool else str(v)[:64]
    return out


def error_summary(errors: Mapping[str, str]) -> str:
    """Ошибки модулей — одной строкой для пользователя."""
    parts = [f"модуль {m}: {e}" for m, e in errors.items()]
    return "Прогон завершён с ошибками — " + "; ".join(parts)


class RunService:
    """Постановка, исполнение и остановка прогонов, сохранённых в БД."""

    def __init__(self, session_factory: sessionmaker[Session], audit: AuditSink, *,
                 registry: Mapping[str, ModuleFactory] | None = None,
                 executor: Executor | None = None,
                 reference_store: object | None = None,
                 vault: CredentialVault | None = None,
                 notifier: Callable[[int], None] | None = None,
                 heartbeat_seconds: float = HEARTBEAT_SECONDS,
                 stale_seconds: float = STALE_SECONDS):
        self.sessions = session_factory
        # Восстановление после сбоя: этот процесс и прогоны, которые он ведёт.
        self.worker_id = make_worker_id()
        self.heartbeat_seconds = heartbeat_seconds
        self.stale_seconds = stale_seconds
        self._owned: set[int] = set()
        self._lock = threading.Lock()
        self._hb_thread: threading.Thread | None = None
        self._hb_stop = threading.Event()
        self._sweep = False      # сторож осиротевших прогонов — только после start()
        # Уведомления о завершении прогона (R9): вызывается с id прогона, ошибки
        # поглощаются — сбой канала не должен менять итог прогона.
        self.notifier = notifier
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
               name: str | None = None, schedule_id: int | None = None,
               retry_of: int | None = None,
               options: Mapping[str, object] | None = None) -> int:
        """Создаёт прогон (pending) и отдаёт его исполнителю. Права проверяет API.

        name — имя, заданное оператором; без него имя строится по модулям и целям.
        """
        unknown = [m for m in modules if m not in self.registry]
        if unknown:
            raise ValueError(f"unknown modules: {', '.join(unknown)}")
        if rate_profile not in PROFILES:
            raise ValueError(f"unknown rate profile: {rate_profile}")
        names = order_modules(with_companions(modules, self.registry))
        opts = clean_run_options(options)
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
                                          schedule_id=schedule_id, retry_of=retry_of,
                                          worker_id=self.worker_id, options=opts)
        self.audit.record(subject=actor, action="scan_queue", target=f"scan_run:{run_id}",
                          result="ok",
                          details={"engagement_id": engagement_id, "name": title,
                                   "schedule_id": schedule_id, "modules": names,
                                   "rate_profile": rate_profile,
                                   "credential_ids": cred_ids,
                                   "cred_set_ids": set_ids,
                                   "retry_of": retry_of, "options": opts or None,
                                   "requested_targets": requested_targets[:100]})
        self._enqueue(run_id, list(requested_targets))
        return run_id

    def retry(self, scan_run_id: int, *, actor: str, started_by: int | None = None) -> int:
        """Новый прогон с параметрами завершившегося (ошибка, прерван,
        остановлен). Allowlist и учётки проверяются заново при исполнении.
        ValueError — прогон ещё идёт или успешно завершён (API отдаёт 409)."""
        with session_scope(self.sessions) as s:
            run = repo.get_scan_run(s, scan_run_id)
            if run is None:
                raise LookupError(f"scan_run {scan_run_id} not found")
            if run.status not in RETRYABLE:
                raise ValueError(f"повторить можно только прогон с ошибкой, частичный, "
                                 f"прерванный или остановленный (сейчас: {run.status})")
            params = {"engagement_id": run.engagement_id, "modules": list(run.modules),
                      "rate_profile": run.rate_profile,
                      "requested_targets": list(run.targets or []),
                      "credential_ids": list(run.credential_ids or []),
                      "cred_set_ids": list(run.cred_set_ids or []),
                      "name": run.name, "schedule_id": run.schedule_id,
                      "options": dict(run.options or {})}
        if not params["requested_targets"]:
            raise ValueError("у прогона не сохранены цели — запустите новый прогон")
        return self.submit(**params, actor=actor, started_by=started_by,
                           retry_of=scan_run_id)

    # --- отметка «жив» и сторож осиротевших прогонов -----------------------
    def _enqueue(self, run_id: int, targets: list[str]) -> None:
        with self._lock:
            self._owned.add(run_id)
        self._ensure_heartbeat()
        self.executor.submit(self._run_owned, run_id, targets)

    def _run_owned(self, run_id: int, targets: list[str]) -> str:
        try:
            return self.execute(run_id, targets)
        finally:
            with self._lock:
                self._owned.discard(run_id)

    def _ensure_heartbeat(self) -> None:
        if self.heartbeat_seconds <= 0:
            return
        with self._lock:
            if self._hb_thread is not None and self._hb_thread.is_alive():
                return
            self._hb_stop.clear()
            self._hb_thread = threading.Thread(target=self._heartbeat_loop,
                                               name="scan-run-heartbeat", daemon=True)
            self._hb_thread.start()

    def _heartbeat_loop(self) -> None:
        while not self._hb_stop.wait(self.heartbeat_seconds):
            self.heartbeat()
            if self._sweep:
                try:
                    self.recover_orphans()
                except Exception:   # БД недоступна — попробуем на следующем тике
                    log.exception("orphaned scan runs check failed")

    def heartbeat(self) -> None:
        """Обновить отметку «жив» у прогонов этого процесса."""
        with self._lock:
            owned = list(self._owned)
        if not owned:
            return
        try:
            with session_scope(self.sessions) as s:
                repo.touch_scan_runs(s, owned, self.worker_id)
        except Exception:
            log.exception("scan run heartbeat failed")

    def start(self) -> None:
        """Старт в API: разобрать прогоны, оставшиеся от прошлого процесса, и
        включить периодический сторож (вместе с отметкой «жив»)."""
        try:
            self.recover_orphans()
        except Exception:
            log.exception("orphaned scan runs check failed at startup")
        self._sweep = True
        self._ensure_heartbeat()

    def stop(self) -> None:
        self._sweep = False
        self._hb_stop.set()

    def recover_orphans(self, now: datetime | None = None) -> dict[str, list[int]]:
        """Осиротевшие running -> interrupted, осиротевшие pending -> в очередь.

        Каждое изменение — условным UPDATE по наблюдённым статусу и отметке:
        если владелец «ожил» и успел обновить прогон, сторож его не тронет."""
        now = now or datetime.now(UTC)
        stale_before = now - timedelta(seconds=self.stale_seconds)
        interrupted: list[int] = []
        requeued: list[tuple[int, list[str]]] = []
        with self._lock:
            owned = set(self._owned)
        with session_scope(self.sessions) as s:
            for run in repo.active_scan_runs(s):
                if run.id in owned:
                    continue
                seen = _aware(run.heartbeat_at or run.started_at or run.created_at)
                dead = owner_is_dead(run.worker_id, self.worker_id)
                if not dead and seen is not None and seen >= stale_before:
                    continue
                cond = [ScanRun.id == run.id, ScanRun.status == run.status,
                        ScanRun.heartbeat_at.is_(None) if run.heartbeat_at is None
                        else ScanRun.heartbeat_at == run.heartbeat_at]
                if run.status == "running":
                    saved = s.scalar(select(func.count(FindingRow.id)).where(
                        FindingRow.scan_run_id == run.id)) or 0
                    res = s.execute(update(ScanRun).where(*cond).values(
                        status="interrupted", finished_at=now,
                        error_message=MSG_INTERRUPTED_SAVED if saved else MSG_INTERRUPTED)
                        .execution_options(synchronize_session=False))
                    if res.rowcount == 1:
                        interrupted.append(run.id)
                else:
                    res = s.execute(update(ScanRun).where(*cond).values(
                        worker_id=self.worker_id, heartbeat_at=now)
                        .execution_options(synchronize_session=False))
                    if res.rowcount == 1:
                        requeued.append((run.id, list(run.targets or [])))
        for run_id in interrupted:
            self.audit.record(subject="scanner", action="scan_finish",
                              target=f"scan_run:{run_id}", result="interrupted",
                              details={"reason": "executor_lost",
                                       "worker_id": self.worker_id})
            ev.safe_add(self.sessions, run_id, [ev.run_finish(
                "interrupted", message="исполнитель прогона перезапущен")])
            self._notify(run_id)
        for run_id, targets in requeued:
            self.audit.record(subject="scanner", action="scan_requeue",
                              target=f"scan_run:{run_id}", result="ok",
                              details={"reason": "executor_lost"})
            self._enqueue(run_id, targets)
        return {"interrupted": interrupted, "requeued": [r for r, _ in requeued]}

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
        if before in {"pending", "running"}:
            ev.safe_add(self.sessions, scan_run_id, [ev.Event(
                "run_stop", ev.SUBJECT_RUN, f"остановка по запросу: {actor}")])
        return status

    def _save_progress(self, scan_run_id: int, snap: dict) -> None:
        with session_scope(self.sessions) as s:
            repo.set_scan_run_progress(s, scan_run_id, snap)

    def _status(self, scan_run_id: int) -> str | None:
        with session_scope(self.sessions) as s:
            run = repo.get_scan_run(s, scan_run_id)
            return None if run is None else run.status

    def _notify(self, scan_run_id: int) -> None:
        if self.notifier is None:
            return
        try:
            self.notifier(scan_run_id)
        except Exception:  # уведомления вторичны
            log.exception("scan_run %s: notification failed", scan_run_id)

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
                        repo.set_scan_run_status(
                            s, scan_run_id, "failed",
                            error_message=f"Внутренняя ошибка сканера: {e}"[:500])
            except Exception:  # БД недоступна; след уже в аудите
                log.exception("scan_run %s: cannot mark as failed", scan_run_id)
            ev.safe_add(self.sessions, scan_run_id, [ev.run_finish(
                "failed", message=f"внутренняя ошибка сканера: {type(e).__name__}")])
            self._notify(scan_run_id)
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
            if run.status != "pending":      # остановлен до старта / уже исполняется
                return run.status
            engagement_id = run.engagement_id
            names = list(run.modules)
            run_options = dict(run.options or {})
            # скорость этапов в прошлых прогонах проекта — для «осталось ≈ …»
            history = stage_history(repo.recent_run_progress(
                s, engagement_id=run.engagement_id, before_id=scan_run_id,
                rate_profile=run.rate_profile))
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
            # pending -> running атомарно: прогон, поставленный в очередь повторно,
            # не исполнится дважды.
            if not repo.claim_scan_run(s, scan_run_id, self.worker_id):
                s.expire_all()
                run = repo.get_scan_run(s, scan_run_id)
                return run.status
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
                            should_stop=lambda: self._status(scan_run_id) == "stopped",
                            events=ev.recorder(self.sessions, scan_run_id))
        out = orch.run_detailed(engagement_id=engagement_id, scan_run_id=scan_run_id,
                                requested_targets=requested_targets, modules=modules,
                                rate=rate, credentials=credentials,
                                cred_candidates=cred_candidates, options=run_options,
                                progress=lambda snap: self._save_progress(scan_run_id, snap),
                                progress_history=history)
        del credentials, cred_candidates    # секреты больше не нужны

        with session_scope(self.sessions) as s:
            # в той же транзакции — результаты прошлой попытки этого прогона
            repo.clear_scan_run_results(s, scan_run_id)
            if out.hosts:
                repo.save_hosts(s, scan_run_id=scan_run_id, hosts=out.hosts)
            if out.services:
                repo.save_services(s, scan_run_id=scan_run_id, services=out.services)
            if out.inventory:
                repo.save_inventory(s, scan_run_id=scan_run_id, inventories=out.inventory)
            repo.save_coverage(s, scan_run_id, out.coverage)
            repo.set_run_warnings(s, scan_run_id, out.warnings)
            # «Активы» независимо от прогонов: каждый обнаруженный хост остаётся
            # в реестре договора, даже без учётки для глубокой проверки
            assets.record_seen(s, engagement_id, seen_hosts(out),
                               source=assets.SOURCE_DISCOVERY,
                               hostnames={i.host: i.hostname for i in out.inventory
                                          if i.hostname})
            prev_id = repo.previous_scan_run_id(s, scan_run_id, coverage=out.coverage)
            statuses = {}
            fixed: list[Finding] = []
            if prev_id is not None:
                d = diff_runs(repo.get_findings(s, prev_id), out.findings,
                              repo.historically_fixed_keys(s, engagement_id, scan_run_id),
                              previous_coverage=repo.run_coverage(s, prev_id),
                              current_coverage=out.coverage)
                statuses = {f.dedup_key(): st for st, items in
                            (("open", d.open), ("new", d.new),
                             ("regression", d.regression)) for f in items}
                fixed = list(d.fixed)
            repo.save_findings(s, engagement_id=engagement_id, scan_run_id=scan_run_id,
                               findings=out.findings, statuses=statuses)
            fp_keys = set(repo.false_positive_marks(s, engagement_id))
            names = assets.hostnames(s, engagement_id)
        names.update({i.host: i.hostname for i in out.inventory if i.hostname})
        ev.safe_add(self.sessions, scan_run_id, ev.host_events(
            out.findings, statuses, fixed,
            [(g.host, g.module, cv.STATUS_LABELS.get(g.status, g.status))
             for g in out.coverage.gaps()],
            false_positive_keys=fp_keys, hostnames=names))
        self._save_compliance(scan_run_id, out)
        with session_scope(self.sessions) as s:
            run = repo.get_scan_run(s, scan_run_id)
            s.refresh(run)
            message = None
            if out.stopped or run.status == "stopped":
                final = "stopped"
            elif not out.allowed:
                final, message = "failed", MSG_NO_TARGETS
            else:
                # итог по покрытию: недоступный хост, таймаут SSH, нет учётки —
                # не «успешно»; ошибки модулей входят в покрытие как error
                final, message = cv.run_verdict(out.coverage, out.allowed)
                if out.errors:
                    message = error_summary(out.errors) + (f". {message}" if message
                                                           else "")
            if run.status != final or message:
                repo.set_scan_run_status(s, scan_run_id, final, error_message=message)
        live = [f for f in out.findings
                if str(f.severity) != "info" and f.dedup_key() not in fp_keys]
        ev.safe_add(self.sessions, scan_run_id, [ev.run_finish(
            final, open_issues=len(live),
            new=sum(1 for f in live if statuses.get(f.dedup_key()) == "new"),
            fixed=sum(1 for f in fixed if f.dedup_key() not in fp_keys),
            message=message)])
        self.audit.record(subject="scanner", action="scan_finish",
                          target=f"scan_run:{scan_run_id}", result=final,
                          details={"targets": len(out.allowed),
                                   "denied": len(out.denied),
                                   "findings": len(out.findings),
                                   "coverage_gaps": len(out.coverage.gaps()),
                                   "errors": out.errors or None})
        self._notify(scan_run_id)
        return final
