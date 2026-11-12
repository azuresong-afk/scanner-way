"""Прогон, сохранённый в БД (`scan_runs`): постановка, исполнение, остановка.

Читает allowlist договора из БД в момент запуска, исполняет `Orchestrator`
(runner.engine), сохраняет результат (runner.persist) и ведёт статус
pending -> running -> done | partial | failed | stopped | interrupted.
Очередь своего процесса, отметка «жив» и сторож осиротевших прогонов —
runner.recovery; прогоны на узлах-сканерах — runner.nodes.

Остановка кооперативная: статус `stopped` выставляется в БД сразу, а
исполняющийся прогон проверяет его между модулями (модуль, уже начавший работу,
доводится до конца — прервать nmap посреди пачки нельзя без риска потерять
аудит его действий).
"""
from __future__ import annotations

import logging
import threading
from collections.abc import Callable, Mapping
from concurrent.futures import Executor, ThreadPoolExecutor
from dataclasses import dataclass

from sqlalchemy.orm import Session, sessionmaker

from scanner.core import repository as repo
from scanner.core import run_events as ev
from scanner.core.allowlist import AllowlistGate
from scanner.core.audit import AuditSink
from scanner.core.credentials import CredentialVault, HostCredential, load_vault
from scanner.core.db import session_scope
from scanner.core.naming import clean_name, run_title
from scanner.core.ratelimit import PROFILES, RateProfile, get_profile
from scanner.core.runner.engine import Orchestrator
from scanner.core.runner.nodes import NodeRunsMixin
from scanner.core.runner.persist import PersistMixin
from scanner.core.runner.progress import stage_history
from scanner.core.runner.recovery import (
    HEARTBEAT_SECONDS,
    STALE_SECONDS,
    RecoveryMixin,
    make_worker_id,
)
from scanner.core.runner.registry import (
    CREDENTIAL_MODULES,
    ModuleFactory,
    default_module_registry,
    order_modules,
    with_companions,
)
from scanner.core.runner.targets import TargetPlan, plan_targets

# Какие прогоны можно повторить кнопкой «Повторить»: любой завершённый,
# в том числе успешный (повторная проверка тех же целей после устранения).
RETRYABLE = frozenset({"done", "failed", "interrupted", "stopped", "partial"})

# Имя логгера — прежнее (до разделения модуля): настройки логирования и
# фильтры по нему продолжают работать.
log = logging.getLogger("scanner.core.orchestrator")


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


@dataclass(slots=True)
class _Prepared:
    """Параметры захваченного прогона (RunService._prepare)."""
    engagement_id: int
    names: list[str]
    options: dict
    history: dict[str, float]
    rate: RateProfile
    gate: AllowlistGate
    credentials: list[HostCredential]
    cred_candidates: list[tuple[str, str]]
    set_ids: list[int]
    targets: list[str]
    name: str | None = None




class RunService(RecoveryMixin, NodeRunsMixin, PersistMixin):
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
            except Exception as e:
                log.exception("cannot build reference store; vuln findings won't be enriched")
                # не None: модули отметят хосты пробелом покрытия, а не «чисто»
                from scanner.feeds.store import UnavailableReferenceStore
                store = UnavailableReferenceStore(f"{type(e).__name__}: {e}"[:200])
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
               options: Mapping[str, object] | None = None,
               node_id: int | None = None) -> int:
        """Создаёт прогон (pending) и отдаёт его исполнителю. Права проверяет API.

        name — имя, заданное оператором; без него имя строится по модулям и целям.
        node_id — исполнить на узле-сканере (scanner.nodes): прогон остаётся
        pending, пока узел его не заберёт; локальная очередь его не берёт.
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
        node_name = self.check_node(node_id, credential_ids=cred_ids, cred_set_ids=set_ids)
        # имя — по выбору оператора, без автоматически добавленных спутников
        title = clean_name(name) or run_title(order_modules(modules), requested_targets)
        with session_scope(self.sessions) as s:
            run_id = repo.create_scan_run(s, engagement_id=engagement_id, modules=names,
                                          rate_profile=rate_profile,
                                          started_by=started_by, credential_ids=cred_ids,
                                          cred_set_ids=set_ids,
                                          name=title, targets=requested_targets[:1024],
                                          schedule_id=schedule_id, retry_of=retry_of,
                                          worker_id=None if node_id else self.worker_id,
                                          options=opts, node_id=node_id)
        self.audit.record(subject=actor, action="scan_queue", target=f"scan_run:{run_id}",
                          result="ok",
                          details={"engagement_id": engagement_id, "name": title,
                                   "schedule_id": schedule_id, "modules": names,
                                   "rate_profile": rate_profile,
                                   "credential_ids": cred_ids,
                                   "cred_set_ids": set_ids,
                                   "retry_of": retry_of, "options": opts or None,
                                   "node_id": node_id, "node": node_name,
                                   "requested_targets": requested_targets[:100]})
        if node_id is None:
            self._enqueue(run_id, list(requested_targets))
        else:
            ev.safe_add(self.sessions, run_id, [ev.Event(
                "run_queued", ev.SUBJECT_RUN, f"ожидает узел «{node_name}»")])
        return run_id


    def retry(self, scan_run_id: int, *, actor: str, started_by: int | None = None) -> int:
        """Новый прогон с параметрами завершившегося (успешно, с ошибкой,
        частично, прерван, остановлен). Allowlist и учётки проверяются заново
        при исполнении. ValueError — прогон ещё идёт (API отдаёт 409)."""
        with session_scope(self.sessions) as s:
            run = repo.get_scan_run(s, scan_run_id)
            if run is None:
                raise LookupError(f"scan_run {scan_run_id} not found")
            if run.status not in RETRYABLE:
                raise ValueError(f"повторить можно только завершённый прогон "
                                 f"(сейчас: {run.status})")
            params = {"engagement_id": run.engagement_id, "modules": list(run.modules),
                      "rate_profile": run.rate_profile,
                      "requested_targets": list(run.targets or []),
                      "credential_ids": list(run.credential_ids or []),
                      "cred_set_ids": list(run.cred_set_ids or []),
                      "name": run.name, "schedule_id": run.schedule_id,
                      "options": dict(run.options or {}), "node_id": run.node_id}
        if not params["requested_targets"]:
            raise ValueError("у прогона не сохранены цели — запустите новый прогон")
        return self.submit(**params, actor=actor, started_by=started_by,
                           retry_of=scan_run_id)


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


    def _prepare(self, scan_run_id: int, worker_id: str) -> _Prepared | str:
        """Параметры прогона из БД и захват pending -> running за worker_id.
        -> _Prepared или итоговый статус, если прогон уже не pending."""
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
            prepared = _Prepared(engagement_id=engagement_id, names=names,
                                 options=run_options, history=history, rate=rate,
                                 gate=gate, credentials=credentials,
                                 cred_candidates=cred_candidates, set_ids=set_ids,
                                 targets=list(run.targets or []), name=run.name)
            # pending -> running атомарно: прогон, поставленный в очередь повторно,
            # не исполнится дважды.
            if not repo.claim_scan_run(s, scan_run_id, worker_id):
                s.expire_all()
                run = repo.get_scan_run(s, scan_run_id)
                return run.status
        return prepared

    def _audit_start(self, scan_run_id: int, p: _Prepared, **extra: object) -> None:
        self.audit.record(subject="scanner", action="scan_start",
                          target=f"scan_run:{scan_run_id}", result="ok",
                          details={"engagement_id": p.engagement_id, "modules": p.names,
                                   "rate_profile": p.rate.name,
                                   "credentials": [c.describe() for c in p.credentials]
                                   or None,
                                   "cred_set_ids": p.set_ids or None,
                                   "cred_candidates": len(p.cred_candidates) or None,
                                   **extra})

    def _execute(self, scan_run_id: int, requested_targets: list[str]) -> str:
        p = self._prepare(scan_run_id, self.worker_id)
        if isinstance(p, str):
            return p
        self._audit_start(scan_run_id, p)
        modules = [self.registry[n]() for n in p.names]
        orch = Orchestrator(p.gate, self.audit,
                            should_stop=lambda: self._status(scan_run_id) == "stopped",
                            events=ev.recorder(self.sessions, scan_run_id))
        out = orch.run_detailed(engagement_id=p.engagement_id, scan_run_id=scan_run_id,
                                requested_targets=requested_targets, modules=modules,
                                rate=p.rate, credentials=p.credentials,
                                cred_candidates=p.cred_candidates, options=p.options,
                                progress=lambda snap: self._save_progress(scan_run_id, snap),
                                progress_history=p.history)
        p.credentials, p.cred_candidates = [], []    # секреты больше не нужны
        return self.persist_outcome(scan_run_id, out)
