"""Оркестратор прогона: allowlist-гейт -> модули -> находки.

Код разделён по модулям пакета scanner.core.runner (что где — в его
docstring): registry, targets, progress, engine (Orchestrator), service
(RunService), recovery, persist, nodes. Этот модуль оставлен как прежняя
точка импорта: все имена, которые импортировались отсюда, доступны как раньше.
"""
from scanner.core.runner.engine import Orchestrator, RunOutcome, finalize_coverage
from scanner.core.runner.nodes import NodeRunsMixin
from scanner.core.runner.persist import PersistMixin, error_summary, seen_hosts
from scanner.core.runner.progress import (
    ETA_MIN_PERCENT,
    PROGRESS_MIN_INTERVAL,
    STAGE_SAVING,
    RunProgress,
    stage_history,
)
from scanner.core.runner.recovery import (
    HEARTBEAT_SECONDS,
    MSG_INTERRUPTED,
    MSG_INTERRUPTED_SAVED,
    MSG_NO_TARGETS,
    MSG_NO_TARGETS_NODE,
    MSG_NODE_LOST,
    STALE_SECONDS,
    RecoveryMixin,
    _aware,
    make_worker_id,
    owner_is_dead,
)
from scanner.core.runner.registry import (
    COMPANION_MODULES,
    CREDENTIAL_MODULES,
    MODULE_ORDER,
    VULN_ENGINES,
    ModuleFactory,
    _advisory_fetcher,
    _advisory_store,
    default_module_registry,
    order_modules,
    with_companions,
)
from scanner.core.runner.service import (
    RETRYABLE,
    RUN_OPTION_KEYS,
    RunService,
    _InlineExecutor,
    _Prepared,
    clean_run_options,
    inline_executor,
)
from scanner.core.runner.targets import (
    MAX_TARGETS_PER_RUN,
    DeniedTarget,
    TargetPlan,
    plan_targets,
)

__all__ = [
    "COMPANION_MODULES", "CREDENTIAL_MODULES", "ETA_MIN_PERCENT", "HEARTBEAT_SECONDS",
    "MAX_TARGETS_PER_RUN", "MODULE_ORDER", "MSG_INTERRUPTED", "MSG_INTERRUPTED_SAVED",
    "MSG_NODE_LOST", "MSG_NO_TARGETS", "MSG_NO_TARGETS_NODE", "PROGRESS_MIN_INTERVAL",
    "RETRYABLE", "RUN_OPTION_KEYS", "STAGE_SAVING", "STALE_SECONDS", "VULN_ENGINES",
    "DeniedTarget", "ModuleFactory", "NodeRunsMixin", "Orchestrator", "PersistMixin",
    "RecoveryMixin", "RunOutcome", "RunProgress", "RunService", "TargetPlan",
    "_InlineExecutor", "_Prepared", "_advisory_fetcher", "_advisory_store", "_aware",
    "clean_run_options", "default_module_registry", "error_summary", "finalize_coverage",
    "inline_executor", "make_worker_id", "order_modules", "owner_is_dead", "plan_targets",
    "seen_hosts", "stage_history", "with_companions",
]
