"""Общий интерфейс сканирующего модуля.

Все модули (discovery, vuln, auth_inventory, config_audit, cred_audit) реализуют ScanModule.
Оркестратор передаёт им ТОЛЬКО отфильтрованные allowlist-ом цели и профиль
лимитов; модуль возвращает список нормализованных Finding.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field

from scanner.core.audit import AuditSink
from scanner.core.credentials import HostCredential
from scanner.core.models import Finding, HostInventory, HostOs, ServiceInfo
from scanner.core.ratelimit import RateProfile


@dataclass(slots=True)
class ScanContext:
    engagement_id: int
    scan_run_id: int
    targets: list[str]                 # уже отфильтрованы allowlist-ом
    rate: RateProfile
    audit: AuditSink
    services: list[ServiceInfo] | None = None  # результат discovery для след. модулей
    # Живые хосты по данным discovery и их ОС (nmap -O + баннеры сервисов).
    hosts: dict[str, HostOs] = field(default_factory=dict)
    # Учётные записи активов, выбранные для прогона (расшифрованы оркестратором).
    credentials: list[HostCredential] = field(default_factory=list)
    # Кандидаты для аудита паролей: пары (логин, секрет) из наборов проверки,
    # расшифрованные оркестратором на время прогона (cred_audit). Пусто —
    # модуль cred_audit не делает ни одной попытки. Тип нейтрален, чтобы base
    # не зависел от модуля cred_audit.
    cred_candidates: list[tuple[str, str]] = field(default_factory=list)
    # Результат аутентифицированной инвентаризации: хост -> ОС и пакеты.
    inventory: dict[str, HostInventory] = field(default_factory=dict)
    # Конфигурация парольной политики, собранная по учётке активов (config_audit,
    # R1a): хост -> {имя файла -> содержимое}. Пусто — проверка политики инертна.
    host_policy_configs: dict[str, dict[str, str]] = field(default_factory=dict)
    # Модули, уже отработавшие без ошибки (оркестратор дополняет по ходу прогона).
    completed: set[str] = field(default_factory=set)


class ScanModule(ABC):
    name: str = "base"

    @abstractmethod
    def run(self, ctx: ScanContext) -> list[Finding]:
        """Выполнить модуль и вернуть нормализованные находки."""
        raise NotImplementedError
