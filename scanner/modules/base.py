"""Общий интерфейс сканирующего модуля.

Все модули (discovery, vuln, auth_inventory, config_audit, cred_audit) реализуют ScanModule.
Оркестратор передаёт им ТОЛЬКО отфильтрованные allowlist-ом цели и профиль
лимитов; модуль возвращает список нормализованных Finding.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

from scanner.core.audit import AuditSink
from scanner.core.coverage import Coverage
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
    # Факты для профилей соответствия (R5): хост -> {ключ -> значение}, какие
    # проверки на хосте реально выполнялись (см. scanner.compliance.facts).
    compliance_facts: dict[str, dict[str, Any]] = field(default_factory=dict)
    # Покрытие (scanner.core.coverage): что модуль реально проверил на хосте —
    # completed / unreachable / timeout / no_credentials / not_applicable / …
    # Модуль отмечает исходы по хостам; что не отмечено, оркестратор
    # достраивает сам (ошибка модуля, хост не найден discovery, выполнено).
    coverage: Coverage = field(default_factory=Coverage)
    # Опции прогона, выбранные оператором (scan_runs.options): no_ping (-Pn) и т. п.
    options: dict[str, Any] = field(default_factory=dict)
    # Ограничения достоверности, замеченные модулями (scan_runs.warnings):
    # {"kind": "advisories_missing", "host", "family", "release", "message"}.
    run_notes: list[dict[str, Any]] = field(default_factory=list)
    # CVE, проверенные по пакетам хоста (auth_inventory): хост -> {CVE: closed |
    # reported}. По ним находки «по баннеру» того же хоста заменяются точным
    # результатом проверки по учётной записи.
    assessed_cves: dict[str, dict[str, str]] = field(default_factory=dict)

    def host_family(self, host: str) -> str | None:
        """Семейство ОС хоста (scanner.core.osfamily) по данным прогона."""
        if host in self.inventory:
            return "linux"         # вход по SSH и пакеты dpkg/rpm/apk
        h = self.hosts.get(host)
        return h.family if h else None

    def alive_hosts(self) -> set[str] | None:
        """Хосты с открытыми портами по discovery; None — discovery не выполнялся."""
        if "discovery" in self.completed and self.services is not None:
            return {s.host for s in self.services}
        return None


class ScanModule(ABC):
    name: str = "base"

    @abstractmethod
    def run(self, ctx: ScanContext) -> list[Finding]:
        """Выполнить модуль и вернуть нормализованные находки."""
        raise NotImplementedError
