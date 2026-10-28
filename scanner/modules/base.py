"""Общий интерфейс сканирующего модуля.

Все модули (discovery, vuln, config_audit, cred_audit) реализуют ScanModule.
Оркестратор передаёт им ТОЛЬКО отфильтрованные allowlist-ом цели и профиль
лимитов; модуль возвращает список нормализованных Finding.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass

from scanner.core.audit import AuditSink
from scanner.core.models import Finding, ServiceInfo
from scanner.core.ratelimit import RateProfile


@dataclass(slots=True)
class ScanContext:
    engagement_id: int
    scan_run_id: int
    targets: list[str]                 # уже отфильтрованы allowlist-ом
    rate: RateProfile
    audit: AuditSink
    services: list[ServiceInfo] | None = None  # результат discovery для след. модулей


class ScanModule(ABC):
    name: str = "base"

    @abstractmethod
    def run(self, ctx: ScanContext) -> list[Finding]:
        """Выполнить модуль и вернуть нормализованные находки."""
        raise NotImplementedError
