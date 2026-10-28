"""Модуль 3: аудит конфигураций (бэкенды: OpenSCAP, Lynis).

Профили: CIS Benchmarks и, для гос-контекста, требования ФСТЭК/ГОСТ.
Безагентно по SSH или на хосте — см. открытый вопрос в architecture.md.
"""
from __future__ import annotations

from scanner.modules.base import ScanContext, ScanModule


class ConfigAuditModule(ScanModule):
    name = "config_audit"

    def run(self, ctx: ScanContext):
        # TODO (итерация 4): прогнать OpenSCAP (XCCDF/OVAL профиль) и/или Lynis,
        # распарсить результаты в Finding(finding_type=CONFIG) с привязкой к
        # правилам бенчмарка.
        raise NotImplementedError("config_audit: OpenSCAP/Lynis — итерация 4")
