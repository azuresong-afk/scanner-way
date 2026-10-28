"""Модуль 3: аудит конфигураций — БЕЗАГЕНТНЫЙ (бэкенды: OpenSCAP, Lynis).

Профили: CIS Benchmarks и, для гос-контекста, требования ФСТЭК/ГОСТ.

Только безагентный режим (решение заказчика): без установки постоянного агента.
  * OpenSCAP — через oscap-ssh: движок на сканере, сбор по SSH на цели;
  * Lynis — доставка по SSH во временный каталог, запуск, забор отчёта, очистка.
Нужны SSH-учётки/ключ с правами аудита в рамках engagement; все подключения и
команды логируются в ctx.audit.
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
