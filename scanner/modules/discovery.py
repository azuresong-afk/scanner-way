"""Модуль 1: исследование сети и инвентаризация (бэкенд: nmap).

Определяет живые хосты, открытые порты, сервисы, версии и fingerprint ОС
(`nmap -sV -O`). Вывод nmap (XML) парсится в ServiceInfo и информационные Finding.
"""
from __future__ import annotations

from scanner.core.models import Finding, FindingType, Severity
from scanner.modules.base import ScanContext, ScanModule


class DiscoveryModule(ScanModule):
    name = "discovery"

    def run(self, ctx: ScanContext) -> list[Finding]:
        # TODO (итерация 2): собрать и выполнить вызов nmap с учётом ctx.rate,
        # записать действие в ctx.audit, распарсить XML (python-libnmap) в
        # ServiceInfo -> положить в ctx.services, вернуть info-находки.
        raise NotImplementedError("discovery: nmap backend — итерация 2")
