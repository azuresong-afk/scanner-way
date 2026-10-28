"""Allowlist-гейт: единственная точка, решающая, можно ли трогать цель.

Любое сетевое действие проходит через AllowlistGate. Цели вне allowlist
отбрасываются и фиксируются в аудите как отказ. Модули НЕ умеют обходить гейт —
им передаётся уже отфильтрованный список целей.
"""
from __future__ import annotations

import ipaddress
from collections.abc import Iterable


class AllowlistGate:
    def __init__(self, allowed_cidrs: Iterable[str]):
        self._networks = [ipaddress.ip_network(c, strict=False) for c in allowed_cidrs]

    def is_allowed(self, host: str) -> bool:
        try:
            addr = ipaddress.ip_address(host)
        except ValueError:
            # Hostname: резолв и проверка выполняются на уровне оркестратора
            # перед запуском; в каркасе hostname без резолва считается запрещённым.
            return False
        return any(addr in net for net in self._networks)

    def filter(self, hosts: Iterable[str]) -> tuple[list[str], list[str]]:
        """Возвращает (allowed, denied)."""
        allowed, denied = [], []
        for h in hosts:
            (allowed if self.is_allowed(h) else denied).append(h)
        return allowed, denied
