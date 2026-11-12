"""Цели прогона: разворот диапазонов и подсетей в адреса и allowlist-гейт.

Единственное место, где цели фильтруются через allowlist; модули получают уже
безопасный список."""
from __future__ import annotations

import ipaddress
from collections.abc import Iterable
from dataclasses import dataclass, field

from scanner.core.allowlist import AllowlistGate
from scanner.core.targetspec import is_range, parse_target, range_hosts

# Защита от опечатки вида 10.0.0.0/8 в запросе: столько адресов за прогон
# с запасом покрывает «десятки–сотни хостов».
MAX_TARGETS_PER_RUN = 4096


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
