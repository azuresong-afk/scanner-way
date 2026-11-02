"""Запись целей: адрес, подсеть (CIDR) или диапазон «начало-конец».

Диапазон хранить в allowlist нельзя (колонка CIDR), поэтому он раскладывается
в минимальный набор подсетей (`ipaddress.summarize_address_range`): ровно те же
адреса, ни одним больше. Так гейт allowlist остаётся прежним и проверяет
только литеральные адреса и подсети.

Поддерживаемые формы:
  10.0.0.5            адрес
  10.0.0.0/24         подсеть
  10.0.0.1-10.0.0.50  диапазон (пробелы вокруг «-» допустимы)
  10.0.0.1-50         краткая форма IPv4: меняется только последний октет
  2001:db8::1-2001:db8::ff  диапазон IPv6 — только полной записью
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass

IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network
IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address

_RANGE = re.compile(r"^\s*([0-9A-Fa-f:.]+)\s*-\s*([0-9A-Fa-f:.]+)\s*$")


@dataclass(frozen=True, slots=True)
class TargetSpec:
    """Разобранная запись цели."""
    text: str                       # нормализованная запись
    networks: tuple[IPNetwork, ...]  # покрывающие подсети, без лишних адресов
    is_range: bool

    @property
    def num_addresses(self) -> int:
        return sum(n.num_addresses for n in self.networks)


def is_range(spec: str) -> bool:
    return _RANGE.match(spec) is not None


def parse_range(spec: str) -> tuple[IPAddress, IPAddress]:
    """(первый, последний) адрес диапазона. ValueError — не диапазон или мусор."""
    m = _RANGE.match(spec)
    if m is None:
        raise ValueError(f"не диапазон: {spec!r}")
    first = ipaddress.ip_address(m.group(1))
    tail = m.group(2)
    if first.version == 4 and tail.isdigit():
        # краткая форма 10.0.0.1-50: последний октет конца диапазона
        octet = int(tail)
        if octet > 255:
            raise ValueError(f"октет вне 0..255: {spec!r}")
        last: IPAddress = ipaddress.IPv4Address((int(first) & ~0xFF) | octet)
    else:
        last = ipaddress.ip_address(tail)
    if first.version != last.version:
        raise ValueError(f"начало и конец диапазона разных версий IP: {spec!r}")
    if last < first:
        raise ValueError(f"конец диапазона меньше начала: {spec!r}")
    return first, last


def parse_target(spec: str) -> TargetSpec:
    """Адрес, подсеть или диапазон → TargetSpec. ValueError — не цель (в т.ч. имя хоста)."""
    raw = spec.strip()
    if not raw:
        raise ValueError("пустая цель")
    if is_range(raw):
        first, last = parse_range(raw)
        nets = tuple(ipaddress.summarize_address_range(first, last))
        if len(nets) == 1:
            return TargetSpec(str(nets[0]) if nets[0].num_addresses > 1 else str(first),
                              nets, False)
        return TargetSpec(f"{first}-{last}", nets, True)
    net = ipaddress.ip_network(raw, strict=False)
    return TargetSpec(str(net), (net,), False)


def range_hosts(spec: TargetSpec) -> list[str]:
    """Все адреса диапазона (вместе с крайними — их перечислили явно)."""
    return [str(a) for n in spec.networks for a in n]
