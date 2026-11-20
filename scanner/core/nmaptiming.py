"""Согласование лимита скорости nmap с таймаутами.

`--max-rate` в nmap — общий потолок пакетов в секунду на ВЕСЬ вызов, а
`--host-timeout` отсчитывается для каждого хоста отдельно с момента, когда nmap
взял его в работу. Если nmap сканирует сразу N хостов, каждому достаётся
rate/N пакетов в секунду, и при фиксированном host-timeout хосты обрываются
(«Профиль «Медленный»: 5 пакетов/с × 1000 портов — уже пять живых хостов не
укладываются в 900 с»), а общий таймаут вызова убивает nmap целиком.

Здесь лимит скорости не трогаем — это защитная мера договора. Вместо этого:
- ограничиваем число хостов, сканируемых одновременно (`--max-hostgroup`), так
  чтобы каждой группе хватало скорости пройти все порты за разумное время;
- host-timeout считаем из реального объёма проб на хост и доли скорости,
  которая ему достаётся, с запасом и временем на -sV/-O;
- размер пачки (хостов на один вызов nmap) подбираем так, чтобы вызов шёл
  не дольше часа, а общий таймаут вызова — из числа «волн» групп в пачке.

Все функции чистые: только арифметика по профилю и опциям.
"""
from __future__ import annotations

import math
from dataclasses import dataclass

from scanner.core import portspec
from scanner.core.ratelimit import RateProfile

DEFAULT_PORTS = 1000         # nmap без -p: топ-1000 TCP
# Проб на порт у живого хоста: сама проба + повторы по фильтруемым портам,
# обнаружение хоста и пакеты -O.
_LIVE_PROBE_FACTOR = 1.5
# Время на фазы, которые --max-rate почти не ограничивает: -sV (TCP-соединения
# к открытым портам) и -O.
_SV_OVERHEAD_SEC = 300
_PLAIN_OVERHEAD_SEC = 60
# Желаемая длительность фазы сканирования портов одной группы хостов.
_GROUP_SCAN_SEC = 600
_SAFETY = 1.5                # запас host-timeout к расчётному времени
_MIN_HOST_TIMEOUT_SEC = 300
_CALL_TARGET_SEC = 3600      # к такой длительности одного вызова nmap стремимся
_CALL_MARGIN_SEC = 120


@dataclass(frozen=True, slots=True)
class TimingPlan:
    hostgroup: int            # --max-hostgroup
    host_timeout_sec: int     # --host-timeout
    batch_size: int           # хостов на один вызов nmap
    probes_per_host: int      # оценка пакетов на хост

    def call_timeout(self, n_hosts: int) -> int:
        """Общий таймаут вызова nmap на n_hosts: волны групп × host-timeout + запас."""
        waves = max(1, math.ceil(n_hosts / self.hostgroup))
        return waves * self.host_timeout_sec + _CALL_MARGIN_SEC


def count_ports(ports: str | None = None, *, top: int | None = None,
                exclude: str | None = None) -> int:
    """Число портов на хост: явный список (-p) или топ-N, минус исключения.

    Запись, которую portspec не понимает (nmap-синтаксис вроде «T:22,U:53»),
    считаем как топ-1000 — оценка, а не отказ."""
    if ports:
        try:
            n = portspec.count(portspec.parse_ports(ports))
        except portspec.PortSpecError:
            n = DEFAULT_PORTS
    else:
        n = top or DEFAULT_PORTS
    if exclude:
        try:
            n -= portspec.count(portspec.parse_ports(exclude))
        except portspec.PortSpecError:
            pass
    return max(1, n)


def plan(rate: RateProfile, n_ports: int, *, max_retries: int,
         service_detection: bool, no_ping: bool = False,
         max_batch: int = 64) -> TimingPlan:
    """План тайминга для nmap по профилю скорости и объёму работы на хост.

    no_ping (-Pn): адрес без ответа не отсеивается обнаружением, и nmap
    повторяет пробу каждого «фильтруемого» порта max_retries раз — закладываем
    полный объём повторов."""
    pps = max(0.1, float(rate.max_requests_per_sec))
    factor = (1 + max(0, max_retries)) if no_ping else _LIVE_PROBE_FACTOR
    probes = max(1, math.ceil(n_ports * max(factor, _LIVE_PROBE_FACTOR)))
    overhead = _SV_OVERHEAD_SEC if service_detection else _PLAIN_OVERHEAD_SEC

    group = int(pps * _GROUP_SCAN_SEC // probes)
    group = max(1, min(group, max(1, rate.max_concurrency), max(1, max_batch)))
    scan_sec = probes * group / pps
    host_timeout = max(_MIN_HOST_TIMEOUT_SEC, math.ceil(scan_sec * _SAFETY + overhead))

    waves_per_call = max(1, _CALL_TARGET_SEC // host_timeout)
    batch = max(1, min(max_batch, group * waves_per_call))
    return TimingPlan(hostgroup=group, host_timeout_sec=host_timeout,
                      batch_size=batch, probes_per_host=probes)
