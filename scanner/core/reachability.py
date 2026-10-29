"""Быстрая проверка доступности одного хоста без полного прогона.

Две лёгкие пробы, обе — только по адресу, уже прошедшему allowlist-гейт
(проверка гейта — забота вызывающего, см. `routes_reachability`):

  * ICMP echo — один пакет через системный `ping` (без raw-сокетов в процессе);
  * TCP connect — к нескольким типовым портам. Ответ RST («закрыт») тоже
    означает, что хост в сети; таймаут — фильтруется или хост недоступен.

Ничего не сканирует сверх этого: без перебора портов, без баннеров, без DNS.
Частота проверок на пользователя ограничена `CheckThrottle`.
"""
from __future__ import annotations

import errno
import ipaddress
import re
import shutil
import socket
import subprocess
import threading
import time
from collections import deque
from collections.abc import Callable, Sequence
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field

DEFAULT_PORTS: tuple[int, ...] = (22, 80, 443, 445, 3389)
MAX_PORTS = 10
ICMP_TIMEOUT_SEC = 2.0
TCP_TIMEOUT_SEC = 1.5

PingRunner = Callable[[str, float], "PingResult"]
TcpProbe = Callable[[str, int, float], "PortResult"]


@dataclass(slots=True)
class PingResult:
    available: bool          # есть ли `ping` в системе
    alive: bool = False
    rtt_ms: float | None = None


@dataclass(slots=True)
class PortResult:
    port: int
    state: str               # open | closed | filtered
    rtt_ms: float | None = None


@dataclass(slots=True)
class ReachabilityResult:
    target: str
    reachable: bool
    icmp: PingResult
    ports: list[PortResult] = field(default_factory=list)
    elapsed_ms: float = 0.0

    @property
    def methods(self) -> list[str]:
        """Чем подтверждена доступность: icmp и/или tcp."""
        out = []
        if self.icmp.alive:
            out.append("icmp")
        if any(p.state in ("open", "closed") for p in self.ports):
            out.append("tcp")
        return out


_RTT = re.compile(r"time[=<]\s*([\d.]+)\s*ms")


def system_ping(target: str, timeout: float = ICMP_TIMEOUT_SEC) -> PingResult:
    """Один ICMP echo через `ping`. Адрес — литеральный IP (гейт уже проверил)."""
    binary = shutil.which("ping")
    if binary is None:
        return PingResult(available=False)
    family = "-6" if ipaddress.ip_address(target).version == 6 else "-4"
    cmd = [binary, family, "-n", "-c", "1", "-W", str(max(1, round(timeout))), target]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True,
                              timeout=timeout + 2, check=False)
    except (subprocess.TimeoutExpired, OSError):
        return PingResult(available=True)
    if proc.returncode != 0:
        return PingResult(available=True)
    m = _RTT.search(proc.stdout)
    return PingResult(available=True, alive=True,
                      rtt_ms=float(m.group(1)) if m else None)


def tcp_probe(target: str, port: int, timeout: float = TCP_TIMEOUT_SEC) -> PortResult:
    family = socket.AF_INET6 if ipaddress.ip_address(target).version == 6 else socket.AF_INET
    start = time.monotonic()
    with socket.socket(family, socket.SOCK_STREAM) as s:
        s.settimeout(timeout)
        try:
            code = s.connect_ex((target, port))
        except OSError:
            return PortResult(port, "filtered")
    rtt = round((time.monotonic() - start) * 1000, 1)
    if code == 0:
        return PortResult(port, "open", rtt)
    if code == errno.ECONNREFUSED:
        return PortResult(port, "closed", rtt)
    return PortResult(port, "filtered")


def check_host(target: str, ports: Sequence[int] = DEFAULT_PORTS, *,
               ping: PingRunner = system_ping,
               probe: TcpProbe = tcp_probe) -> ReachabilityResult:
    """ICMP и TCP-пробы параллельно; общее время ≈ максимум из таймаутов."""
    start = time.monotonic()
    with ThreadPoolExecutor(max_workers=1 + len(ports),
                            thread_name_prefix="reach") as pool:
        icmp_f = pool.submit(ping, target, ICMP_TIMEOUT_SEC)
        port_fs = [pool.submit(probe, target, p, TCP_TIMEOUT_SEC) for p in ports]
        icmp = icmp_f.result()
        results = [f.result() for f in port_fs]
    reachable = icmp.alive or any(p.state in ("open", "closed") for p in results)
    return ReachabilityResult(target=target, reachable=reachable, icmp=icmp,
                              ports=results,
                              elapsed_ms=round((time.monotonic() - start) * 1000, 1))


class CheckThrottle:
    """Не больше `limit` проверок на пользователя за скользящее окно `window` сек."""

    def __init__(self, limit: int = 10, window: float = 60.0,
                 clock: Callable[[], float] = time.monotonic):
        self.limit, self.window, self._clock = limit, window, clock
        self._hits: dict[str, deque[float]] = {}
        self._lock = threading.Lock()

    def allow(self, key: str) -> bool:
        now = self._clock()
        with self._lock:
            q = self._hits.setdefault(key, deque())
            while q and now - q[0] >= self.window:
                q.popleft()
            if len(q) >= self.limit:
                return False
            q.append(now)
            return True
