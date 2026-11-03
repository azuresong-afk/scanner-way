"""Проверка сетевой доступности (вкладка «Доступность»): какие хосты в сети и
какие на них открыты TCP-порты — без полного прогона.

Бэкенд — nmap без определения ОС и без NSE-скриптов:
  * порты — 1000 самых популярных (`--top-ports 1000`) или явный список
    (`-p 22,80,8000-8100`); исключения — `--exclude-ports`;
  * без проверки ping (`-Pn`) — как опция прогона: хост, не отвечающий на
    обнаружение, всё равно проверяется по портам;
  * определение сервисов (`-sV`) — по желанию, дольше.

Безопасность — как у прогона: цели уже прошли allowlist в API и ещё раз
проверяются как литеральные IP перед вызовом nmap (defense in depth); nmap
вызывается без shell с лимитами профиля интенсивности (`--max-rate`,
`--max-parallelism`); каждый вызов и итог пишутся в журнал аудита.

Задание выполняется в фоне пачками по `BATCH` хостов: после каждой пачки
результат сохраняется (прогресс в интерфейсе), а живые хосты заносятся в
«Активы» — даже если учётных записей к ним ещё нет.
"""
from __future__ import annotations

import ipaddress
import logging
import shlex
import subprocess
import threading
from collections.abc import Callable, Iterable, Mapping, Sequence
from concurrent.futures import Executor, ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import UTC, datetime

from libnmap.parser import NmapParser, NmapParserException
from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from scanner.core.audit import AuditSink
from scanner.core.db import PortScanRow
from scanner.core.ratelimit import RateProfile, get_profile

log = logging.getLogger(__name__)

MODE_TOP = "top"          # N самых популярных портов nmap
MODE_LIST = "list"        # явный список/диапазоны
TOP_PORTS = 1000
BATCH = 32
HOST_TIMEOUT_SEC = 300
MAX_RETRIES = 1
ACTIVE = ("queued", "running")

MSG_INTERRUPTED = ("Проверка прервана: служба сканера была перезапущена. "
                   "Результаты завершённых пачек сохранены — запустите проверку "
                   "повторно для остальных адресов.")


class NetScanError(RuntimeError):
    """nmap завершился с ошибкой или вывод не разобран."""


class Stopped(Exception):
    """Проверку остановил пользователь."""


@dataclass(slots=True)
class ScanOptions:
    mode: str = MODE_TOP
    ports: str | None = None          # нормализованная запись (portspec.to_text) для MODE_LIST
    exclude: str | None = None        # то же для --exclude-ports
    no_ping: bool = False
    service_detection: bool = False
    top: int = TOP_PORTS


@dataclass(slots=True)
class OpenPort:
    port: int
    protocol: str = "tcp"
    service: str | None = None
    product: str | None = None
    version: str | None = None

    def to_dict(self) -> dict:
        return {"port": self.port, "protocol": self.protocol, "service": self.service,
                "product": self.product, "version": self.version}


@dataclass(slots=True)
class HostResult:
    host: str
    up: bool
    reason: str | None = None          # syn-ack / echo-reply / user-set (-Pn) …
    hostname: str | None = None
    mac: str | None = None
    vendor: str | None = None
    ports: list[OpenPort] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {"host": self.host, "up": self.up, "reason": self.reason,
                "hostname": self.hostname, "mac": self.mac, "vendor": self.vendor,
                "ports": [p.to_dict() for p in self.ports]}


# Раннер: (argv, timeout, stop_event) -> XML со stdout. Подменяется в тестах.
Runner = Callable[[list[str], float, threading.Event], str]


def literal_ips(targets: Iterable[str]) -> tuple[list[str], list[str]]:
    ok, bad = [], []
    for t in targets:
        try:
            ok.append(str(ipaddress.ip_address(str(t).strip())))
        except ValueError:
            bad.append(str(t))
    return ok, bad


def build_command(targets: Sequence[str], rate: RateProfile, opts: ScanOptions,
                  nmap_path: str = "nmap") -> list[str]:
    """argv nmap. Цели — проверенные литеральные IP, порты — из portspec."""
    cmd = [nmap_path, "-n"]
    if opts.service_detection:
        cmd.append("-sV")
    if opts.no_ping:
        cmd.append("-Pn")
    if any(":" in t for t in targets):
        cmd.append("-6")
    if opts.mode == MODE_LIST:
        if not opts.ports:
            raise NetScanError("не задан список портов")
        cmd += ["-p", opts.ports]
    else:
        cmd += ["--top-ports", str(opts.top)]
    if opts.exclude:
        cmd += ["--exclude-ports", opts.exclude]
    cmd += [
        "-T4" if rate.name == "aggressive" else "-T3",
        "--max-rate", f"{rate.max_requests_per_sec:g}",
        "--max-parallelism", str(rate.max_concurrency),
        "--max-retries", str(MAX_RETRIES),
        "--host-timeout", f"{HOST_TIMEOUT_SEC}s",
        "-oX", "-", *targets,
    ]
    return cmd


def parse_xml(xml: str, targets: Sequence[str]) -> list[HostResult]:
    """Результат по каждому адресу пачки: не упомянутые nmap — недоступны."""
    try:
        report = NmapParser.parse_fromstring(xml)
    except NmapParserException as e:
        raise NetScanError(f"не удалось разобрать XML nmap: {e}") from e
    seen: dict[str, HostResult] = {}
    for h in report.hosts:
        try:
            addr = str(ipaddress.ip_address(h.address))
        except ValueError:
            continue
        ports = []
        for svc in h.services:
            if svc.state != "open":
                continue
            sd = svc.service_dict
            ports.append(OpenPort(svc.port, svc.protocol, svc.service or None,
                                  sd.get("product") or None, sd.get("version") or None))
        up = h.is_up()
        reason = getattr(h, "_status", {}).get("reason") or None
        # с -Pn nmap считает «включённым» любой адрес: без открытых портов
        # подтверждения, что хост в сети, нет
        if up and reason == "user-set" and not ports:
            up = False
        seen[addr] = HostResult(host=addr, up=up, reason=reason,
                                hostname=(h.hostnames[0] if h.hostnames else None),
                                mac=h.mac or None, vendor=h.vendor or None,
                                ports=sorted(ports, key=lambda p: p.port))
    return [seen.get(t) or HostResult(host=t, up=False) for t in targets]


def subprocess_runner(cmd: list[str], timeout: float, stop: threading.Event) -> str:
    """nmap как дочерний процесс; остановка пользователем прерывает его."""
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            text=True)
    result: dict[str, str] = {}

    def comm() -> None:
        result["out"], result["err"] = proc.communicate()

    t = threading.Thread(target=comm, daemon=True)
    t.start()
    waited = 0.0
    while t.is_alive():
        t.join(0.5)
        waited += 0.5
        if stop.is_set() or waited > timeout:
            proc.kill()
            t.join(5)
            if stop.is_set():
                raise Stopped()
            raise NetScanError(f"nmap не завершился за {int(timeout)} с")
    if proc.returncode != 0:
        raise NetScanError(f"nmap rc={proc.returncode}: {result.get('err', '').strip()[:500]}")
    return result.get("out", "")


def register_assets(session: Session, engagement_id: int, hosts: Iterable[str], *,
                    hostnames: Mapping[str, str] | None = None,
                    created_by: int | None = None) -> int:
    """Живые хосты → «Активы» (source=netscan). Возвращает число новых.

    Учётные записи не нужны: актив заводится по факту ответа хоста в сети,
    глубокую проверку настраивают потом. У существующих активов обновляется
    только отметка «последний раз обнаружен» (assets.record_seen)."""
    from scanner.core import assets as asvc
    return asvc.record_seen(session, engagement_id, hosts, source=asvc.SOURCE_NETSCAN,
                            hostnames=hostnames, created_by=created_by)


def summarize(results: Sequence[dict]) -> dict:
    up = [r for r in results if r.get("up")]
    return {"hosts_done": len(results), "hosts_up": len(up),
            "open_ports": sum(len(r.get("ports") or []) for r in up)}


class PortScanService:
    """Фоновое исполнение заданий проверки доступности."""

    def __init__(self, sessions: sessionmaker[Session], audit: AuditSink, *,
                 executor: Executor | None = None, runner: Runner | None = None,
                 nmap_path: str = "nmap", workers: int = 2):
        self.sessions, self.audit = sessions, audit
        self._own = executor is None
        self.executor = executor or ThreadPoolExecutor(max_workers=max(1, workers),
                                                       thread_name_prefix="netscan")
        self.runner = runner or subprocess_runner
        self.nmap_path = nmap_path
        self._stops: dict[int, threading.Event] = {}
        self._lock = threading.Lock()

    # ---- жизненный цикл ----
    def recover(self) -> list[int]:
        """Задания, оставшиеся queued/running от прошлого процесса → interrupted."""
        with self.sessions() as s:
            rows = list(s.scalars(select(PortScanRow).where(PortScanRow.status.in_(ACTIVE))))
            for r in rows:
                r.status, r.error = "interrupted", MSG_INTERRUPTED
                r.finished_at = datetime.now(UTC)
            s.commit()
            ids = [r.id for r in rows]
        for i in ids:
            self.audit.record(subject="system", action="port_scan", target=f"port_scan:{i}",
                              result="interrupted")
        return ids

    def shutdown(self) -> None:
        with self._lock:
            for ev in self._stops.values():
                ev.set()
        if self._own:
            self.executor.shutdown(wait=False, cancel_futures=True)

    # ---- задания ----
    def submit(self, scan_id: int) -> None:
        with self._lock:
            self._stops[scan_id] = threading.Event()
        self.executor.submit(self._execute, scan_id)

    def stop(self, scan_id: int) -> bool:
        with self._lock:
            ev = self._stops.get(scan_id)
        if ev is None:
            return False
        ev.set()
        return True

    def _execute(self, scan_id: int) -> None:
        stop = self._stops.get(scan_id) or threading.Event()
        try:
            self._run(scan_id, stop)
        except Exception:      # задание не должно ронять пул
            log.exception("port scan %s failed", scan_id)
        finally:
            with self._lock:
                self._stops.pop(scan_id, None)

    def _finish(self, scan_id: int, status: str, error: str | None = None) -> None:
        with self.sessions() as s:
            row = s.get(PortScanRow, scan_id)
            row.status, row.error = status, error
            row.finished_at = datetime.now(UTC)
            s.commit()
            details = {"hosts_up": row.hosts_up, "open_ports": row.open_ports,
                       "assets_created": row.assets_created}
            actor = row.actor
        self.audit.record(subject=actor or "scanner", action="port_scan",
                          target=f"port_scan:{scan_id}", result=status,
                          details={**details, **({"error": error[:300]} if error else {})})

    def _run(self, scan_id: int, stop: threading.Event) -> None:
        with self.sessions() as s:
            row = s.get(PortScanRow, scan_id)
            if row is None or row.status != "queued":
                return
            if stop.is_set():
                row.status, row.finished_at = "stopped", datetime.now(UTC)
                s.commit()
                return
            row.status, row.started_at = "running", datetime.now(UTC)
            s.commit()
            engagement_id, created_by = row.engagement_id, row.started_by
            targets = list(row.targets or [])
            opts = ScanOptions(mode=row.port_mode, ports=row.ports, exclude=row.exclude_ports,
                               no_ping=row.no_ping, service_detection=row.service_detection)
            rate = get_profile(row.rate_profile)
        targets, bad = literal_ips(targets)
        for t in bad:
            self.audit.record(subject="scanner", action="nmap_exec", target=t,
                              result="not_an_ip_literal")
        results: list[dict] = []
        for i in range(0, len(targets), BATCH):
            if stop.is_set():
                return self._finish(scan_id, "stopped")
            batch = targets[i:i + BATCH]
            # allowlist — ещё раз перед каждой пачкой: его могли сузить во время проверки
            with self.sessions() as s:
                from scanner.core import repository as repo
                allowed, denied = repo.load_allowlist_gate(s, engagement_id).filter(batch)
            for t in denied:
                self.audit.record(subject="scanner", action="nmap_exec", target=t,
                                  result="not_in_allowlist")
            if allowed:
                cmd = build_command(allowed, rate, opts, self.nmap_path)
                timeout = HOST_TIMEOUT_SEC * 2 + 60
                self.audit.record(subject="scanner", action="nmap_exec",
                                  target=",".join(allowed), result="started",
                                  details=shlex.join(cmd))
                try:
                    xml = self.runner(cmd, timeout, stop)
                    found = parse_xml(xml, allowed)
                except Stopped:
                    self.audit.record(subject="scanner", action="nmap_exec",
                                      target=",".join(allowed), result="stopped")
                    return self._finish(scan_id, "stopped")
                except (NetScanError, OSError) as e:
                    self.audit.record(subject="scanner", action="nmap_exec",
                                      target=",".join(allowed), result="error",
                                      details=str(e)[:500])
                    return self._finish(scan_id, "failed", str(e)[:1000])
                self.audit.record(subject="scanner", action="nmap_exec",
                                  target=",".join(allowed), result="ok",
                                  details=f"hosts_up={sum(r.up for r in found)}")
            else:
                found = []
            results += [r.to_dict() for r in found]
            results += [{**HostResult(host=t, up=False).to_dict(),
                         "reason": "not_in_allowlist"} for t in denied]
            live = [r for r in found if r.up]
            with self.sessions() as s:
                created = register_assets(
                    s, engagement_id, [r.host for r in live],
                    hostnames={r.host: r.hostname for r in live if r.hostname},
                    created_by=created_by)
                row = s.get(PortScanRow, scan_id)
                row.results = list(results)
                summary = summarize(results)
                row.hosts_done, row.hosts_up = summary["hosts_done"], summary["hosts_up"]
                row.open_ports = summary["open_ports"]
                row.assets_created = (row.assets_created or 0) + created
                s.commit()
        return self._finish(scan_id, "done")
