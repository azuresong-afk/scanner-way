"""Модуль 1: исследование сети и инвентаризация (бэкенд: nmap).

Определяет живые хосты, открытые порты, сервисы, версии и fingerprint ОС
(`nmap -sV -O`). Вывод nmap (XML) парсится в ServiceInfo и информационные Finding.

Безопасность:
- цели приходят уже отфильтрованными allowlist-ом; модуль дополнительно
  (defense in depth) принимает только литеральные IP-адреса и отклоняет всё
  остальное с записью отказа в аудит — так в argv nmap не попадёт ни опция,
  ни hostname, ни подсеть шире разрешённой;
- nmap вызывается без shell, с явными лимитами из RateProfile
  (`--max-rate`, `--max-parallelism`) и таймаутами;
- каждый вызов (полная команда) и его итог пишутся в ctx.audit.
"""
from __future__ import annotations

import ipaddress
import shlex
import subprocess
from collections.abc import Callable, Sequence
from dataclasses import dataclass

from libnmap.parser import NmapParser, NmapParserException

from scanner.core.models import Finding, FindingType, HostOs, ServiceInfo, Severity
from scanner.core.osfamily import GENERIC_LINUX, classify, family_label, is_distro
from scanner.core.ratelimit import RateProfile
from scanner.modules.base import ScanContext, ScanModule

# Раннер: (argv, timeout_sec) -> XML со stdout. Подменяется в тестах.
Runner = Callable[[list[str], float], str]

# Шаблон тайминга nmap по профилю. -T2 и ниже добавляют задержку 0.4 с на
# каждую пробу и делают -sV по сотням хостов неприемлемо долгим, поэтому
# реальным ограничителем служат --max-rate/--max-parallelism из профиля.
_TIMING = {"gentle": "-T3", "normal": "-T3", "aggressive": "-T4"}


class DiscoveryError(RuntimeError):
    """nmap завершился с ошибкой или вернул неразбираемый вывод."""


@dataclass(slots=True)
class DiscoveryOptions:
    ports: str | None = None          # None — топ-1000 портов nmap по умолчанию
    os_detection: bool = True         # -O требует root (в контейнере — есть)
    udp: bool = False                 # -sU: медленно, включается явно
    batch_size: int = 64              # хостов на один вызов nmap
    host_timeout_sec: int = 900
    max_retries: int = 2
    nmap_path: str = "nmap"


def validate_targets(targets: Sequence[str]) -> tuple[list[str], list[str]]:
    """Делит цели на (валидные IP, отклонённые). Подсети и имена — отклоняются."""
    ok, rejected = [], []
    for t in targets:
        try:
            ok.append(str(ipaddress.ip_address(t.strip())))
        except ValueError:
            rejected.append(t)
    return ok, rejected


def build_nmap_command(targets: Sequence[str], rate: RateProfile,
                       opts: DiscoveryOptions | None = None) -> list[str]:
    """Собирает argv nmap. Цели должны быть уже проверены validate_targets()."""
    opts = opts or DiscoveryOptions()
    cmd = [opts.nmap_path, "-sV"]
    if opts.os_detection:
        cmd.append("-O")
    if opts.udp:
        cmd += ["-sS", "-sU"]
    if any(":" in t for t in targets):
        cmd.append("-6")
    cmd += [
        _TIMING.get(rate.name, "-T3"),
        "--max-rate", f"{rate.max_requests_per_sec:g}",
        "--max-parallelism", str(rate.max_concurrency),
        "--max-retries", str(opts.max_retries),
        "--host-timeout", f"{opts.host_timeout_sec}s",
    ]
    if opts.ports:
        cmd += ["-p", opts.ports]
    cmd += ["-oX", "-", *targets]
    return cmd


def _subprocess_runner(cmd: list[str], timeout: float) -> str:
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                          check=False)
    if proc.returncode != 0:
        raise DiscoveryError(f"nmap rc={proc.returncode}: {proc.stderr.strip()[:500]}")
    return proc.stdout


def parse_nmap_xml(xml: str, module: str = "discovery"
                   ) -> tuple[list[ServiceInfo], list[Finding]]:
    """Разбирает XML nmap в (ServiceInfo открытых портов, info-находки)."""
    services, findings, _ = parse_nmap_report(xml, module)
    return services, findings


def host_os(addr: str, os_matches: list, banners: Sequence[str]) -> HostOs:
    """ОС хоста по nmap -O и баннерам сервисов (-sV).

    -O различает ядро, но не дистрибутив («Linux 4.15 - 5.8»). Баннеры вроде
    «OpenSSH 8.9p1 Ubuntu 3ubuntu0.6» или «Apache httpd 2.4.57 (Debian)»
    уточняют дистрибутив; противоречащий -O баннер (Ubuntu на хосте, который
    -O считает Windows) не учитывается — это может быть проброс порта.
    """
    out = HostOs(host=addr)
    if os_matches:
        best = os_matches[0]
        classes = " ".join(f"{c.vendor} {c.osfamily}" for c in best.osclasses)
        out.name, out.accuracy, out.source = best.name, int(best.accuracy), "nmap"
        out.family = classify(f"{best.name} {classes}")
    for banner in banners:
        fam = classify(banner)
        if is_distro(fam) and out.family in (None, "other", GENERIC_LINUX):
            out.family, out.source = fam, "banner"
            out.name = out.name or family_label(fam)
            break
        if out.family is None and fam == "windows":
            out.family, out.source, out.name = fam, "banner", family_label(fam)
    return out


def parse_nmap_report(xml: str, module: str = "discovery"
                      ) -> tuple[list[ServiceInfo], list[Finding], list[HostOs]]:
    """Как parse_nmap_xml, плюс живые хосты с их ОС."""
    try:
        report = NmapParser.parse_fromstring(xml)
    except NmapParserException as e:
        raise DiscoveryError(f"не удалось разобрать XML nmap: {e}") from e

    services: list[ServiceInfo] = []
    findings: list[Finding] = []
    hosts: list[HostOs] = []
    for host in report.hosts:
        if not host.is_up():
            continue
        addr = host.address

        evidence = []
        if host.hostnames:
            evidence.append("hostnames: " + ", ".join(host.hostnames))
        if host.mac:
            evidence.append(f"mac: {host.mac}" + (f" ({host.vendor})" if host.vendor else ""))
        title = f"Хост доступен: {addr}"
        if host.hostnames:
            title += f" ({host.hostnames[0]})"
        findings.append(Finding(module=module, host=addr, finding_type=FindingType.INFO,
                                title=title, severity=Severity.INFO,
                                vuln_id="INFO:host-up",
                                evidence="; ".join(evidence) or None))

        os_matches = host.os_match_probabilities() if host.os_fingerprinted else []
        if os_matches:
            best = os_matches[0]
            lines = [f"{m.name} ({m.accuracy}%)" for m in os_matches[:3]]
            cpes = [c.cpestring for oc in best.osclasses for c in oc.cpelist]
            if cpes:
                lines.append("cpe: " + ", ".join(dict.fromkeys(cpes)))
            findings.append(Finding(module=module, host=addr, finding_type=FindingType.INFO,
                                    title=f"ОС: {best.name} (точность {best.accuracy}%)",
                                    severity=Severity.INFO, vuln_id="INFO:os",
                                    evidence="; ".join(lines)))

        banners: list[str] = []
        for svc in host.services:
            if svc.state != "open":
                continue
            sd = svc.service_dict
            banners.append(" ".join(sd.get(k) or "" for k in
                                    ("product", "version", "extrainfo", "ostype")))
            product, version = sd.get("product") or None, sd.get("version") or None
            cpe = svc.cpelist[0].cpestring if svc.cpelist else None
            services.append(ServiceInfo(host=addr, port=svc.port, protocol=svc.protocol,
                                        service=svc.service or None, product=product,
                                        version=version, cpe=cpe))
            label = " ".join(p for p in (svc.service, product, version) if p)
            ev = [svc.banner] if svc.banner else []
            if cpe:
                ev.append(f"cpe: {cpe}")
            findings.append(Finding(module=module, host=addr, port=svc.port,
                                    finding_type=FindingType.INFO, severity=Severity.INFO,
                                    title=f"Открытый порт {svc.port}/{svc.protocol}"
                                          + (f": {label}" if label else ""),
                                    vuln_id=f"INFO:open-port/{svc.protocol}",
                                    evidence="; ".join(ev) or None))
        hosts.append(host_os(addr, os_matches, banners))
    return services, findings, hosts


class DiscoveryModule(ScanModule):
    name = "discovery"

    def __init__(self, options: DiscoveryOptions | None = None,
                 runner: Runner | None = None):
        self.options = options or DiscoveryOptions()
        self._runner = runner or _subprocess_runner

    def run(self, ctx: ScanContext) -> list[Finding]:
        targets, rejected = validate_targets(ctx.targets)
        for t in rejected:
            ctx.audit.record(subject="scanner", action="discovery_deny", target=t,
                             result="not_an_ip_literal")
        if ctx.services is None:
            ctx.services = []

        opts = self.options
        findings: list[Finding] = []
        step = max(1, opts.batch_size)
        for i in range(0, len(targets), step):
            batch = targets[i:i + step]
            cmd = build_nmap_command(batch, ctx.rate, opts)
            # Общий таймаут вызова: host-timeout на волну параллельных хостов + запас.
            timeout = opts.host_timeout_sec * 2 + 60
            ctx.audit.record(subject="scanner", action="nmap_exec",
                             target=",".join(batch), result="started",
                             details=shlex.join(cmd))
            try:
                xml = self._runner(cmd, timeout)
                services, batch_findings, hosts = parse_nmap_report(xml, self.name)
            except (DiscoveryError, subprocess.TimeoutExpired, OSError) as e:
                ctx.audit.record(subject="scanner", action="nmap_exec",
                                 target=",".join(batch), result="error",
                                 details=str(e)[:500])
                raise DiscoveryError(str(e)) from e
            ctx.audit.record(subject="scanner", action="nmap_exec",
                             target=",".join(batch), result="ok",
                             details=f"hosts_up={sum(f.vuln_id == 'INFO:host-up' for f in batch_findings)} "
                                     f"open_ports={len(services)}")
            ctx.services.extend(services)
            ctx.hosts.update((h.host, h) for h in hosts)
            findings.extend(batch_findings)
        return findings
