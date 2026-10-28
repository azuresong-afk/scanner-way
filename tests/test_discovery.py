"""Тесты модуля discovery на эталонном nmap XML — без реального сканирования."""
from pathlib import Path

import pytest

from scanner.core.ratelimit import get_profile
from scanner.modules.base import ScanContext
from scanner.modules.discovery import (
    DiscoveryError,
    DiscoveryModule,
    DiscoveryOptions,
    build_nmap_command,
    parse_nmap_xml,
    validate_targets,
)

SAMPLE = (Path(__file__).parent / "fixtures" / "nmap_sample.xml").read_text()


class ListAudit:
    def __init__(self):
        self.records = []

    def record(self, **kw):
        self.records.append(kw)


def _ctx(targets, profile="gentle"):
    return ScanContext(engagement_id=1, scan_run_id=1, targets=targets,
                       rate=get_profile(profile), audit=ListAudit())


def test_parse_services():
    services, _ = parse_nmap_xml(SAMPLE)
    by_key = {(s.host, s.port): s for s in services}
    # filtered 25/tcp и down-хост 10.0.0.7 не попадают в инвентарь
    assert set(by_key) == {("10.0.0.5", 22), ("10.0.0.5", 80), ("10.0.0.5", 443),
                           ("10.0.0.6", 445), ("10.0.0.6", 3389)}
    ssh = by_key[("10.0.0.5", 22)]
    assert (ssh.protocol, ssh.service, ssh.product) == ("tcp", "ssh", "OpenSSH")
    assert ssh.version == "8.9p1 Ubuntu 3ubuntu0.6"
    assert ssh.cpe == "cpe:/a:openbsd:openssh:8.9p1"
    smb = by_key[("10.0.0.6", 445)]
    assert smb.service == "microsoft-ds" and smb.product is None and smb.cpe is None


def test_parse_findings():
    _, findings = parse_nmap_xml(SAMPLE)
    hosts_up = [f for f in findings if f.vuln_id == "INFO:host-up"]
    assert {f.host for f in hosts_up} == {"10.0.0.5", "10.0.0.6"}
    web = next(f for f in hosts_up if f.host == "10.0.0.5")
    assert "web01.client.local" in web.title and "52:54:00:12:34:56" in web.evidence

    os_f = [f for f in findings if f.vuln_id == "INFO:os"]
    assert len(os_f) == 1 and os_f[0].host == "10.0.0.5"
    assert "Linux 5.0 - 5.14" in os_f[0].title and "98" in os_f[0].title
    assert "cpe:/o:linux:linux_kernel:5" in os_f[0].evidence

    ports = [f for f in findings if f.vuln_id == "INFO:open-port/tcp"]
    assert len(ports) == 5
    assert all(f.module == "discovery" and f.severity == "info" for f in findings)
    # ключи сравнения прогонов уникальны
    assert len({f.dedup_key() for f in findings}) == len(findings)


def test_parse_garbage_raises():
    with pytest.raises(DiscoveryError):
        parse_nmap_xml("not xml")


def test_validate_targets_rejects_non_ip():
    ok, rejected = validate_targets(["10.0.0.5", "10.0.0.0/24", "-iL/etc/passwd",
                                     "host.local", "fe80::1"])
    assert ok == ["10.0.0.5", "fe80::1"]
    assert rejected == ["10.0.0.0/24", "-iL/etc/passwd", "host.local"]


def test_command_applies_rate_limits():
    cmd = build_nmap_command(["10.0.0.5"], get_profile("gentle"))
    assert cmd[:3] == ["nmap", "-sV", "-O"]
    assert cmd[cmd.index("--max-rate") + 1] == "5"
    assert cmd[cmd.index("--max-parallelism") + 1] == "8"
    assert cmd[-3:] == ["-oX", "-", "10.0.0.5"]

    cmd = build_nmap_command(["10.0.0.5"], get_profile("aggressive"),
                             DiscoveryOptions(ports="22,80", os_detection=False))
    assert "-O" not in cmd and "-T4" in cmd
    assert cmd[cmd.index("-p") + 1] == "22,80"


def test_run_populates_services_and_audit():
    calls = []

    def fake_runner(cmd, timeout):
        calls.append(cmd)
        return SAMPLE

    ctx = _ctx(["10.0.0.5", "10.0.0.6", "10.0.0.7", "evil.example"])
    findings = DiscoveryModule(runner=fake_runner).run(ctx)

    assert len(calls) == 1 and "evil.example" not in calls[0]
    assert len(ctx.services) == 5 and len(findings) == 8
    actions = [(r["action"], r["result"]) for r in ctx.audit.records]
    assert actions == [("discovery_deny", "not_an_ip_literal"),
                       ("nmap_exec", "started"), ("nmap_exec", "ok")]
    assert "--max-rate 5" in ctx.audit.records[1]["details"]


def test_run_batches_targets():
    calls = []

    def fake_runner(cmd, timeout):
        calls.append(cmd)
        return SAMPLE

    ctx = _ctx([f"10.0.0.{i}" for i in range(1, 6)])
    DiscoveryModule(DiscoveryOptions(batch_size=2), runner=fake_runner).run(ctx)
    assert [c[c.index("-") + 1:] for c in calls] == [
        ["10.0.0.1", "10.0.0.2"], ["10.0.0.3", "10.0.0.4"], ["10.0.0.5"]]


def test_run_error_is_audited():
    def failing_runner(cmd, timeout):
        raise DiscoveryError("nmap rc=1: requires root privileges")

    ctx = _ctx(["10.0.0.5"])
    with pytest.raises(DiscoveryError):
        DiscoveryModule(runner=failing_runner).run(ctx)
    assert ctx.audit.records[-1]["result"] == "error"
    assert "root" in ctx.audit.records[-1]["details"]
