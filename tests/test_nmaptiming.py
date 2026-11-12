"""Б1: --max-rate (общий на вызов) не должен конфликтовать с --host-timeout."""
import math

import pytest

from scanner.core import netscan, nmaptiming
from scanner.core.ratelimit import PROFILES, get_profile
from scanner.modules.base import ScanContext
from scanner.modules.discovery import (
    DiscoveryModule,
    DiscoveryOptions,
    build_nmap_command,
    timing_plan,
)
from tests.test_discovery import SAMPLE, ListAudit


def _arg(cmd, flag):
    return cmd[cmd.index(flag) + 1]


@pytest.mark.parametrize("profile", list(PROFILES))
@pytest.mark.parametrize("no_ping", [False, True])
@pytest.mark.parametrize("n_ports", [10, 1000, 65535])
def test_host_gets_enough_rate_share(profile, no_ping, n_ports):
    rate = PROFILES[profile]
    p = nmaptiming.plan(rate, n_ports, max_retries=2, service_detection=True,
                        no_ping=no_ping)
    # каждому хосту группы достаётся rate/hostgroup пакетов/с — его пробы
    # должны уложиться в host-timeout с запасом
    per_host_sec = p.probes_per_host / (rate.max_requests_per_sec / p.hostgroup)
    assert per_host_sec * 1.2 < p.host_timeout_sec
    assert 1 <= p.hostgroup <= rate.max_concurrency
    assert p.hostgroup <= p.batch_size <= 64
    # таймаут вызова покрывает все волны групп пачки
    waves = math.ceil(p.batch_size / p.hostgroup)
    assert p.call_timeout(p.batch_size) >= waves * p.host_timeout_sec


def test_review_scenario_20_live_hosts_gentle_and_normal():
    """Расчёт из разбора: при 900 с и общей скорости ≥5 (gentle) / ≥19 (normal)
    живых хостов обрывались. Теперь группа ограничена, host-timeout хватает."""
    for name in ("gentle", "normal"):
        rate = get_profile(name)
        p = timing_plan(rate, DiscoveryOptions())
        share = rate.max_requests_per_sec / p.hostgroup
        assert p.probes_per_host / share < p.host_timeout_sec
        cmd = build_nmap_command([f"10.0.0.{i}" for i in range(1, 21)], rate, plan=p)
        assert _arg(cmd, "--max-rate") == f"{rate.max_requests_per_sec:g}"
        assert _arg(cmd, "--max-hostgroup") == str(p.hostgroup)
        assert _arg(cmd, "--host-timeout") == f"{p.host_timeout_sec}s"


def test_rate_limit_is_never_raised():
    for name, rate in PROFILES.items():
        cmd = build_nmap_command(["10.0.0.5"], rate)
        assert float(_arg(cmd, "--max-rate")) == rate.max_requests_per_sec
        assert _arg(cmd, "--max-parallelism") == str(rate.max_concurrency)


def test_no_ping_plans_more_probes():
    rate = get_profile("normal")
    a = nmaptiming.plan(rate, 1000, max_retries=2, service_detection=True)
    b = nmaptiming.plan(rate, 1000, max_retries=2, service_detection=True, no_ping=True)
    assert b.probes_per_host > a.probes_per_host and b.hostgroup <= a.hostgroup


def test_count_ports():
    assert nmaptiming.count_ports(None) == 1000
    assert nmaptiming.count_ports("22,80,8000-8100") == 103
    assert nmaptiming.count_ports(None, top=100, exclude="80") == 99
    assert nmaptiming.count_ports("T:22,U:53") == 1000  # не разобрано — оценка


def test_explicit_host_timeout_wins():
    p = timing_plan(get_profile("gentle"), DiscoveryOptions(host_timeout_sec=111))
    assert p.host_timeout_sec == 111


def test_discovery_batches_and_timeout_follow_plan():
    calls = []

    def runner(cmd, timeout):
        calls.append((cmd, timeout))
        return SAMPLE

    targets = [f"10.0.1.{i}" for i in range(1, 21)]
    ctx = ScanContext(engagement_id=1, scan_run_id=1, targets=targets,
                      rate=get_profile("gentle"), audit=ListAudit())
    DiscoveryModule(runner=runner).run(ctx)
    p = timing_plan(get_profile("gentle"), DiscoveryOptions())
    assert len(calls) == math.ceil(20 / p.batch_size)
    for cmd, timeout in calls:
        n = len(cmd) - cmd.index("-") - 1
        assert n <= p.batch_size
        assert timeout == p.call_timeout(n)


def test_netscan_uses_plan():
    opts = netscan.ScanOptions()
    p = netscan.timing_plan(get_profile("gentle"), opts)
    cmd = netscan.build_command(["10.0.0.5"], get_profile("gentle"), opts)
    assert _arg(cmd, "--max-rate") == "5"
    assert _arg(cmd, "--max-hostgroup") == str(p.hostgroup)
    assert _arg(cmd, "--host-timeout") == f"{p.host_timeout_sec}s"
    assert p.batch_size <= netscan.BATCH
    small = netscan.timing_plan(get_profile("gentle"),
                                netscan.ScanOptions(mode=netscan.MODE_LIST, ports="22,80"))
    assert small.hostgroup > p.hostgroup  # 2 порта — можно больше хостов сразу
