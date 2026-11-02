"""Разбор целей: адрес, подсеть, диапазон «начало-конец»."""
from __future__ import annotations

import ipaddress

import pytest

from scanner.core.allowlist import AllowlistGate
from scanner.core.orchestrator import plan_targets
from scanner.core.targetspec import parse_range, parse_target, range_hosts


def _addrs(spec):
    return {str(a) for n in spec.networks for a in n}


def test_range_full_and_short_form_same_addresses():
    full = parse_target("10.0.0.1-10.0.0.50")
    short = parse_target(" 10.0.0.1 - 50 ")
    assert full == short
    assert full.is_range and full.text == "10.0.0.1-10.0.0.50"
    # ровно 50 адресов, ни одного лишнего
    assert full.num_addresses == 50
    assert _addrs(full) == {f"10.0.0.{i}" for i in range(1, 51)}


def test_range_that_is_a_subnet_becomes_cidr():
    s = parse_target("10.0.0.0-10.0.0.255")
    assert not s.is_range and s.text == "10.0.0.0/24"
    one = parse_target("10.0.0.7-10.0.0.7")
    assert not one.is_range and one.text == "10.0.0.7"


def test_range_across_octets_and_ipv6():
    s = parse_target("10.0.0.250-10.0.1.5")
    assert s.num_addresses == 12 and s.is_range
    v6 = parse_target("2001:db8::1-2001:db8::10")
    assert v6.num_addresses == 16
    assert all(n.version == 6 for n in v6.networks)


@pytest.mark.parametrize("bad", [
    "10.0.0.50-10.0.0.1",      # конец меньше начала
    "10.0.0.1-300",            # октет вне диапазона
    "10.0.0.1-2001:db8::1",    # разные версии
    "host-a",                  # имя хоста
    "example.com",
    "10.0.0.1-",
    "",
])
def test_invalid_specs(bad):
    with pytest.raises(ValueError):
        parse_target(bad)


def test_cidr_and_address_normalized():
    assert parse_target("10.0.0.7/24").text == "10.0.0.0/24"
    assert parse_target(" 10.0.0.5 ").text == "10.0.0.5/32"
    assert parse_range("10.0.0.1-3") == (ipaddress.ip_address("10.0.0.1"),
                                         ipaddress.ip_address("10.0.0.3"))


def test_plan_targets_expands_range_and_trims_to_allowlist():
    gate = AllowlistGate(["10.0.0.0/28"])            # .0–.15
    plan = plan_targets(gate, ["10.0.0.10-10.0.0.20", "10.0.0.12"])
    assert plan.allowed == [f"10.0.0.{i}" for i in range(10, 16)]
    assert [(d.target, d.reason, d.count) for d in plan.denied] == [
        ("10.0.0.10-10.0.0.20", "not_in_allowlist", 5)]


def test_plan_targets_range_limits():
    gate = AllowlistGate(["10.0.0.0/8"])
    plan = plan_targets(gate, ["10.0.0.1-10.0.10.1"], max_targets=100)
    assert plan.allowed == [] and plan.denied[0].reason == "too_many_targets"
    bad = plan_targets(gate, ["10.0.0.9-10.0.0.1"])
    assert bad.denied[0].reason == "not_an_ip"


def test_range_hosts_includes_edges():
    assert range_hosts(parse_target("10.0.0.0-10.0.0.3")) == [
        "10.0.0.0", "10.0.0.1", "10.0.0.2", "10.0.0.3"]
