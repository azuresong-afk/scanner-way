"""Проверка доступности хоста: пробы, лимит, API (allowlist, роли, аудит)."""
from __future__ import annotations

import errno

import pytest
from fastapi.testclient import TestClient

from scanner.core import reachability as reach
from scanner.core.reachability import (
    CheckThrottle,
    PingResult,
    PortResult,
    check_host,
)
from tests.test_api import Api, Recorder, _make


# ---------- ядро ----------
def test_closed_port_means_host_is_up():
    r = check_host("10.0.0.5", [22, 80],
                   ping=lambda t, to: PingResult(available=True, alive=False),
                   probe=lambda t, p, to: PortResult(p, "closed" if p == 22 else "filtered"))
    assert r.reachable and r.methods == ["tcp"]


def test_nothing_answers_means_unreachable():
    r = check_host("10.0.0.5", [22],
                   ping=lambda t, to: PingResult(available=False),
                   probe=lambda t, p, to: PortResult(p, "filtered"))
    assert not r.reachable and r.methods == []


def test_icmp_alone_is_enough():
    r = check_host("10.0.0.5", [443],
                   ping=lambda t, to: PingResult(True, True, 0.4),
                   probe=lambda t, p, to: PortResult(p, "filtered"))
    assert r.reachable and r.methods == ["icmp"]


def test_tcp_probe_maps_errno(monkeypatch):
    class Sock:
        code = 0

        def __init__(self, *a):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def settimeout(self, t):
            pass

        def connect_ex(self, addr):
            return Sock.code

    monkeypatch.setattr(reach.socket, "socket", Sock)
    assert reach.tcp_probe("10.0.0.5", 22).state == "open"
    Sock.code = errno.ECONNREFUSED
    assert reach.tcp_probe("10.0.0.5", 22).state == "closed"
    Sock.code = errno.ETIMEDOUT
    assert reach.tcp_probe("10.0.0.5", 22).state == "filtered"


def test_system_ping_parses_rtt(monkeypatch):
    class Proc:
        returncode = 0
        stdout = "64 bytes from 10.0.0.5: icmp_seq=1 ttl=64 time=0.351 ms"

    seen = {}
    monkeypatch.setattr(reach.shutil, "which", lambda b: "/bin/ping")
    monkeypatch.setattr(reach.subprocess, "run",
                        lambda cmd, **kw: seen.setdefault("cmd", cmd) and Proc())
    r = reach.system_ping("10.0.0.5")
    assert r.alive and r.rtt_ms == pytest.approx(0.351)
    assert seen["cmd"][-1] == "10.0.0.5" and "-c" in seen["cmd"]


def test_system_ping_missing_binary(monkeypatch):
    monkeypatch.setattr(reach.shutil, "which", lambda b: None)
    assert reach.system_ping("10.0.0.5") == PingResult(available=False)


def test_throttle_sliding_window():
    now = [0.0]
    t = CheckThrottle(limit=2, window=60, clock=lambda: now[0])
    assert t.allow("a") and t.allow("a") and not t.allow("a")
    assert t.allow("b")                    # лимит — на пользователя
    now[0] = 60.0
    assert t.allow("a")


# ---------- API ----------
class FakeCheck:
    def __init__(self):
        self.calls: list[tuple[str, list[int]]] = []

    def __call__(self, host, ports):
        self.calls.append((host, ports))
        return check_host(host, ports,
                          ping=lambda t, to: PingResult(True, True, 1.2),
                          probe=lambda t, p, to: PortResult(p, "open" if p == 22 else "filtered"))


@pytest.fixture
def fake():
    return FakeCheck()


@pytest.fixture
def api(sqlite_factory, fake):
    from scanner.core.orchestrator import inline_executor
    app = _make(sqlite_factory, Recorder(), [], inline_executor())
    app.state.reach_check = fake
    with TestClient(app) as c:
        yield Api(c)


def _check(api, eid, headers, target, **kw):
    return api.c.post(f"/engagements/{eid}/reachability", headers=headers,
                      json={"target": target, **kw})


def _reach_audit(api, sqlite_factory):
    return [e for e in api.audit(sqlite_factory) if e[1] == "reachability_check"]


def test_operator_checks_allowlisted_host(api, sqlite_factory, fake):
    eid = api.engagement("10.0.0.0/24")
    op = api.user("op", "operator")
    r = _check(api, eid, op, "10.0.0.5")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["reachable"] and body["methods"] == ["icmp", "tcp"]
    assert body["icmp_rtt_ms"] == 1.2
    assert {p["port"]: p["state"] for p in body["ports"]}[22] == "open"
    assert fake.calls == [("10.0.0.5", [22, 80, 443, 445, 3389])]
    assert _reach_audit(api, sqlite_factory) == [
        ("user:op", "reachability_check", f"engagement:{eid}", "reachable")]


def test_custom_ports_deduplicated(api, fake):
    eid = api.engagement("10.0.0.0/24")
    op = api.user("op", "operator")
    assert _check(api, eid, op, "10.0.0.5", ports=[8080, 22, 8080]).status_code == 200
    assert fake.calls[-1][1] == [22, 8080]
    assert _check(api, eid, op, "10.0.0.5", ports=[70000]).status_code == 422


@pytest.mark.parametrize("target,result", [
    ("10.9.9.9", "rejected_not_in_allowlist"),
    ("10.0.0.0/24", "rejected_not_an_ip"),
    ("intranet.local", "rejected_not_an_ip"),
])
def test_rejected_targets_never_probed(api, sqlite_factory, fake, target, result):
    eid = api.engagement("10.0.0.0/24")
    op = api.user("op", "operator")
    r = _check(api, eid, op, target)
    assert r.status_code == 422
    assert fake.calls == []
    assert _reach_audit(api, sqlite_factory) == [
        ("user:op", "reachability_check", f"engagement:{eid}", result)]


def test_empty_allowlist_denies_everything(api, fake):
    eid = api.engagement()
    op = api.user("op", "operator")
    assert _check(api, eid, op, "10.0.0.5").status_code == 422
    assert fake.calls == []


@pytest.mark.parametrize("role", ["admin", "auditor"])
def test_roles_without_run_scan_are_denied(api, sqlite_factory, fake, role):
    eid = api.engagement("10.0.0.0/24")
    headers = api.admin if role == "admin" else api.user("aud", "auditor")
    r = _check(api, eid, headers, "10.0.0.5")
    assert r.status_code == 403
    assert fake.calls == []
    assert any(e[1] == "access_denied" for e in api.audit(sqlite_factory))


def test_rate_limited_per_user(api, sqlite_factory, fake):
    eid = api.engagement("10.0.0.0/24")
    op = api.user("op", "operator")
    api.c.app.state.reach_throttle = CheckThrottle(limit=2, window=60)
    assert _check(api, eid, op, "10.0.0.5").status_code == 200
    assert _check(api, eid, op, "10.0.0.6").status_code == 200
    assert _check(api, eid, op, "10.0.0.7").status_code == 429
    assert len(fake.calls) == 2
    assert _reach_audit(api, sqlite_factory)[-1][3] == "rate_limited"


def test_unknown_engagement(api):
    op = api.user("op", "operator")
    assert _check(api, 999, op, "10.0.0.5").status_code == 404
