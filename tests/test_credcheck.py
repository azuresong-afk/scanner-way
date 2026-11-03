"""Проверка входа по учётным записям активов: ядро (исходы входа) и API
(права, allowlist, лимит частоты, аудит без секретов)."""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from scanner.core import credcheck as cc
from scanner.core import sshexec, winexec
from scanner.core.credentials import HostCredential
from scanner.core.db import AuditLogRow
from scanner.core.reachability import PortResult
from tests.test_api import Api, Recorder, _make

HOST_PASSWORD = "Host-Pa55-do-not-leak"


def _cred(cid=1, name="аудит", protocol="ssh", port=22, targets=(), **kw) -> HostCredential:
    return HostCredential(id=cid, name=name, auth="password", username="audit",
                          port=port, targets=tuple(targets), password=HOST_PASSWORD,
                          protocol=protocol, **kw)


class Shell:
    closed = 0

    def close(self):
        Shell.closed += 1


def _conn(port_state="open", ssh=None, win=None) -> cc.Connectors:
    def ssh_connect(host, cred, opts):
        if ssh:
            raise ssh
        return Shell()

    def win_connect(host, cred, opts):
        if win:
            raise win
        return Shell()

    return cc.Connectors(ssh_options=sshexec.SshOptions(connect_timeout_sec=10),
                         win_options=winexec.WinRmOptions(connect_timeout_sec=10),
                         probe=lambda h, p, t: PortResult(p, port_state),
                         ssh_connect=ssh_connect, win_connect=win_connect)


# ---------- ядро ----------
def test_ssh_login_ok_closes_session():
    Shell.closed = 0
    r = cc.check_login("10.0.0.5", _cred(), _conn())
    assert r.status == cc.OK and Shell.closed == 1
    assert "вход выполнен" in r.message


@pytest.mark.parametrize("exc,status", [
    (sshexec.AuthFailed("учётные данные отклонены"), cc.AUTH_FAILED),
    (sshexec.HostKeyMismatch("ключ хоста изменился"), cc.HOST_KEY_MISMATCH),
    (sshexec.Unreachable("нет SSH-соединения: ConnectionRefusedError"), cc.UNREACHABLE),
    (sshexec.SshError("SSHException: Error reading SSH protocol banner"), cc.TIMEOUT),
    (sshexec.SshError("SSHException: Incompatible version"), cc.ERROR),
])
def test_ssh_outcomes(exc, status):
    r = cc.check_login("10.0.0.5", _cred(), _conn(ssh=exc))
    assert r.status == status
    assert HOST_PASSWORD not in r.message


def test_ssh_timeout_cause_is_timeout():
    try:
        try:
            raise TimeoutError("timed out")
        except TimeoutError as inner:
            raise sshexec.Unreachable("нет SSH-соединения: TimeoutError") from inner
    except sshexec.Unreachable as e:
        exc = e
    assert cc.check_login("10.0.0.5", _cred(), _conn(ssh=exc)).status == cc.TIMEOUT


@pytest.mark.parametrize("exc,status", [
    (winexec.AuthFailed("учётные данные отклонены"), cc.AUTH_FAILED),
    (winexec.CertMismatch("сертификат хоста изменился"), cc.HOST_KEY_MISMATCH),
    (winexec.Unreachable("нет WinRM-соединения: ConnectionError"), cc.UNREACHABLE),
    (winexec.WinRmError("WinRM ответил HTTP 500"), cc.ERROR),
])
def test_winrm_outcomes(exc, status):
    r = cc.check_login("10.0.0.10", _cred(protocol="winrm", port=5986), _conn(win=exc))
    assert r.status == status and r.message.startswith("WinRM")


def test_precheck_short_circuits_login():
    called = []
    c = _conn("closed")
    c.ssh_connect = lambda *a: called.append(a)
    assert cc.check_login("10.0.0.5", _cred(), c).status == cc.UNREACHABLE
    c.probe = lambda h, p, t: PortResult(p, "filtered")
    r = cc.check_login("10.0.0.5", _cred(), c)
    assert r.status == cc.TIMEOUT and "межсетевым" in r.message
    assert called == []                     # до входа дело не дошло


def test_bound_credentials_by_scope_and_protocol():
    creds = [_cred(1, "вся сеть"), _cred(2, "узкая", targets=["10.0.0.5/32"]),
             _cred(3, "чужая", targets=["10.0.1.0/24"]),
             _cred(4, "win", protocol="winrm", port=5986, targets=["10.0.0.0/24"])]
    assert [c.id for c in cc.bound_credentials("10.0.0.5", creds)] == [2, 1, 4]
    assert [c.id for c in cc.bound_credentials("10.0.1.7", creds)] == [3, 1]


def test_host_summary():
    c = _conn()
    r = cc.check_host_credentials("10.0.0.5", [], c)
    assert r.status == cc.NO_CREDENTIAL and "не привязана" in r.message
    r = cc.check_host_credentials("10.0.0.5", [_cred(1), _cred(2)], c)
    assert r.status == cc.OK and len(r.results) == 2

    def flaky(host, cred, opts):
        if cred.id == 2:
            raise sshexec.AuthFailed("x")
        return Shell()
    c.ssh_connect = flaky
    assert cc.check_host_credentials("10.0.0.5", [_cred(1), _cred(2)], c).status == cc.PARTIAL
    r = cc.check_host_credentials("10.0.0.5", [_cred(2)], c)
    assert r.status == cc.AUTH_FAILED and "отклонены" in r.message


# ---------- API ----------
class FakeCheck:
    def __init__(self):
        self.calls: list[tuple[str, list[int]]] = []

    def __call__(self, host, creds):
        self.calls.append((host, [c.id for c in creds]))
        conn = _conn(ssh=sshexec.AuthFailed("x") if host.endswith(".6") else None)
        return cc.check_host_credentials(host, creds, conn)


@pytest.fixture
def fake():
    return FakeCheck()


@pytest.fixture
def api(sqlite_factory, fake):
    from scanner.core.orchestrator import inline_executor
    app = _make(sqlite_factory, Recorder(), [], inline_executor())
    app.state.cred_check = fake
    with TestClient(app) as c:
        yield Api(c)


def _add_cred(api, eid, headers, **kw):
    body = {"name": "аудит", "username": "audit", "auth": "password",
            "password": HOST_PASSWORD, **kw}
    r = api.c.post(f"/engagements/{eid}/credentials", headers=headers, json=body)
    assert r.status_code == 201, r.text
    return r.json()["id"]


def _check(api, eid, headers, hosts, **kw):
    return api.c.post(f"/engagements/{eid}/credential-check", headers=headers,
                      json={"hosts": hosts, **kw})


def test_needs_run_scan_and_host_credentials(api):
    eid = api.engagement("10.0.0.0/24")
    for headers in (api.admin, api.user("op", "operator"),
                    api.user("keeper", "host_credentials")):
        assert _check(api, eid, headers, ["10.0.0.5"]).status_code == 403


def test_bulk_check_per_host_results(api, fake, sqlite_factory):
    eid = api.engagement("10.0.0.0/24")
    holder = api.user("keeper", "operator", "host_credentials")
    ssh = _add_cred(api, eid, holder, targets=["10.0.0.5", "10.0.0.6"])
    win = _add_cred(api, eid, holder, name="win", username="svc", protocol="winrm",
                    targets=["10.0.0.7"])
    r = _check(api, eid, holder, ["10.0.0.5", "10.0.0.6", "10.0.0.7", "10.0.0.8",
                                  "192.168.1.1", "10.0.0.5"])
    assert r.status_code == 200, r.text
    by = {h["host"]: h for h in r.json()["hosts"]}
    assert list(by) == ["10.0.0.5", "10.0.0.6", "10.0.0.7", "10.0.0.8", "192.168.1.1"]
    assert by["10.0.0.5"]["status"] == "ok"
    assert by["10.0.0.5"]["results"][0]["credential_id"] == ssh
    assert by["10.0.0.6"]["status"] == "auth_failed"
    assert by["10.0.0.7"]["status"] == "ok"
    assert by["10.0.0.7"]["results"][0]["protocol"] == "winrm"
    assert by["10.0.0.7"]["results"][0]["credential_id"] == win
    assert by["10.0.0.8"]["status"] == "no_credential"
    assert by["192.168.1.1"]["status"] == "not_in_allowlist"
    # вне allowlist — не трогали; повтор адреса — один раз
    assert sorted(h for h, _ in fake.calls) == ["10.0.0.5", "10.0.0.6", "10.0.0.7", "10.0.0.8"]
    assert HOST_PASSWORD not in r.text

    with sqlite_factory() as s:
        rows = list(s.execute(select(AuditLogRow.action, AuditLogRow.result,
                                     AuditLogRow.details)
                              .where(AuditLogRow.action == "credential_check")))
    assert sorted(r for _, r, _ in rows) == sorted(
        ["ok", "auth_failed", "ok", "no_credential", "not_in_allowlist"])
    assert HOST_PASSWORD not in repr(rows)


def test_only_selected_credentials(api, fake):
    eid = api.engagement("10.0.0.0/24")
    holder = api.user("keeper", "operator", "host_credentials")
    a = _add_cred(api, eid, holder)
    _add_cred(api, eid, holder, name="другая")
    r = _check(api, eid, holder, ["10.0.0.5"], credential_ids=[a])
    assert r.status_code == 200
    assert fake.calls == [("10.0.0.5", [a])]
    assert _check(api, eid, holder, ["10.0.0.5"], credential_ids=[999]).status_code == 404


def test_rejects_non_ip_and_too_many(api, fake):
    eid = api.engagement("10.0.0.0/24")
    holder = api.user("keeper", "operator", "host_credentials")
    assert _check(api, eid, holder, ["10.0.0.0/24"]).status_code == 422
    assert _check(api, eid, holder, ["db.local"]).status_code == 422
    assert _check(api, eid, holder, [f"10.0.0.{i}" for i in range(1, 18)]).status_code == 422
    assert fake.calls == []


def test_rate_limit_counts_hosts(api, fake):
    from scanner.core.reachability import CheckThrottle
    api.c.app.state.credcheck_throttle = CheckThrottle(limit=5, window=60)
    eid = api.engagement("10.0.0.0/24")
    holder = api.user("keeper", "operator", "host_credentials")
    hosts = [f"10.0.0.{i}" for i in range(1, 5)]
    assert _check(api, eid, holder, hosts).status_code == 200
    assert _check(api, eid, holder, hosts).status_code == 429     # 4 + 4 > 5
    assert _check(api, eid, holder, ["10.0.0.9"]).status_code == 200
    # адреса вне allowlist лимит не тратят
    assert _check(api, eid, holder, ["192.168.0.1"]).status_code == 200
