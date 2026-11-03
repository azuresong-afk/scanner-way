"""Проверка сетевой доступности (вкладка «Доступность»): запись портов, команда
nmap, разбор XML, фоновое задание, API (allowlist, права, лимиты, аудит),
занесение живых хостов в «Активы»."""
from __future__ import annotations

import threading

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from scanner.core import netscan, portspec
from scanner.core.db import AssetRow
from scanner.core.netscan import ScanOptions, build_command, parse_xml
from scanner.core.orchestrator import inline_executor
from scanner.core.ratelimit import get_profile
from scanner.core.reachability import CheckThrottle
from tests.test_api import Api, DeferredExecutor, Recorder, _make


# ---------- запись портов ----------
@pytest.mark.parametrize("text,expected", [
    ("22, 80,443", [(22, 22), (80, 80), (443, 443)]),
    ("8000-8100", [(8000, 8100)]),
    ("8000 - 8100; 22", [(22, 22), (8000, 8100)]),
    ("8000–8100", [(8000, 8100)]),                 # длинное тире
    ("80 81 82 1-79", [(1, 82)]),                   # слияние соседних
    ("", []),
])
def test_parse_ports(text, expected):
    assert portspec.parse_ports(text) == expected


@pytest.mark.parametrize("text", ["0", "65536", "80-22", "ssh", "U:53", "-p", "1-2-3", "22,--script"])
def test_parse_ports_rejects(text):
    with pytest.raises(portspec.PortSpecError):
        portspec.parse_ports(text)


def test_subtract_and_text():
    r = portspec.subtract([(1, 100)], [(10, 20), (50, 50), (95, 200)])
    assert r == [(1, 9), (21, 49), (51, 94)]
    assert portspec.to_text(r) == "1-9,21-49,51-94"
    assert portspec.count(r) == 9 + 29 + 44
    assert portspec.subtract([(22, 22)], [(22, 22)]) == []


# ---------- команда nmap ----------
def test_command_top_ports_with_exclusions():
    cmd = build_command(["10.0.0.5"], get_profile("gentle"),
                        ScanOptions(exclude="9100,8000-8100"))
    assert cmd[:2] == ["nmap", "-n"]
    assert cmd[cmd.index("--top-ports") + 1] == "1000"
    assert cmd[cmd.index("--exclude-ports") + 1] == "9100,8000-8100"
    assert "-p" not in cmd and "-Pn" not in cmd and "-sV" not in cmd
    assert cmd[cmd.index("--max-rate") + 1] == "5"
    assert cmd[-1] == "10.0.0.5" and cmd[-3:-1] == ["-oX", "-"]
    assert "-O" not in cmd                        # без определения ОС — быстро


def test_command_port_list_no_ping_services():
    cmd = build_command(["10.0.0.5", "10.0.0.6"], get_profile("normal"),
                        ScanOptions(mode="list", ports="22,80,8000-8100", no_ping=True,
                                    service_detection=True))
    assert cmd[cmd.index("-p") + 1] == "22,80,8000-8100"
    assert "--top-ports" not in cmd and "-Pn" in cmd and "-sV" in cmd
    assert cmd[-2:] == ["10.0.0.5", "10.0.0.6"]


XML = """<?xml version="1.0"?>
<nmaprun scanner="nmap" args="nmap" start="1" version="7.94" xmloutputversion="1.05">
<host><status state="up" reason="syn-ack"/>
<address addr="10.0.0.5" addrtype="ipv4"/>
<hostnames><hostname name="web01.local" type="PTR"/></hostnames>
<ports>
<port protocol="tcp" portid="22"><state state="open" reason="syn-ack"/><service name="ssh" product="OpenSSH" version="9.2p1"/></port>
<port protocol="tcp" portid="443"><state state="open" reason="syn-ack"/><service name="https"/></port>
<port protocol="tcp" portid="25"><state state="closed" reason="reset"/><service name="smtp"/></port>
</ports></host>
<host><status state="up" reason="user-set"/>
<address addr="10.0.0.7" addrtype="ipv4"/>
<ports></ports></host>
<host><status state="up" reason="echo-reply"/>
<address addr="10.0.0.8" addrtype="ipv4"/>
<ports></ports></host>
<runstats><finished time="2"/><hosts up="3" down="1" total="4"/></runstats>
</nmaprun>"""


def test_parse_xml():
    res = {r.host: r for r in parse_xml(XML, ["10.0.0.5", "10.0.0.6", "10.0.0.7", "10.0.0.8"])}
    web = res["10.0.0.5"]
    assert web.up and web.hostname == "web01.local" and web.reason == "syn-ack"
    assert [(p.port, p.service, p.product) for p in web.ports] == [
        (22, "ssh", "OpenSSH"), (443, "https", None)]           # закрытый 25 — не в списке
    assert not res["10.0.0.6"].up                                # nmap не вывел — недоступен
    assert not res["10.0.0.7"].up                                # -Pn без открытых портов
    assert res["10.0.0.8"].up and res["10.0.0.8"].ports == []    # ответил на ping


def test_parse_xml_garbage():
    with pytest.raises(netscan.NetScanError):
        parse_xml("not xml", ["10.0.0.5"])


# ---------- API ----------
class FakeNmap:
    def __init__(self, xml: str = XML, error: Exception | None = None):
        self.xml, self.error = xml, error
        self.calls: list[list[str]] = []

    def __call__(self, cmd, timeout, stop):
        self.calls.append(cmd)
        if self.error:
            raise self.error
        return self.xml


def _client(sqlite_factory, nmap, executor=None):
    app = _make(sqlite_factory, Recorder(), [], inline_executor())
    svc = app.state.portscans
    svc.runner = nmap
    svc.executor.shutdown(wait=False)
    svc.executor, svc._own = executor or inline_executor(), False
    return TestClient(app)


@pytest.fixture
def nmap():
    return FakeNmap()


@pytest.fixture
def api(sqlite_factory, nmap):
    with _client(sqlite_factory, nmap) as c:
        yield Api(c)


def _start(api, eid, headers, targets, **kw):
    return api.c.post(f"/engagements/{eid}/port-scans", headers=headers,
                      json={"targets": targets, **kw})


def _audit(api, sqlite_factory, action="port_scan"):
    return [e for e in api.audit(sqlite_factory) if e[1] == action]


def test_scan_range_registers_live_hosts_as_assets(api, sqlite_factory, nmap):
    eid = api.engagement("10.0.0.0/24")
    op = api.user("op", "operator")
    r = _start(api, eid, op, ["10.0.0.5-8"], exclude_ports="9100, 8000-8100")
    assert r.status_code == 202, r.text
    body = r.json()
    assert body["hosts_total"] == 4 and body["port_count"] == 1000
    assert body["exclude_ports"] == "8000-8100,9100"
    cmd = nmap.calls[0]
    assert cmd[-4:] == ["10.0.0.5", "10.0.0.6", "10.0.0.7", "10.0.0.8"]
    assert cmd[cmd.index("--exclude-ports") + 1] == "8000-8100,9100"

    d = api.c.get(f"/port-scans/{body['id']}", headers=op).json()
    assert d["status"] == "done" and d["hosts_done"] == 4
    assert d["hosts_up"] == 2 and d["open_ports"] == 2 and d["assets_created"] == 2
    up = {h["host"]: [p["port"] for p in h["ports"]] for h in d["results"] if h["up"]}
    assert up == {"10.0.0.5": [22, 443], "10.0.0.8": []}

    with sqlite_factory() as s:
        assets = {a.address: a.hostname for a in s.scalars(select(AssetRow))}
    assert assets == {"10.0.0.5": "web01.local", "10.0.0.8": None}
    results = [e[3] for e in _audit(api, sqlite_factory)]
    assert results == ["queued", "done"]
    assert [e[3] for e in _audit(api, sqlite_factory, "nmap_exec")] == ["started", "ok"]

    # повтор — активы не дублируются, существующие не трогаются
    assert _start(api, eid, op, ["10.0.0.5"]).status_code == 202
    with sqlite_factory() as s:
        assert len(list(s.scalars(select(AssetRow)))) == 2


def test_port_list_minus_exclusions(api, nmap):
    eid = api.engagement("10.0.0.0/24")
    op = api.user("op", "operator")
    r = _start(api, eid, op, ["10.0.0.5"], port_mode="list", ports="20-25, 80",
               exclude_ports="23", no_ping=True, service_detection=True)
    assert r.status_code == 202, r.text
    assert r.json()["ports"] == "20-25,80" and r.json()["port_count"] == 6
    cmd = nmap.calls[0]
    assert cmd[cmd.index("-p") + 1] == "20-25,80"
    assert cmd[cmd.index("--exclude-ports") + 1] == "23"
    assert "-Pn" in cmd and "-sV" in cmd


@pytest.mark.parametrize("kw,msg", [
    ({"port_mode": "list"}, "укажите порты"),
    ({"port_mode": "list", "ports": "22", "exclude_ports": "1-100"}, "не осталось"),
    ({"ports": "22,--script=x", "port_mode": "list"}, "не порт"),
    ({"exclude_ports": "70000"}, "вне диапазона"),
])
def test_bad_ports_rejected(api, sqlite_factory, nmap, kw, msg):
    eid = api.engagement("10.0.0.0/24")
    op = api.user("op", "operator")
    r = _start(api, eid, op, ["10.0.0.5"], **kw)
    assert r.status_code == 422 and msg in r.text
    assert nmap.calls == []
    assert _audit(api, sqlite_factory)[-1][3] == "rejected_bad_ports"


def test_outside_allowlist_never_scanned(api, sqlite_factory, nmap):
    eid = api.engagement("10.0.0.0/24")
    op = api.user("op", "operator")
    for targets in (["10.9.9.9"], ["intranet.local"]):
        r = _start(api, eid, op, targets)
        assert r.status_code == 422
    assert nmap.calls == []
    assert {e[3] for e in _audit(api, sqlite_factory)} == {"rejected_not_in_allowlist"}
    # подсеть, частично вне allowlist — урезается до разрешённой части
    r = _start(api, eid, op, ["10.0.0.252/30", "10.0.1.1"])
    assert r.status_code == 202
    assert r.json()["hosts_total"] == 2
    assert {d["reason"] for d in r.json()["denied_targets"]} == {"not_in_allowlist"}
    assert nmap.calls[0][-2:] == ["10.0.0.253", "10.0.0.254"]


def test_too_many_targets(api, nmap):
    eid = api.engagement("10.0.0.0/8")
    op = api.user("op", "operator")
    r = _start(api, eid, op, ["10.0.0.0/16"])
    assert r.status_code == 422
    assert r.json()["detail"] == "no target passed the engagement allowlist"
    assert nmap.calls == []


@pytest.mark.parametrize("role", ["admin", "auditor"])
def test_roles_without_run_scan_cannot_start(api, nmap, role):
    eid = api.engagement("10.0.0.0/24")
    headers = api.admin if role == "admin" else api.user("aud", "auditor")
    assert _start(api, eid, headers, ["10.0.0.5"]).status_code == 403
    assert nmap.calls == []


def test_auditor_can_view_results(api, nmap):
    eid = api.engagement("10.0.0.0/24")
    op = api.user("op", "operator")
    sid = _start(api, eid, op, ["10.0.0.5"]).json()["id"]
    aud = api.user("aud", "auditor")
    lst = api.c.get(f"/engagements/{eid}/port-scans", headers=aud)
    assert lst.status_code == 200 and [x["id"] for x in lst.json()] == [sid]
    assert "results" not in lst.json()[0]
    assert api.c.get(f"/port-scans/{sid}", headers=aud).status_code == 200
    assert api.c.post(f"/port-scans/{sid}/stop", headers=aud).status_code == 403


def test_rate_limited_per_user(api, sqlite_factory, nmap):
    eid = api.engagement("10.0.0.0/24")
    op = api.user("op", "operator")
    api.c.app.state.portscan_throttle = CheckThrottle(limit=1, window=60)
    assert _start(api, eid, op, ["10.0.0.5"]).status_code == 202
    assert _start(api, eid, op, ["10.0.0.6"]).status_code == 429
    assert len(nmap.calls) == 1
    assert _audit(api, sqlite_factory)[-1][3] == "rate_limited"


def test_nmap_error_fails_scan(sqlite_factory):
    nmap = FakeNmap(error=netscan.NetScanError("nmap rc=1: boom"))
    with _client(sqlite_factory, nmap) as c:
        api = Api(c)
        eid = api.engagement("10.0.0.0/24")
        op = api.user("op", "operator")
        sid = _start(api, eid, op, ["10.0.0.5"]).json()["id"]
        d = c.get(f"/port-scans/{sid}", headers=op).json()
        assert d["status"] == "failed" and "boom" in d["error"]


def test_stop_queued_and_concurrency_limit(sqlite_factory, nmap):
    deferred = DeferredExecutor()
    with _client(sqlite_factory, nmap, deferred) as c:
        api = Api(c)
        eid = api.engagement("10.0.0.0/24")
        op = api.user("op", "operator")
        a = _start(api, eid, op, ["10.0.0.5"]).json()["id"]
        _start(api, eid, op, ["10.0.0.6"])
        r = _start(api, eid, op, ["10.0.0.7"])          # уже 2 активных
        assert r.status_code == 429 and "in progress" in r.text
        assert c.post(f"/port-scans/{a}/stop", headers=op).status_code == 200
        deferred.run_all()
        assert c.get(f"/port-scans/{a}", headers=op).json()["status"] == "stopped"
        assert len(nmap.calls) == 1                      # второй отработал, первый — нет
        assert c.post(f"/port-scans/{a}/stop", headers=op).status_code == 409


def test_allowlist_rechecked_before_batch(sqlite_factory, nmap):
    deferred = DeferredExecutor()
    with _client(sqlite_factory, nmap, deferred) as c:
        api = Api(c)
        eid = api.engagement("10.0.0.0/24")
        op = api.user("op", "operator")
        sid = _start(api, eid, op, ["10.0.0.5"]).json()["id"]
        entry = c.get(f"/engagements/{eid}/allowlist", headers=api.admin).json()[0]
        c.delete(f"/engagements/{eid}/allowlist/{entry['id']}", headers=api.admin)
        deferred.run_all()
        assert nmap.calls == []
        d = c.get(f"/port-scans/{sid}", headers=op).json()
        assert d["status"] == "done" and d["results"][0]["reason"] == "not_in_allowlist"


def test_recover_marks_interrupted(sqlite_factory, nmap):
    with _client(sqlite_factory, nmap, DeferredExecutor()) as c:
        api = Api(c)
        eid = api.engagement("10.0.0.0/24")
        op = api.user("op", "operator")
        sid = _start(api, eid, op, ["10.0.0.5"]).json()["id"]
        assert c.app.state.portscans.recover() == [sid]
        d = c.get(f"/port-scans/{sid}", headers=op).json()
        assert d["status"] == "interrupted" and "перезапущена" in d["error"]


def test_subprocess_runner_stops(monkeypatch):
    class Proc:
        returncode = None
        killed = False

        def __init__(self, *a, **kw):
            self.ev = threading.Event()

        def communicate(self):
            self.ev.wait(5)
            return "", ""

        def kill(self):
            Proc.killed = True
            self.ev.set()

    monkeypatch.setattr(netscan.subprocess, "Popen", Proc)
    stop = threading.Event()
    stop.set()
    with pytest.raises(netscan.Stopped):
        netscan.subprocess_runner(["nmap"], 60, stop)
    assert Proc.killed
