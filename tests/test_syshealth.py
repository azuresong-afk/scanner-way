"""Состояние самого сканера: компоненты, /system/health, /health/status, монитор,
уведомления system_health, `scanner health` и хелсчек узла-сканера."""
from __future__ import annotations

import json
from collections import namedtuple
from datetime import UTC, datetime, timedelta

from fastapi.testclient import TestClient

from scanner.api.main import create_app
from scanner.api.settings import ApiSettings
from scanner.core import syshealth as sh
from scanner.core.db import (
    Engagement,
    IntegrationChannelRow,
    NotificationLogRow,
    ScanNode,
    ScanRun,
)
from scanner.core.orchestrator import inline_executor
from scanner.integrations.events import SYSTEM_HEALTH, Event, Filters, route
from scanner.integrations.render import render_text
from scanner.integrations.syslog_cef import SyslogCefChannel
from scanner.reporting.remediation import RemediationResolver
from tests.test_api import PASSWORD, SECRET, Api

Usage = namedtuple("Usage", "total used free")
GB = 1024 ** 3


def _engines_all(**_kw):
    return {n: {"installed": True, "version": "1.0"} for n in sh.ENGINES}


def _ctx(factory, **kw) -> sh.HealthContext:
    kw.setdefault("engines", _engines_all)
    kw.setdefault("disk_paths", [])
    kw.setdefault("check_migrations", False)
    return sh.HealthContext(sessions=factory, **kw)


def _by_id(rep):
    return {c["id"]: c for c in rep["components"]}


# ---------------- отдельные проверки ----------------
def test_worst_and_titles():
    assert sh.worst(["ok", "warn", "ok"]) == "warn"
    assert sh.worst(["ok", "unknown"]) == "unknown"
    assert sh.worst(["warn", "error", "unknown"]) == "error"
    assert sh.worst([]) == "ok"


def test_engines_missing_required_is_error_optional_is_warn():
    info = {n: {"installed": True, "version": "7.9"} for n in sh.ENGINES}
    assert sh.check_engines(info).status == "ok"
    info["lynis"] = {"installed": False}
    c = sh.check_engines(info)
    assert c.status == "warn" and "lynis" in c.summary
    info["nmap"] = {"installed": False}
    c = sh.check_engines(info)
    assert c.status == "error" and "nmap" in c.summary and c.hint


def test_engine_probe_parses_versions(monkeypatch):
    class P:
        def __init__(self, out, err=""):
            self.stdout, self.stderr = out, err
    outs = {"nmap": P("Nmap version 7.94SVN ( https://nmap.org )\n"),
            "nuclei": P("", "[INF] Nuclei Engine Version: v3.2.4\n")}
    monkeypatch.setattr(sh.subprocess, "run",
                        lambda cmd, **kw: outs["nmap" if "nmap" in cmd[0] else "nuclei"])
    which = lambda n: f"/usr/bin/{n}"
    assert sh._probe_engine("nmap", ["nmap", "--version"], which)["version"] == "7.94SVN"
    assert sh._probe_engine("nuclei", ["nuclei", "-version"], which)["version"] == "3.2.4"
    assert sh._probe_engine("x", ["x"], lambda n: None) == {
        "installed": False, "version": None, "path": None}


def test_engine_info_is_cached():
    calls = []

    def probe(name, cmd):
        calls.append(name)
        return {"installed": True, "version": "1"}
    sh._engine_cache.clear()
    sh.engine_info(probe=probe)
    sh.engine_info(probe=probe)
    assert len(calls) == len(sh.ENGINES)
    sh.engine_info(probe=probe, refresh=True)
    assert len(calls) == 2 * len(sh.ENGINES)
    sh._engine_cache.clear()


def test_disk_thresholds():
    ok = sh.check_disk(["/a"], usage=lambda p: Usage(100 * GB, 50 * GB, 50 * GB))
    assert ok.status == "ok" and "50.0 ГБ" in ok.summary
    warn = sh.check_disk(["/a"], usage=lambda p: Usage(100 * GB, 92 * GB, 8 * GB))
    assert warn.status == "warn" and warn.hint
    err = sh.check_disk(["/a"], usage=lambda p: Usage(100 * GB, 99.5 * GB, GB // 2))
    assert err.status == "error"
    # один и тот же раздел под двумя путями — одна строка
    same = sh.check_disk(["/a", "/b"], usage=lambda p: Usage(100 * GB, 50 * GB, 50 * GB))
    assert len(same.items) == 1

    def boom(p):
        raise FileNotFoundError(p)
    assert sh.check_disk(["/nope"], usage=boom).status == "unknown"


def test_workers():
    assert sh.check_workers(None).status == "unknown"
    assert sh.check_workers({"runs": True, "scheduler": True}).status == "ok"
    c = sh.check_workers({"runs": True, "scheduler": False})
    assert c.status == "error" and "расписания" in c.summary


def test_runs_stuck_waiting_interrupted(sqlite_factory):
    now = datetime.now(UTC)
    with sqlite_factory.begin() as s:
        s.add(Engagement(id=1, name="E"))
        s.flush()
        s.add(ScanRun(id=1, engagement_id=1, modules=["vuln"], status="running",
                      heartbeat_at=now))
    with sqlite_factory() as s:
        assert sh.check_runs(s, stale_seconds=180).status == "ok"
    with sqlite_factory.begin() as s:
        s.add(ScanRun(id=2, engagement_id=1, modules=["vuln"], status="running",
                      heartbeat_at=now - timedelta(hours=2)))
        s.add(ScanRun(id=3, engagement_id=1, modules=["vuln"], status="pending",
                      created_at=now - timedelta(hours=3)))
        s.add(ScanRun(id=4, engagement_id=1, modules=["vuln"], status="interrupted",
                      finished_at=now - timedelta(hours=1)))
    with sqlite_factory() as s:
        c = sh.check_runs(s, stale_seconds=180, now=now)
    assert c.status == "warn"
    assert c.details["stuck"] == [2] and c.details["waiting_long"] == [3]
    assert c.details["interrupted_24h"] == 1 and "№2" in c.summary


def test_nodes_offline_is_warn(sqlite_factory):
    with sqlite_factory() as s:
        assert sh.check_nodes(s).summary == "сетевых узлов нет"
    now = datetime.now(UTC)
    with sqlite_factory.begin() as s:
        s.add(ScanNode(name="Казань", mode="online", scope=["10.0.0.0/24"],
                       last_seen_at=now))
        s.add(ScanNode(name="Омск", mode="online", scope=["10.1.0.0/24"],
                       last_seen_at=now - timedelta(hours=1)))
        s.add(ScanNode(name="Флешка", mode="offline", scope=["10.2.0.0/24"]))
    with sqlite_factory() as s:
        c = sh.check_nodes(s, now=now)
    assert c.status == "warn" and "Омск" in c.summary and "Флешка" not in c.summary
    assert "на связи 1 из 2" in c.summary


def test_notifications_failed_deliveries(sqlite_factory):
    with sqlite_factory() as s:
        assert sh.check_notifications(s).summary == "каналы не настроены"
    with sqlite_factory.begin() as s:
        ch = IntegrationChannelRow(name="Почта SOC", type="smtp", enabled=True,
                                   events=["run_finished"])
        s.add(ch)
        s.flush()
        s.add(NotificationLogRow(channel_id=ch.id, event="run_finished", status="sent"))
    with sqlite_factory() as s:
        assert sh.check_notifications(s).status == "ok"
    with sqlite_factory.begin() as s:
        s.add(NotificationLogRow(channel_id=1, event="run_finished", status="failed",
                                 last_error="535 auth failed"))
    with sqlite_factory() as s:
        c = sh.check_notifications(s)
    assert c.status == "warn" and "Почта SOC" in c.summary
    assert "535" not in json.dumps(c.items, ensure_ascii=False)   # текст ошибки не выносим


def test_collect_isolates_failing_check(sqlite_factory, monkeypatch):
    def boom(*a, **k):
        raise RuntimeError("feeds exploded")
    monkeypatch.setattr(sh, "check_feeds", boom)
    rep = sh.collect(_ctx(sqlite_factory, threads=lambda: {"runs": True}))
    comps = _by_id(rep)
    assert comps["feeds"]["status"] == "unknown"
    assert comps["database"]["status"] == "ok"
    assert comps["runs"]["status"] == "ok"
    assert set(comps) == set(sh.COMPONENT_TITLES)


def test_collect_db_down_skips_db_checks():
    from sqlalchemy import create_engine

    from scanner.core.db import make_session_factory
    engine = create_engine("postgresql+psycopg://u:p@127.0.0.1:1/x",
                           connect_args={"connect_timeout": 1})
    rep = sh.collect(_ctx(make_session_factory(engine)))
    comps = _by_id(rep)
    assert rep["status"] == "error" and comps["database"]["status"] == "error"
    for cid in ("runs", "feeds", "nodes", "notifications"):
        assert comps[cid]["status"] == "unknown"
    assert sh.brief(rep)["components"]["database"] == "error"


# ---------------- монитор и уведомления ----------------
def test_monitor_notifies_on_transitions_only(sqlite_factory):
    state = {"disk": Usage(100 * GB, 50 * GB, 50 * GB)}
    sent = []
    ctx = _ctx(sqlite_factory, threads=lambda: {"runs": True}, disk_paths=["/d"])
    mon = sh.HealthMonitor(ctx, tick_seconds=0,
                           notify=lambda *a: sent.append((a[0], a[2])))
    import scanner.core.syshealth as mod
    orig = mod.check_disk
    mod.check_disk = lambda paths: orig(paths, usage=lambda p: state["disk"])
    try:
        assert mon.tick() == [] and sent == []           # всё в порядке — тишина
        state["disk"] = Usage(100 * GB, 99.5 * GB, GB // 2)
        assert mon.tick() == [("disk", "ok", "error")]
        assert mon.tick() == []                          # без изменений — без повторов
        state["disk"] = Usage(100 * GB, 50 * GB, 50 * GB)
        assert mon.tick() == [("disk", "error", "ok")]
    finally:
        mod.check_disk = orig
    assert sent == [("disk", "error"), ("disk", "ok")]


def test_monitor_reports_problem_present_at_start(sqlite_factory):
    sent = []
    ctx = _ctx(sqlite_factory, threads=lambda: {"runs": False})
    mon = sh.HealthMonitor(ctx, tick_seconds=0, notify=lambda *a: sent.append(a[0]))
    assert ("workers", "ok", "error") in mon.tick()
    assert sent == ["workers"]


def test_system_health_event_routing_and_render():
    ev = Event(kind=SYSTEM_HEALTH, title="Место на диске", source="disk",
               health_status="error", message="/data: свободно 0.5 ГБ (0.5%)",
               hint="Освободите место")
    assert route(ev, ["system_health"], Filters(engagements=[5])) is ev   # без фильтров
    assert route(ev, ["run_finished"], Filters()) is None
    subject, body = render_text(ev)
    assert "не работает" in subject and "Освободите место" in body
    ok = Event(kind=SYSTEM_HEALTH, title="Место на диске", source="disk",
               health_status="ok", message="в порядке", hint="Освободите место")
    assert "снова в порядке" in render_text(ok)[0]
    assert "Что сделать" not in render_text(ok)[1]
    [(line, prio)] = SyslogCefChannel()._packets(ev)
    assert "system_health" in line and "cs5=error" in line and prio == 3


def test_dispatcher_system_health_dedup(sqlite_factory):
    from scanner.core.audit import DbAuditSink
    from scanner.integrations.dispatcher import Dispatcher
    with sqlite_factory.begin() as s:
        s.add(IntegrationChannelRow(name="SIEM", type="syslog_cef", enabled=True,
                                    config={"host": "127.0.0.1", "port": 514,
                                            "protocol": "udp"},
                                    events=["system_health"]))
        s.add(IntegrationChannelRow(name="Отчёты", type="syslog_cef", enabled=True,
                                    config={"host": "127.0.0.1", "port": 515,
                                            "protocol": "udp"},
                                    events=["run_finished"]))

    class NoExec:
        def submit(self, *a, **k):
            return None
    d = Dispatcher(sqlite_factory, DbAuditSink(sqlite_factory), executor=NoExec(),
                   tick_seconds=0, public_url="https://scanner.local/")
    d.notify_system_health("disk", "Место на диске", "error", "мало места", "почистить")
    d.notify_system_health("disk", "Место на диске", "error", "мало места", "почистить")
    d.notify_system_health("disk", "Место на диске", "ok", "в порядке", None)
    with sqlite_factory() as s:
        rows = list(s.query(NotificationLogRow).order_by(NotificationLogRow.id))
    assert [(r.channel_id, r.dedup_key) for r in rows] == [
        (1, "health:disk:error"), (1, "health:disk:ok")]
    assert rows[0].payload["link"] == "https://scanner.local/health"


# ---------------- API ----------------
def _app(factory, **kw):
    settings = ApiSettings(secret=SECRET, run_heartbeat_seconds=0, ready_check_migrations=False,
                           scheduler_tick_seconds=0, feeds_tick_seconds=0,
                           notify_tick_seconds=0, health_tick_seconds=0,
                           bootstrap_admin="root", bootstrap_password=PASSWORD, **kw)
    return create_app(session_factory=factory, settings=settings, registry={},
                      executor=inline_executor(),
                      resolver_factory=lambda f: RemediationResolver())


def test_api_system_health_requires_login_and_status_is_brief(sqlite_factory, monkeypatch):
    monkeypatch.setattr(sh, "engine_info", _engines_all)
    app = _app(sqlite_factory)
    app.state.health.ctx.engines = _engines_all
    app.state.health.ctx.disk_paths = []
    with TestClient(app) as c:
        assert c.get("/system/health").status_code == 401
        api = Api(c)
        h = api.user("viewer", "auditor")
        r = c.get("/system/health", headers=h)
        assert r.status_code == 200
        body = r.json()
        comps = _by_id(body)
        assert set(comps) == set(sh.COMPONENT_TITLES)
        assert comps["workers"]["status"] == "ok"       # tick=0 — «выключено», не сбой
        assert {i["id"] for i in comps["workers"]["items"]} >= {"runs", "health"}
        # пустая установка: обязательных справочников нет — это сбой, с подсказкой
        assert comps["feeds"]["status"] == "error" and comps["feeds"]["hint"]
        assert body["status"] == "error"
        # без входа — только статусы, без сводок и подсказок
        r = c.get("/health/status")
        assert r.status_code == 503
        brief = r.json()
        assert set(brief) == {"status", "checked_at", "components"}
        assert brief["components"]["database"] == "ok"
        assert "summary" not in json.dumps(brief)


def test_api_health_status_503_on_error(sqlite_factory):
    app = _app(sqlite_factory)
    app.state.health.ctx.engines = lambda **kw: {}      # nmap нет → error
    app.state.health.ctx.disk_paths = []
    with TestClient(app) as c:
        r = c.get("/health/status")
        assert r.status_code == 503 and r.json()["components"]["engines"] == "error"
        # /health/ready этим не затрагивается: контейнер не перезапускают из-за движка
        assert c.get("/health/ready").status_code == 200


def test_integrations_offer_system_health_event(sqlite_factory):
    with TestClient(_app(sqlite_factory)) as c:
        api = Api(c)
        r = c.get("/integrations/types", headers=api.admin)
        assert r.status_code == 200
        kinds = {k["type"]: k for k in r.json()}
        assert "system_health" in kinds["telegram"]["events"]
        assert "system_health" not in kinds["jira"]["events"]


# ---------------- CLI и узел ----------------
def test_cli_health_json(tmp_path, capsys, monkeypatch):
    from scanner import cli
    monkeypatch.setattr(sh, "engine_info", _engines_all)
    monkeypatch.setattr(sh, "default_disk_paths", lambda: [str(tmp_path)])
    db = tmp_path / "h.db"
    from sqlalchemy import create_engine

    from scanner.core.db import Base
    eng = create_engine(f"sqlite:///{db}")
    Base.metadata.create_all(eng)
    eng.dispose()
    # без разметки Alembic в SQLite схема считается неразмеченной → сбой БД, код 1
    rc = cli.main(["--db-url", f"sqlite:///{db}", "health", "--json"])
    rep = json.loads(capsys.readouterr().out)
    assert rc == 1 and _by_id(rep)["database"]["status"] == "error"
    assert _by_id(rep)["workers"]["status"] == "unknown"


def test_node_health_file(tmp_path):
    from scanner.nodes.agent import check_health, write_health
    f = tmp_path / "health.json"
    ok, msg = check_health(f)
    assert not ok and "ни разу" in msg
    write_health(f, ok=False, error="connect refused", now=1000.0)
    ok, msg = check_health(f, now=1001.0)
    assert not ok and "connect refused" in msg
    write_health(f, ok=True, now=2000.0)
    assert check_health(f, now=2100.0)[0]
    write_health(f, ok=False, error="timeout", now=2500.0)
    assert check_health(f, now=2550.0)[0]               # недавно была связь — в порядке
    ok, msg = check_health(f, now=2000.0 + 3600)
    assert not ok and "60 мин" in msg and "timeout" in msg
    assert check_health(None)[0]


def test_node_cli_health(tmp_path, monkeypatch, capsys):
    from scanner import cli
    from scanner.nodes.agent import write_health
    f = tmp_path / "h.json"
    monkeypatch.setenv("SCANNER_NODE_HEALTH_FILE", str(f))
    assert cli.main(["node", "health"]) == 1
    write_health(f, ok=True)
    assert cli.main(["node", "health"]) == 0
    assert "OK" in capsys.readouterr().out
