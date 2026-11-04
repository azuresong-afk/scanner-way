"""Прогресс идущего прогона (миграция 0023) — для плашки в шапке интерфейса:
«Прогон №131 идёт · этап · 27 из 42 хостов · 63%»."""
from __future__ import annotations

from scanner.core import coverage as cv
from scanner.core import repository as repo
from scanner.core.audit import DbAuditSink
from scanner.core.db import ScanRun, session_scope
from scanner.core.models import Finding
from scanner.core.orchestrator import (
    STAGE_SAVING,
    RunProgress,
    RunService,
    inline_executor,
)
from scanner.modules.base import ScanContext, ScanModule

SNAPS: list[tuple[int, dict, dict | None]] = []


def _stored(factory, run_id):
    with session_scope(factory) as s:
        return s.get(ScanRun, run_id).progress


def test_tracker_counts_hosts_per_stage_and_overall_percent():
    snaps: list[dict] = []
    t = RunProgress(snaps.append, ["discovery", "auth_inventory"], 4, min_interval=0)
    t.begin("discovery")
    assert {k: v for k, v in snaps[-1].items()
            if k not in ("updated_at", "elapsed_seconds", "eta_seconds")} == {
        "stage": "discovery", "stage_index": 1, "stages": 2, "hosts_done": 0,
        "hosts_total": 4, "percent": 0, "stage_seconds": {}}
    t.mark("10.0.0.1", "discovery")
    t.mark("10.0.0.1", "discovery")          # повторная отметка не считается
    t.mark("10.0.0.2", "other")              # чужой модуль не считается
    assert snaps[-1]["hosts_done"] == 1 and snaps[-1]["percent"] == 12
    t.end_stage(["10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4"])
    assert snaps[-1]["hosts_done"] == 4 and snaps[-1]["percent"] == 50
    t.begin("auth_inventory")
    for h in ("10.0.0.1", "10.0.0.2", "10.0.0.3"):
        t.mark(h, "auth_inventory")
    assert snaps[-1]["stage_index"] == 2 and snaps[-1]["hosts_done"] == 3
    assert snaps[-1]["percent"] == 87
    t.end_stage(["10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4"])
    assert snaps[-1]["percent"] == 99          # 100 — только когда прогон завершён
    t.saving()
    assert snaps[-1]["stage"] == STAGE_SAVING and snaps[-1]["percent"] == 99


def test_tracker_throttles_host_marks_but_not_stage_changes():
    snaps: list[dict] = []
    now = [0.0]
    t = RunProgress(snaps.append, ["discovery"], 3, min_interval=2, clock=lambda: now[0])
    t.begin("discovery")
    t.mark("10.0.0.1", "discovery")
    t.mark("10.0.0.2", "discovery")
    assert len(snaps) == 1                     # обе отметки в пределах 2 с
    now[0] = 3.0
    t.mark("10.0.0.3", "discovery")
    assert len(snaps) == 2 and snaps[-1]["hosts_done"] == 3
    t.end_stage(["10.0.0.1"])
    assert len(snaps) == 3


def test_tracker_sink_failure_is_swallowed():
    def boom(_):
        raise RuntimeError("db down")
    t = RunProgress(boom, ["discovery"], 1, min_interval=0)
    t.begin("discovery")
    t.mark("10.0.0.1", "discovery")


class Probe(ScanModule):
    """Отмечает хосты по одному и запоминает, что видно в БД в этот момент."""
    name = "discovery"
    factory = None
    run_id = None

    def run(self, ctx: ScanContext) -> list[Finding]:
        for h in ctx.targets:
            ctx.coverage.mark(h, self.name, cv.COMPLETED)
            SNAPS.append((len(SNAPS), _stored(Probe.factory, Probe.run_id) or {}, None))
        return []


class Second(ScanModule):
    name = "vuln"

    def run(self, ctx: ScanContext) -> list[Finding]:
        SNAPS.append((len(SNAPS), _stored(Probe.factory, Probe.run_id) or {}, None))
        return []


def test_run_stores_progress_while_running(sqlite_factory):
    SNAPS.clear()
    svc = RunService(sqlite_factory, DbAuditSink(sqlite_factory),
                     registry={"discovery": Probe, "vuln": Second},
                     executor=inline_executor(), vault=None, heartbeat_seconds=0)
    with session_scope(sqlite_factory) as s:
        eid = repo.create_engagement(s, name="ООО Ромашка")
        repo.add_allowlist_entry(s, engagement_id=eid, cidr="10.0.0.0/24")
        run_id = repo.create_scan_run(s, engagement_id=eid, modules=["discovery", "vuln"],
                                      targets=["10.0.0.1", "10.0.0.2"])
    Probe.factory, Probe.run_id = sqlite_factory, run_id
    assert _stored(sqlite_factory, run_id) is None        # в очереди — прогресса нет
    svc.execute(run_id, ["10.0.0.1", "10.0.0.2"])
    first = SNAPS[0][1]
    assert first["stage"] == "discovery" and first["hosts_total"] == 2
    assert first["stage_index"] == 1 and first["stages"] == 2
    second = SNAPS[-1][1]
    assert second["stage"] == "vuln" and second["stage_index"] == 2
    assert second["percent"] == 50 and second["hosts_done"] == 0
    with session_scope(sqlite_factory) as s:
        run = s.get(ScanRun, run_id)
        assert run.status in {"done", "partial"}
        assert run.progress["stage"] == STAGE_SAVING          # последний снимок


def test_eta_uses_live_stage_speed_and_history_for_next_stages():
    snaps: list[dict] = []
    now = [0.0]
    t = RunProgress(snaps.append, ["discovery", "auth_inventory"], 10, min_interval=0,
                    clock=lambda: now[0], history={"auth_inventory": 6.0})
    t.begin("discovery")
    assert snaps[-1]["eta_seconds"] is None or snaps[-1]["eta_seconds"] >= 60
    now[0] = 20.0
    for i in range(5):                          # 5 из 10 хостов за 20 с → ещё 20 с
        t.mark(f"10.0.0.{i}", "discovery")
    # + следующий этап по истории: 6 с/хост × 10 хостов = 60 с
    assert snaps[-1]["eta_seconds"] == 80
    assert snaps[-1]["elapsed_seconds"] == 20
    now[0] = 40.0
    t.end_stage([f"10.0.0.{i}" for i in range(10)])
    assert snaps[-1]["stage_seconds"] == {"discovery": 40.0}
    assert snaps[-1]["eta_seconds"] == 60
    t.begin("auth_inventory")
    now[0] = 70.0
    for i in range(5):                          # своя скорость: 30 с на 5 хостов
        t.mark(f"10.0.0.{i}", "auth_inventory")
    assert snaps[-1]["eta_seconds"] == 30
    t.saving()
    assert snaps[-1]["eta_seconds"] is None


def test_eta_without_history_uses_this_runs_stage_speed():
    snaps: list[dict] = []
    now = [0.0]
    t = RunProgress(snaps.append, ["discovery", "vuln"], 4, min_interval=0, clock=lambda: now[0])
    t.begin("discovery")
    now[0] = 8.0
    t.end_stage(["a", "b", "c", "d"])           # 2 с/хост — так же оцениваем vuln
    assert snaps[-1]["eta_seconds"] == 8


def test_stage_history_takes_newest_per_module():
    from scanner.core.orchestrator import stage_history
    rows = [{"hosts_total": 10, "stage_seconds": {"vuln": 50}},
            None,
            {"hosts_total": 5, "stage_seconds": {"vuln": 100, "discovery": 10}},
            {"hosts_total": 0, "stage_seconds": {"config_audit": 10}}]
    assert stage_history(rows) == {"vuln": 5.0, "discovery": 2.0}


def test_next_run_gets_history_from_previous_run(sqlite_factory):
    SNAPS.clear()
    svc = RunService(sqlite_factory, DbAuditSink(sqlite_factory),
                     registry={"discovery": Probe, "vuln": Second},
                     executor=inline_executor(), vault=None, heartbeat_seconds=0)
    with session_scope(sqlite_factory) as s:
        eid = repo.create_engagement(s, name="ООО Ромашка")
        repo.add_allowlist_entry(s, engagement_id=eid, cidr="10.0.0.0/24")
        first = repo.create_scan_run(s, engagement_id=eid, modules=["discovery", "vuln"],
                                     targets=["10.0.0.1"])
    Probe.factory, Probe.run_id = sqlite_factory, first
    svc.execute(first, ["10.0.0.1"])
    stored = _stored(sqlite_factory, first)
    assert set(stored["stage_seconds"]) == {"discovery", "vuln"}
    with session_scope(sqlite_factory) as s:
        second = repo.create_scan_run(s, engagement_id=eid, modules=["discovery", "vuln"],
                                      targets=["10.0.0.1"])
        rows = repo.recent_run_progress(s, engagement_id=eid, before_id=second,
                                        rate_profile="gentle")
    assert rows and rows[0]["stage_seconds"] == stored["stage_seconds"]
