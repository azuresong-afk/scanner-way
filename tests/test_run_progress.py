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
    assert snaps[-1] | {"updated_at": None} == {
        "stage": "discovery", "stage_index": 1, "stages": 2, "hosts_done": 0,
        "hosts_total": 4, "percent": 0, "updated_at": None}
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
