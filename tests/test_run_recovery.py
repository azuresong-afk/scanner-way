"""Восстановление прогонов после сбоя (миграция 0017).

Процесс, который вёл прогон, «умирает» — прогон не должен навсегда остаться
«выполняется»: running становится «Прерван» с понятной причиной, pending снова
ставится в очередь, повторное исполнение не дублирует результаты, «Повторить»
создаёт новый прогон с теми же параметрами.
"""
from __future__ import annotations

import os
import socket
from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select

from scanner.api.main import create_app
from scanner.api.settings import ApiSettings
from scanner.core import repository as repo
from scanner.core import run_events
from scanner.core.audit import DbAuditSink
from scanner.core.db import AuditLogRow, FindingRow, HostResult, ScanRun, session_scope
from scanner.core.models import Finding, FindingType, HostOs, ServiceInfo, Severity
from scanner.core.orchestrator import (
    MSG_INTERRUPTED,
    MSG_INTERRUPTED_SAVED,
    MSG_NO_TARGETS,
    RunService,
    inline_executor,
    owner_is_dead,
)
from scanner.modules.base import ScanContext, ScanModule
from scanner.reporting.remediation import RemediationResolver
from tests.conftest import PG_URL
from tests.test_migrations_pg import pg_factory  # noqa: F401 — фикстура

SECRET = "x" * 40
PASSWORD = "correct-horse-battery"


class FakeDiscovery(ScanModule):
    name = "discovery"

    def run(self, ctx: ScanContext) -> list[Finding]:
        ctx.services = [ServiceInfo(t, 22, "tcp", "ssh", "OpenSSH", "7.4") for t in ctx.targets]
        ctx.hosts = {t: HostOs(t, "Linux", "linux", 95, "nmap") for t in ctx.targets}
        return [Finding(module=self.name, host=t, port=22, finding_type=FindingType.VULN,
                        title="weak ssh", severity=Severity.HIGH, vuln_id="CVE-2016-6210",
                        cve_ids=["CVE-2016-6210"]) for t in ctx.targets]


class Broken(ScanModule):
    name = "broken"

    def run(self, ctx: ScanContext) -> list[Finding]:
        raise RuntimeError("ssh unreachable")


REGISTRY = {"discovery": FakeDiscovery, "broken": Broken}


class DeferredExecutor:
    def __init__(self):
        self.jobs = []

    def submit(self, fn, *args):
        self.jobs.append(lambda: fn(*args))

    def run_all(self):
        while self.jobs:
            self.jobs.pop(0)()


def _service(factory, executor=None, **kw) -> RunService:
    return RunService(factory, DbAuditSink(factory), registry=REGISTRY,
                      executor=executor or inline_executor(), vault=None,
                      heartbeat_seconds=0, **kw)


def _engagement(factory) -> int:
    with session_scope(factory) as s:
        eid = repo.create_engagement(s, name="ООО Ромашка")
        repo.add_allowlist_entry(s, engagement_id=eid, cidr="10.0.0.0/24")
    return eid


def _orphan(factory, eid: int, *, status: str, worker_id: str | None,
            heartbeat: datetime | None, targets=("10.0.0.1",)) -> int:
    """Прогон, который «вёл» другой (уже несуществующий) процесс."""
    with session_scope(factory) as s:
        run_id = repo.create_scan_run(s, engagement_id=eid, modules=["discovery"],
                                      targets=list(targets), name="ночной")
        run = s.get(ScanRun, run_id)
        run.status, run.worker_id, run.heartbeat_at = status, worker_id, heartbeat
        if status == "running":
            run.started_at = datetime.now(UTC) - timedelta(minutes=5)
    return run_id


def _run(factory, run_id: int) -> ScanRun:
    with session_scope(factory) as s:
        run = s.get(ScanRun, run_id)
        s.expunge(run)
        return run


def _actions(factory) -> list[tuple[str, str, str | None]]:
    with session_scope(factory) as s:
        return [tuple(r) for r in s.execute(
            select(AuditLogRow.action, AuditLogRow.target, AuditLogRow.result)
            .order_by(AuditLogRow.id))]


def _dead_twin(svc: RunService) -> str:
    """worker_id прошлого запуска того же контейнера: тот же хост и pid."""
    host, pid, _ = svc.worker_id.rsplit(":", 2)
    return f"{host}:{pid}:previousboot"


# ---------- кто считается «мёртвым» ----------
def test_owner_is_dead_rules():
    me = f"{socket.gethostname()}:{os.getpid()}:boot1"
    assert owner_is_dead(f"{socket.gethostname()}:{os.getpid()}:boot0", me)  # прошлый запуск
    assert not owner_is_dead(me, me)
    assert not owner_is_dead(f"other-host:{os.getpid()}:boot0", me)  # чужой хост — по давности
    assert not owner_is_dead(None, me)
    assert not owner_is_dead("garbage", me)
    # живой соседний процесс (родитель pytest) на этом хосте — жив
    assert not owner_is_dead(f"{socket.gethostname()}:{os.getppid()}:x", me)


# ---------- сторож ----------
def test_running_of_dead_process_becomes_interrupted(sqlite_factory):
    svc = _service(sqlite_factory)
    eid = _engagement(sqlite_factory)
    run_id = _orphan(sqlite_factory, eid, status="running", worker_id=_dead_twin(svc),
                     heartbeat=datetime.now(UTC))     # отметка свежая, но процесса нет
    got = svc.recover_orphans()
    assert got == {"interrupted": [run_id], "requeued": []}
    run = _run(sqlite_factory, run_id)
    assert run.status == "interrupted" and run.finished_at is not None
    assert run.error_message == MSG_INTERRUPTED
    assert ("scan_finish", f"scan_run:{run_id}", "interrupted") in _actions(sqlite_factory)
    with session_scope(sqlite_factory) as s:          # и в ленте «Сводки»
        last = run_events.list_events(s, run_id, 1)[0]
        assert (last.kind, last.message) == (
            "run_finish", "прерван. исполнитель прогона перезапущен")
    # повторный проход ничего не меняет
    assert svc.recover_orphans() == {"interrupted": [], "requeued": []}


def test_stale_heartbeat_from_other_host(sqlite_factory):
    svc = _service(sqlite_factory, stale_seconds=180)
    eid = _engagement(sqlite_factory)
    now = datetime.now(UTC)
    fresh = _orphan(sqlite_factory, eid, status="running", worker_id="other:1:a",
                    heartbeat=now - timedelta(seconds=30))
    stale = _orphan(sqlite_factory, eid, status="running", worker_id="other:1:a",
                    heartbeat=now - timedelta(minutes=10))
    legacy = _orphan(sqlite_factory, eid, status="running", worker_id=None, heartbeat=None)
    got = svc.recover_orphans()
    assert sorted(got["interrupted"]) == sorted([stale, legacy])
    assert _run(sqlite_factory, fresh).status == "running"


def test_interrupted_after_findings_saved_says_so(sqlite_factory):
    svc = _service(sqlite_factory)
    eid = _engagement(sqlite_factory)
    run_id = _orphan(sqlite_factory, eid, status="running", worker_id=_dead_twin(svc),
                     heartbeat=None)
    with session_scope(sqlite_factory) as s:
        repo.save_findings(s, engagement_id=eid, scan_run_id=run_id,
                           findings=[Finding(module="discovery", host="10.0.0.1",
                                             finding_type=FindingType.INFO, title="up")])
    svc.recover_orphans()
    run = _run(sqlite_factory, run_id)
    assert run.status == "interrupted" and run.error_message == MSG_INTERRUPTED_SAVED


def test_orphaned_pending_is_requeued_and_runs(sqlite_factory):
    svc = _service(sqlite_factory)
    eid = _engagement(sqlite_factory)
    run_id = _orphan(sqlite_factory, eid, status="pending", worker_id=_dead_twin(svc),
                     heartbeat=datetime.now(UTC))
    got = svc.recover_orphans()
    assert got == {"interrupted": [], "requeued": [run_id]}
    run = _run(sqlite_factory, run_id)
    assert run.status == "done" and run.worker_id == svc.worker_id
    assert ("scan_requeue", f"scan_run:{run_id}", "ok") in _actions(sqlite_factory)


def test_own_runs_are_never_touched(sqlite_factory):
    deferred = DeferredExecutor()
    svc = _service(sqlite_factory, executor=deferred, stale_seconds=0)
    eid = _engagement(sqlite_factory)
    run_id = svc.submit(engagement_id=eid, modules=["discovery"], rate_profile="gentle",
                        requested_targets=["10.0.0.1"], actor="user:op")
    # даже с нулевым порогом свой прогон из очереди — не сирота
    assert svc.recover_orphans() == {"interrupted": [], "requeued": []}
    deferred.run_all()
    assert _run(sqlite_factory, run_id).status == "done"


def test_heartbeat_updates_only_own_active_runs(sqlite_factory):
    deferred = DeferredExecutor()
    svc = _service(sqlite_factory, executor=deferred)
    eid = _engagement(sqlite_factory)
    run_id = svc.submit(engagement_id=eid, modules=["discovery"], rate_profile="gentle",
                        requested_targets=["10.0.0.1"], actor="user:op")
    with session_scope(sqlite_factory) as s:
        s.get(ScanRun, run_id).heartbeat_at = datetime(2020, 1, 1, tzinfo=UTC)
    svc.heartbeat()
    hb = _run(sqlite_factory, run_id).heartbeat_at
    assert hb.replace(tzinfo=UTC) > datetime(2025, 1, 1, tzinfo=UTC)


# ---------- без дублей ----------
def test_run_is_claimed_once(sqlite_factory):
    deferred = DeferredExecutor()
    svc = _service(sqlite_factory, executor=deferred)
    eid = _engagement(sqlite_factory)
    run_id = svc.submit(engagement_id=eid, modules=["discovery"], rate_profile="gentle",
                        requested_targets=["10.0.0.1"], actor="user:op")
    # та же задача попала в очередь дважды (например, сторож другого процесса)
    deferred.jobs.append(deferred.jobs[0])
    deferred.run_all()
    with session_scope(sqlite_factory) as s:
        assert s.scalar(select(func.count(FindingRow.id))
                        .where(FindingRow.scan_run_id == run_id)) == 1
    starts = [a for a in _actions(sqlite_factory) if a[0] == "scan_start"]
    assert len(starts) == 1


def test_reexecution_replaces_results(sqlite_factory):
    svc = _service(sqlite_factory)
    eid = _engagement(sqlite_factory)
    run_id = svc.submit(engagement_id=eid, modules=["discovery"], rate_profile="gentle",
                        requested_targets=["10.0.0.1", "10.0.0.2"], actor="user:op")
    with session_scope(sqlite_factory) as s:     # как будто прогон вернули в очередь
        s.get(ScanRun, run_id).status = "pending"
    assert svc.execute(run_id, ["10.0.0.1", "10.0.0.2"]) == "done"
    with session_scope(sqlite_factory) as s:
        assert s.scalar(select(func.count(FindingRow.id))
                        .where(FindingRow.scan_run_id == run_id)) == 2
        assert s.scalar(select(func.count(HostResult.id))
                        .where(HostResult.scan_run_id == run_id)) == 2


# ---------- понятные причины ----------
def test_error_messages_for_user(sqlite_factory):
    svc = _service(sqlite_factory)
    eid = _engagement(sqlite_factory)
    broken = svc.submit(engagement_id=eid, modules=["discovery", "broken"],
                        rate_profile="gentle", requested_targets=["10.0.0.1"],
                        actor="user:op")
    run = _run(sqlite_factory, broken)
    assert run.status == "partial"          # discovery отработал — результат частичный
    assert "модуль broken" in run.error_message and "ssh unreachable" in run.error_message
    outside = svc.submit(engagement_id=eid, modules=["discovery"], rate_profile="gentle",
                         requested_targets=["192.168.1.1"], actor="user:op")
    assert _run(sqlite_factory, outside).error_message == MSG_NO_TARGETS
    ok = svc.submit(engagement_id=eid, modules=["discovery"], rate_profile="gentle",
                    requested_targets=["10.0.0.1"], actor="user:op")
    assert _run(sqlite_factory, ok).error_message is None


# ---------- API: старт и «Повторить» ----------
def _app(factory):
    settings = ApiSettings(secret=SECRET, bootstrap_admin="root",
                           bootstrap_password=PASSWORD, run_heartbeat_seconds=0)
    return create_app(session_factory=factory, settings=settings, registry=REGISTRY,
                      executor=inline_executor(),
                      resolver_factory=lambda findings: RemediationResolver())


def _login(c, username):
    r = c.post("/auth/token", json={"username": username, "password": PASSWORD})
    assert r.status_code == 200, r.text
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


@pytest.fixture
def client(sqlite_factory):
    with TestClient(_app(sqlite_factory)) as c:
        admin = _login(c, "root")
        for name, role in (("op", "operator"), ("aud", "auditor")):
            assert c.post("/users", headers=admin, json={
                "username": name, "password": PASSWORD, "roles": [role]}).status_code == 201
        yield c


def test_startup_interrupts_runs_of_previous_process(sqlite_factory):
    eid = _engagement(sqlite_factory)
    me = RunService(sqlite_factory, DbAuditSink(sqlite_factory), registry=REGISTRY,
                    executor=inline_executor(), vault=None, heartbeat_seconds=0)
    run_id = _orphan(sqlite_factory, eid, status="running", worker_id=_dead_twin(me),
                     heartbeat=datetime.now(UTC))
    with TestClient(_app(sqlite_factory)) as c:
        op_headers = _login(c, "root")
        body = c.get(f"/runs/{run_id}", headers=op_headers).json()
    assert body["status"] == "interrupted"
    assert body["error_message"] == MSG_INTERRUPTED


def test_retry_creates_new_run_with_same_params(client, sqlite_factory):
    op = _login(client, "op")
    eid = _engagement(sqlite_factory)
    old = _orphan(sqlite_factory, eid, status="running", worker_id="other:1:a",
                  heartbeat=datetime(2020, 1, 1, tzinfo=UTC))
    client.app.state.runs.recover_orphans()
    r = client.post(f"/runs/{old}/retry", headers=op)
    assert r.status_code == 202, r.text
    new = r.json()
    assert new["id"] != old and new["retry_of"] == old
    assert new["status"] == "done" and new["name"] == "ночной"
    assert new["targets"] == ["10.0.0.1"]
    assert len(client.get(f"/runs/{new['id']}/findings", headers=op).json()) == 1
    assert client.get(f"/runs/{old}/findings", headers=op).json() == []
    # успешный прогон тоже можно повторить (повторная проверка после устранения)
    again = client.post(f"/runs/{new['id']}/retry", headers=op)
    assert again.status_code == 202, again.text
    assert again.json()["retry_of"] == new["id"] and again.json()["targets"] == ["10.0.0.1"]
    # идущий прогон повторить нельзя; аудитор не запускает прогоны
    running = _orphan(sqlite_factory, eid, status="running", worker_id=None, heartbeat=None)
    assert client.post(f"/runs/{running}/retry", headers=op).status_code == 409
    aud = _login(client, "aud")
    assert client.post(f"/runs/{old}/retry", headers=aud).status_code == 403


def test_retry_rechecks_allowlist(client, sqlite_factory):
    op = _login(client, "op")
    eid = _engagement(sqlite_factory)
    old = _orphan(sqlite_factory, eid, status="interrupted", worker_id=None, heartbeat=None,
                  targets=("192.168.5.5",))
    r = client.post(f"/runs/{old}/retry", headers=op)
    assert r.status_code == 422


# ---------- то же на PostgreSQL (TIMESTAMPTZ, условные UPDATE) ----------
pg_only = pytest.mark.skipif(not PG_URL, reason="SCANNER_TEST_DATABASE_URL not set")


@pg_only
def test_recovery_on_postgres(pg_factory):  # noqa: F811
    svc = _service(pg_factory)
    eid = _engagement(pg_factory)
    dead = _orphan(pg_factory, eid, status="running", worker_id=_dead_twin(svc),
                   heartbeat=datetime.now(UTC))
    pending = _orphan(pg_factory, eid, status="pending", worker_id="other:1:a",
                      heartbeat=datetime.now(UTC) - timedelta(hours=1))
    fresh = _orphan(pg_factory, eid, status="running", worker_id="other:1:a",
                    heartbeat=datetime.now(UTC))
    got = svc.recover_orphans()
    assert got == {"interrupted": [dead], "requeued": [pending]}
    assert _run(pg_factory, dead).status == "interrupted"
    assert _run(pg_factory, pending).status == "done"
    assert _run(pg_factory, fresh).status == "running"
    # «Повторить» и повторное исполнение без дублей
    new_id = svc.retry(dead, actor="user:op")
    assert _run(pg_factory, new_id).retry_of == dead
    with session_scope(pg_factory) as s:
        s.get(ScanRun, new_id).status = "pending"
    assert svc.execute(new_id, ["10.0.0.1"]) == "done"
    with session_scope(pg_factory) as s:
        assert s.scalar(select(func.count(FindingRow.id))
                        .where(FindingRow.scan_run_id == new_id)) == 1
