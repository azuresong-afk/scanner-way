"""Автообновление справочников: срабатывание по времени, итоги, права, окно NVD."""
from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from scanner.api.main import create_app
from scanner.api.settings import ApiSettings
from scanner.core.audit import DbAuditSink
from scanner.core.db import AuditLogRow, FeedSync
from scanner.core.orchestrator import inline_executor
from scanner.feeds.scheduler import FeedScheduler, seed_feed_sync
from scanner.feeds.sources import (
    FeedContext,
    FeedError,
    FeedResult,
    FeedSource,
    nvd_windows,
)
from scanner.reporting.remediation import RemediationResolver
from tests.test_api import PASSWORD, SECRET, Api


def _utc(*a) -> datetime:
    return datetime(*a, tzinfo=UTC)


class Fake:
    """Фейковый загрузчик: пишет вызовы, результат задаётся в тесте."""

    def __init__(self):
        self.calls: list[FeedContext] = []
        self.result: FeedResult | Exception = FeedResult(count=5, message="Загружено: 5",
                                                         fingerprint="fp1")

    def __call__(self, ctx: FeedContext) -> FeedResult:
        self.calls.append(ctx)
        if isinstance(self.result, Exception):
            raise self.result
        return self.result


@pytest.fixture
def fake():
    return Fake()


@pytest.fixture
def sources(fake):
    return {"nvd": FeedSource("nvd", "NVD", fake, kind="daily", time_of_day="03:00")}


@pytest.fixture
def sched(sqlite_factory, sources):
    seed_feed_sync(sqlite_factory, timezone="UTC", sources=sources)
    return FeedScheduler(sqlite_factory, DbAuditSink(sqlite_factory), sources=sources,
                         executor=inline_executor(), tick_seconds=0)


def _enable(factory, next_run_at, **kw):
    with factory.begin() as s:
        row = s.get(FeedSync, "nvd")
        row.enabled, row.next_run_at = True, next_run_at
        for k, v in kw.items():
            setattr(row, k, v)


def _row(factory) -> FeedSync:
    with factory() as s:
        row = s.get(FeedSync, "nvd")
        s.expunge(row)
        return row


# ---------- срабатывание по времени ----------
def test_seed_creates_disabled_rows(sqlite_factory, sources):
    seed_feed_sync(sqlite_factory, sources=sources)
    seed_feed_sync(sqlite_factory, sources=sources)     # идемпотентно
    row = _row(sqlite_factory)
    assert (row.enabled, row.next_run_at, row.kind) == (False, None, "daily")


def test_not_due_and_disabled_do_not_fire(sched, fake, sqlite_factory):
    now = _utc(2026, 10, 30, 12)
    assert sched.tick(now) == []                                   # выключено
    _enable(sqlite_factory, now + timedelta(minutes=1))
    assert sched.tick(now) == [] and not fake.calls                # ещё не время


def test_due_fires_once_and_records_result(sched, fake, sqlite_factory):
    now = _utc(2026, 10, 30, 12)
    _enable(sqlite_factory, now - timedelta(minutes=1))
    assert sched.tick(now) == ["nvd"]
    assert sched.tick(now) == []                                   # next_run_at уже сдвинут
    assert len(fake.calls) == 1
    row = _row(sqlite_factory)
    assert (row.last_result, row.last_count, row.message) == ("ok", 5, "Загружено: 5")
    assert row.last_run_at.replace(tzinfo=UTC) == now
    assert row.fingerprint == "fp1" and row.running_since is None
    assert row.next_run_at.replace(tzinfo=UTC) == _utc(2026, 10, 31, 3)   # завтра 03:00
    with sqlite_factory() as s:
        acts = list(s.scalars(select(AuditLogRow.action)))
    assert "feed_sync" in acts


def test_error_is_recorded_and_keeps_previous_success(sched, fake, sqlite_factory):
    now = _utc(2026, 10, 30, 12)
    ok_at = _utc(2026, 10, 29, 3)
    _enable(sqlite_factory, now - timedelta(minutes=1), last_success_at=ok_at,
            last_count=7)
    fake.result = FeedError("NVD недоступен")
    sched.tick(now)
    row = _row(sqlite_factory)
    assert row.last_result == "error" and row.message == "NVD недоступен"
    assert row.last_count == 7                                      # старое значение цело
    assert row.last_success_at.replace(tzinfo=UTC) == ok_at          # граница инкремента цела
    assert row.running_since is None
    fake.result = RuntimeError("boom")                              # неожиданное исключение
    _enable(sqlite_factory, now - timedelta(minutes=1))
    sched.tick(now + timedelta(minutes=5))
    assert "RuntimeError: boom" in _row(sqlite_factory).message


def test_unchanged_result(sched, fake, sqlite_factory):
    fake.result = FeedResult(message="не изменилась", unchanged=True, fingerprint="fp1")
    _enable(sqlite_factory, _utc(2026, 10, 30, 11), fingerprint="fp1")
    sched.tick(_utc(2026, 10, 30, 12))
    assert fake.calls[0].fingerprint == "fp1"
    assert _row(sqlite_factory).last_result == "unchanged"


def test_running_source_is_not_started_twice(sched, fake, sqlite_factory):
    now = _utc(2026, 10, 30, 12)
    _enable(sqlite_factory, now - timedelta(minutes=1), running_since=now)
    assert sched.tick(now) == [] and not fake.calls
    assert sched.submit_manual("nvd", "user:x") is False
    # осиротевшая метка (процесс упал) не блокирует
    _enable(sqlite_factory, now - timedelta(minutes=1),
            running_since=now - timedelta(days=1))
    assert sched.tick(now) == ["nvd"]


def test_loader_gets_last_success_for_incremental(sched, fake, sqlite_factory):
    ok_at = _utc(2026, 10, 29, 3)
    _enable(sqlite_factory, _utc(2026, 10, 30, 3), last_success_at=ok_at)
    now = _utc(2026, 10, 30, 12)
    sched.tick(now)
    assert fake.calls[0].last_success_at.replace(tzinfo=UTC) == ok_at
    assert fake.calls[0].now == now


# ---------- окно NVD ----------
def test_nvd_windows_split_by_limit():
    a = _utc(2026, 1, 1)
    assert nvd_windows(a, a + timedelta(days=30)) == [(a, a + timedelta(days=30))]
    wins = nvd_windows(a, a + timedelta(days=250))
    assert [w[0] for w in wins] == [a, a + timedelta(days=100), a + timedelta(days=200)]
    assert wins[-1][1] == a + timedelta(days=250)
    assert all(e - s <= timedelta(days=120) for s, e in wins)
    assert nvd_windows(a, a) == []


def test_load_nvd_uses_incremental_window(monkeypatch, sqlite_factory):
    from scanner.feeds import nvd as nvd_mod
    from scanner.feeds import sources as src

    seen = []

    class FakeFeed:
        def __init__(self, *a, **k): ...
        def iter_api(self, **kw):
            seen.append(kw)
            return iter(())
        def sync(self, store, *, records, **kw):
            list(records)
            return 3

    monkeypatch.setattr(nvd_mod, "NvdFeed", FakeFeed)
    now = _utc(2026, 10, 30, 12)
    ctx = FeedContext(engine=sqlite_factory.kw["bind"], audit=None, now=now,
                      last_success_at=_utc(2026, 10, 29, 3))
    res = src.load_nvd(ctx)
    assert res.count == 3
    assert seen == [{"last_mod_start": _utc(2026, 10, 29, 2), "last_mod_end": now}]
    seen.clear()
    src.load_nvd(FeedContext(engine=ctx.engine, audit=None, now=now))   # первый раз
    assert seen == [{}]                                                  # полная выгрузка


# ---------- API и права ----------
@pytest.fixture
def api(sqlite_factory, sources):
    settings = ApiSettings(secret=SECRET, bootstrap_admin="root",
                           bootstrap_password=PASSWORD, feeds_tick_seconds=0)
    app = create_app(session_factory=sqlite_factory, settings=settings, registry={},
                     executor=inline_executor(), feed_sources=sources,
                     feed_executor=inline_executor(),
                     resolver_factory=lambda f: RemediationResolver())
    with TestClient(app) as c:
        yield Api(c)


def test_list_status_and_viewers(api):
    operator = api.user("op", "operator")
    r = api.c.get("/feeds", headers=operator)
    assert r.status_code == 200
    (feed,) = r.json()
    assert feed["source"] == "nvd" and feed["title"] == "NVD"
    assert feed["enabled"] is False and feed["running"] is False
    assert api.c.get("/feeds").status_code == 401


def test_manual_run_requires_permission(api, fake):
    operator = api.user("op", "operator")
    auditor = api.user("aud", "auditor")
    for h in (operator, auditor):
        assert api.c.post("/feeds/nvd/run", headers=h).status_code == 403
        assert api.c.put("/feeds/nvd", headers=h,
                         json={"enabled": True}).status_code == 403
    assert not fake.calls
    r = api.c.post("/feeds/nvd/run", headers=api.admin)
    assert r.status_code == 202
    assert len(fake.calls) == 1 and fake.calls[0].actor == "user:root"
    feed = api.c.get("/feeds", headers=api.admin).json()[0]
    assert (feed["last_result"], feed["last_count"], feed["running"]) == ("ok", 5, False)


def test_update_schedule_validates_and_computes_next(api):
    r = api.c.put("/feeds/nvd", headers=api.admin, json={
        "enabled": True, "kind": "weekly", "time_of_day": "04:30", "weekdays": [0, 3],
        "timezone": "Europe/Moscow"})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["enabled"] and body["next_run_at"] and body["weekdays"] == [0, 3]
    assert api.c.put("/feeds/nvd", headers=api.admin, json={
        "enabled": True, "kind": "weekly", "weekdays": []}).status_code == 422
    assert api.c.put("/feeds/nvd", headers=api.admin, json={
        "enabled": True, "time_of_day": "25:00"}).status_code == 422
    off = api.c.put("/feeds/nvd", headers=api.admin, json={"enabled": False}).json()
    assert off["next_run_at"] is None
    assert api.c.put("/feeds/nope", headers=api.admin,
                     json={"enabled": True}).status_code == 404


def test_manual_run_conflict_when_running(api, sqlite_factory):
    with sqlite_factory.begin() as s:
        s.get(FeedSync, "nvd").running_since = datetime.now(UTC)
    assert api.c.post("/feeds/nvd/run", headers=api.admin).status_code == 409
