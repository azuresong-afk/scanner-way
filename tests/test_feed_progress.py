"""Справочники: прогресс долгой загрузки, готовность источников (мастер
первоначальной настройки), загрузка БДУ из браузера и бюллетеней выпуска ОС
одним действием."""
from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient

from scanner.api.main import create_app
from scanner.api.settings import ApiSettings
from scanner.core import repository as repo
from scanner.core.db import FeedSync, session_scope
from scanner.core.orchestrator import inline_executor
from scanner.feeds.readiness import progress_view, readiness
from scanner.feeds.sources import FeedResult, FeedSource
from scanner.reporting.remediation import RemediationResolver
from tests.test_api import PASSWORD, SECRET, Api


class ProgressLoader:
    """Загрузчик, который сообщает прогресс и запоминает, что видел в БД."""

    def __init__(self, factory):
        self.factory = factory
        self.seen: list[tuple] = []

    def __call__(self, ctx):
        ctx.progress("Полная загрузка NVD через API", 0, 300000)
        ctx.progress("Полная загрузка NVD через API", 2000, 300000)   # дросселируется
        ctx.progress("Запись", 150000, 300000)                         # смена этапа
        with self.factory() as s:
            row = s.get(FeedSync, "nvd")
            self.seen.append((row.progress_stage, row.progress_done, row.progress_total,
                              row.running_since is not None))
        return FeedResult(count=300000, message="Полная загрузка NVD: 300000 CVE")


@pytest.fixture
def loader(sqlite_factory):
    return ProgressLoader(sqlite_factory)


@pytest.fixture
def api(sqlite_factory, loader):
    sources = {"nvd": FeedSource("nvd", "NVD", loader),
               "bdu": FeedSource("bdu", "БДУ ФСТЭК", lambda ctx: FeedResult(count=1)),
               "advisories": FeedSource("advisories", "Бюллетени",
                                        lambda ctx: FeedResult(count=1))}
    settings = ApiSettings(secret=SECRET, bootstrap_admin="root",
                           bootstrap_password=PASSWORD, feeds_tick_seconds=0)
    app = create_app(session_factory=sqlite_factory, settings=settings, registry={},
                     executor=inline_executor(), feed_sources=sources,
                     feed_executor=inline_executor(),
                     resolver_factory=lambda f: RemediationResolver())
    with TestClient(app) as c:
        yield Api(c)


def test_progress_is_written_during_load_and_cleared(api, loader):
    r = api.c.post("/feeds/nvd/run", headers=api.admin)
    assert r.status_code == 202
    assert loader.seen == [("Запись", 150000, 300000, True)]
    feed = next(f for f in api.c.get("/feeds", headers=api.admin).json()
                if f["source"] == "nvd")
    assert feed["running"] is False and feed["progress"] is None
    assert feed["last_result"] == "ok" and feed["message_is_previous"] is False


def test_progress_view_percent_rate_eta():
    now = datetime(2026, 11, 3, 12, 0, tzinfo=UTC)
    row = FeedSync(source="nvd", running_since=now - timedelta(seconds=100),
                   progress_stage="Полная загрузка NVD через API", progress_done=20000,
                   progress_total=300000, progress_at=now)
    v = progress_view(row, now)
    assert v["percent"] == pytest.approx(6.7, abs=0.1)
    assert v["rate_per_sec"] == 200.0 and v["eta_seconds"] == 1400
    assert v["stage"].startswith("Полная загрузка")
    row.running_since = None
    assert progress_view(row, now) is None


def test_old_error_is_not_shown_as_current_during_new_attempt(api, sqlite_factory):
    with sqlite_factory.begin() as s:
        row = s.get(FeedSync, "nvd")
        row.last_result, row.message = "error", "NVD: ConnectTimeout"
        row.last_error_at = datetime.now(UTC) - timedelta(hours=1)
        row.running_since = datetime.now(UTC)
        row.progress_stage, row.progress_done, row.progress_total = "Полная", 10, 100
    feed = next(f for f in api.c.get("/feeds", headers=api.admin).json()
                if f["source"] == "nvd")
    assert feed["running"] and feed["message_is_previous"] is True
    assert feed["progress"]["percent"] == 10.0
    ready = api.c.get("/feeds/readiness", headers=api.admin).json()
    nvd = next(i for i in ready["sources"] if i["source"] == "nvd")
    assert nvd["state"] == "running" and nvd["message_is_previous"] is True


def test_readiness_lists_missing_sources_and_releases(sqlite_factory):
    with session_scope(sqlite_factory) as s:
        eid = repo.create_engagement(s, name="x")
        rid = repo.create_scan_run(s, engagement_id=eid, modules=["auth_inventory"])
        repo.set_scan_run_status(s, rid, "done")
        repo.set_run_warnings(s, rid, [{"kind": "advisories_missing", "family": "debian",
                                        "release": "trixie", "os": "Debian 13",
                                        "hosts": ["10.0.0.5"], "message": "…"}])
    srcs = {"bdu": FeedSource("bdu", "БДУ ФСТЭК", lambda c: None),
            "advisories": FeedSource("advisories", "Бюллетени", lambda c: None)}
    with session_scope(sqlite_factory) as s:
        r = readiness(s, srcs)
    assert r["ready"] is False
    bdu = next(i for i in r["sources"] if i["source"] == "bdu")
    assert bdu["state"] == "missing" and "vullist.xlsx" in bdu["hint"]
    assert r["missing_releases"] == [{"family": "debian", "release": "trixie",
                                      "os": "Debian 13", "hosts": ["10.0.0.5"],
                                      "runs": [rid]}]


def test_load_release_one_action(api, monkeypatch):
    calls = []

    def fake_sync(store, targets, *, directory, urls, fetch=None):
        from scanner.feeds.advisories.sync import ReleaseResult
        calls.append(targets)
        return [ReleaseResult("debian", "trixie", count=42, source="tracker")], "fp"

    monkeypatch.setattr("scanner.feeds.advisories.sync.sync_releases", fake_sync)
    op = api.user("op", "operator")
    body = {"family": "debian", "release": "trixie"}
    assert api.c.post("/feeds/advisories/releases", headers=op, json=body).status_code == 403
    assert api.c.post("/feeds/advisories/releases", headers=api.admin,
                      json={"family": "nope", "release": "1"}).status_code == 422
    r = api.c.post("/feeds/advisories/releases", headers=api.admin, json=body)
    assert r.status_code == 202, r.text
    assert calls == [[("debian", "trixie")]]
    feed = next(f for f in api.c.get("/feeds", headers=api.admin).json()
                if f["source"] == "advisories")
    assert feed["last_result"] == "ok" and "debian:trixie — 42" in feed["message"]


def test_bdu_upload_saves_file_and_starts_load(api, tmp_path, monkeypatch):
    from scanner.core.config import settings
    dest = tmp_path / "vullist.xlsx"
    monkeypatch.setattr(settings, "bdu_fstec_feed_path", str(dest))
    monkeypatch.setattr(settings, "bdu_fstec_feed_url", "")
    r = api.c.post("/feeds/bdu/upload", headers=api.admin, content=b"not an xlsx")
    assert r.status_code == 422 and not dest.exists()
    r = api.c.post("/feeds/bdu/upload", headers=api.admin, content=b"PK\x03\x04data")
    assert r.status_code == 202, r.text
    assert dest.read_bytes() == b"PK\x03\x04data"
    assert r.json()["last_result"] == "ok"
    op = api.user("op", "operator")
    assert api.c.post("/feeds/bdu/upload", headers=op, content=b"PK").status_code == 403


def test_nvd_feed_reports_page_progress():
    from scanner.feeds.nvd import NvdFeed

    class Resp:
        def __init__(self, data):
            self.data, self.status_code = data, 200

        def raise_for_status(self):
            pass

        def json(self):
            return self.data

    pages = iter([{"totalResults": 3, "resultsPerPage": 2, "vulnerabilities": []},
                  {"totalResults": 3, "resultsPerPage": 1, "vulnerabilities": []}])

    class Client:
        def get(self, url, params, headers):
            return Resp(next(pages))

    feed = NvdFeed(None, client=Client(), sleep=lambda s: None)
    seen = []
    feed.progress = lambda done, total: seen.append((done, total))
    assert list(feed.iter_api()) == []
    assert seen == [(2, 3), (3, 3)]
