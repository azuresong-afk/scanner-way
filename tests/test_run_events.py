"""Лента событий прогона для «Сводки» (миграция 0023) и тренд за период.

Сканер пишет: начало и итог прогона, модули (начат / готов / ошибка /
пропущен), по хосту — новые и вернувшиеся уязвимости, закрытые, хост не
проверен. Ошибка записи ленты не роняет прогон.
"""
from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import select

from scanner.core import assets
from scanner.core import coverage as cv
from scanner.core import findings_query as fq
from scanner.core import repository as repo
from scanner.core import run_events as ev
from scanner.core.audit import DbAuditSink
from scanner.core.db import FalsePositiveRow, RunEventRow, ScanRun, session_scope
from scanner.core.models import Finding, FindingType, HostOs, ServiceInfo, Severity
from scanner.core.orchestrator import RunService, inline_executor
from scanner.modules.base import ScanContext, ScanModule
from scanner.modules.discovery import DiscoveryModule


def _f(host: str, cve: str, sev: Severity = Severity.HIGH, *, bdu: str | None = None,
       module: str = "vuln") -> Finding:
    return Finding(module=module, host=host, port=22, finding_type=FindingType.VULN,
                   title=f"OpenSSH: {cve}", severity=sev, vuln_id=cve, cve_ids=[cve],
                   bdu_ids=[bdu] if bdu else [])


# ---------- тексты и порядок ----------
def test_plural_and_module_texts():
    assert [ev.plural(n, ("цель", "цели", "целей")) for n in (1, 2, 5, 11, 21, 104)] == \
        ["цель", "цели", "целей", "целей", "цель", "цели"]
    assert ev.module_start("vuln", 3).message == "начат: 3 цели"
    assert ev.module_start("vuln", 3).subject == "Уязвимости ПО"
    assert ev.module_finish("discovery", 0).message == "готов, находок нет"
    assert ev.module_finish("discovery", 21).message == "готов: 21 находка"
    assert ev.module_start("custom", 1).subject == "custom"
    assert ev.run_start(2, ["discovery", "vuln"]).message == \
        "начат: 2 цели; модули: обнаружение, уязвимости ПО"


def test_run_finish_text():
    assert ev.run_finish("done", open_issues=12, new=3, fixed=2).message == \
        "завершён, открытых 12, новых 3, закрыто 2"
    assert ev.run_finish("done", open_issues=0).message == "завершён, открытых 0"
    part = ev.run_finish("partial", open_issues=4, message="10.0.0.7 — хост недоступен")
    assert part.message == "завершён частично, открытых 4. 10.0.0.7 — хост недоступен"
    assert ev.run_finish("stopped", open_issues=4).message == "остановлен"
    assert ev.run_finish("failed", message="x" * 2000).message.startswith("завершился ошибкой. x")
    assert len(ev.run_finish("failed", message="x" * 2000).message) == 1000


def test_host_events_rank_merge_and_exclude():
    a, b, c = "10.0.0.1", "10.0.0.2", "10.0.0.3"
    findings = [
        _f(a, "CVE-1", Severity.CRITICAL, bdu="BDU:2024-1"), _f(a, "CVE-2"),
        _f(a, "CVE-3", Severity.LOW),
        _f(b, "CVE-4", Severity.MEDIUM),                       # вернулась
        _f(b, "CVE-5"),                                         # ложное срабатывание
        Finding(module="discovery", host=a, finding_type=FindingType.INFO, title="up",
                vuln_id="INFO:up"),
    ]
    statuses = {f.dedup_key(): "new" for f in findings}
    statuses[findings[3].dedup_key()] = "regression"
    statuses[findings[4].dedup_key()] = "new"
    gone = [_f(c, "CVE-9"), _f(c, "CVE-8", Severity.INFO)]
    gaps = [(c, "discovery", "хост недоступен"), (c, "vuln", "хост недоступен")]
    out = ev.host_events(findings, statuses, gone, gaps,
                         false_positive_keys={findings[4].dedup_key()},
                         hostnames={a: "astra-db01"})
    # в ленте новые сверху: самое важное записано последним
    kinds = [e.kind for e in reversed(out)]
    assert kinds == ["host_regression", "host_new", "host_gap", "host_fixed"]
    reg, new, gap, fixed = list(reversed(out))
    assert reg.subject == b and reg.severity == "medium"
    assert reg.message == "вернулись после исправления: 1 · CVE-4"
    assert new.subject == "astra-db01" and new.host == a and new.severity == "critical"
    assert new.message == "новых уязвимостей: 1 критическая, 1 высокая, 1 прочая · CVE-1, BDU:2024-1, CVE-2"
    # одна строка на хост и причину, а не на каждый модуль
    assert gap.message == "не проверен: хост недоступен (обнаружение, уязвимости ПО)"
    assert fixed.severity == "ok" and fixed.message == "закрыто 1 · CVE-9"


def test_host_events_are_capped():
    findings = [_f(f"10.0.1.{i}", f"CVE-{i}", Severity.CRITICAL if i < 3 else Severity.LOW)
                for i in range(1, 41)]
    statuses = {f.dedup_key(): "new" for f in findings}
    out = ev.host_events(findings, statuses, limit=5)
    assert len(out) == 6
    assert out[0].kind == "hosts_more"
    assert out[0].message.startswith("ещё 35 событий по хостам")
    # критичные хосты — в ленте, не в «ещё»
    assert {e.host for e in out[1:]} >= {"10.0.1.1", "10.0.1.2"}


# ---------- прогон пишет ленту ----------
class Net:
    def __init__(self):
        self.up: set[str] = set()
        self.cves: dict[str, list[tuple[str, Severity]]] = {}


class FakeDiscovery(ScanModule):
    name = "discovery"

    def __init__(self, net: Net):
        self.net = net

    def run(self, ctx: ScanContext) -> list[Finding]:
        ctx.services = [ServiceInfo(t, 22, "tcp", "ssh", "OpenSSH", "9.2p1")
                        for t in ctx.targets if t in self.net.up]
        for t in ctx.targets:
            if t in self.net.up:
                ctx.hosts[t] = HostOs(t, "Debian 12", "debian", 95, "banner")
        DiscoveryModule._mark_coverage(self, ctx, ctx.targets, False)
        return []


class FakeVuln(ScanModule):
    name = "vuln"

    def __init__(self, net: Net):
        self.net = net

    def run(self, ctx: ScanContext) -> list[Finding]:
        return [_f(t, c, sev) for t in ctx.alive_hosts() or ()
                for c, sev in self.net.cves.get(t, [])]


class Broken(ScanModule):
    name = "broken"

    def run(self, ctx: ScanContext) -> list[Finding]:
        raise RuntimeError("ssh unreachable")


@pytest.fixture
def net():
    return Net()


@pytest.fixture
def svc(sqlite_factory, net):
    registry = {"discovery": lambda: FakeDiscovery(net), "vuln": lambda: FakeVuln(net),
                "broken": Broken}
    return RunService(sqlite_factory, DbAuditSink(sqlite_factory), registry=registry,
                      executor=inline_executor(), vault=None, heartbeat_seconds=0)


def _eng(factory) -> int:
    with session_scope(factory) as s:
        eid = repo.create_engagement(s, name="Стенд")
        repo.add_allowlist_entry(s, engagement_id=eid, cidr="10.0.0.0/24")
    return eid


def _submit(svc, eid, targets, modules=("discovery", "vuln")):
    return svc.submit(engagement_id=eid, modules=list(modules), rate_profile="gentle",
                      requested_targets=targets, actor="user:op")


def _fp(factory, eid, f: Finding) -> None:
    with session_scope(factory) as s:
        s.add(FalsePositiveRow(engagement_id=eid, dedup_key=f.dedup_key(), host=f.host,
                               port=f.port, vuln_id=f.vuln_id, module=f.module, title=f.title))


def _feed(factory, rid) -> list[tuple[str, str, str]]:
    """Лента в порядке записи: (kind, subject, message)."""
    with session_scope(factory) as s:
        return [(e.kind, e.subject, e.message)
                for e in reversed(ev.list_events(s, rid, ev.LIST_LIMIT_MAX))]


def test_run_writes_feed_with_modules_hosts_and_result(svc, sqlite_factory, net):
    net.up |= {"10.0.0.5", "10.0.0.6"}
    net.cves["10.0.0.5"] = [("CVE-2024-6387", Severity.CRITICAL), ("CVE-2023-48795", Severity.MEDIUM)]
    net.cves["10.0.0.6"] = [("CVE-2023-48795", Severity.MEDIUM)]
    eid = _eng(sqlite_factory)
    with session_scope(sqlite_factory) as s:
        assets.create_asset(s, eid, address="10.0.0.5", hostname="astra-db01")
    first = _submit(svc, eid, ["10.0.0.5", "10.0.0.6"])
    feed = _feed(sqlite_factory, first)
    assert feed[0] == ("run_start", "Прогон", "начат: 2 цели; модули: обнаружение, уязвимости ПО")
    assert ("module_start", "Обнаружение", "начат: 2 цели") in feed
    assert ("module_finish", "Уязвимости ПО", "готов: 3 находки") in feed
    # первый прогон: базы для сравнения нет — всё «новое» не объявляется
    assert not [k for k, *_ in feed if k.startswith("host_")]
    assert feed[-1] == ("run_finish", "Прогон", "завершён, открытых 3")

    # второй прогон: одна закрыта, одна новая, 10.0.0.6 выключен
    net.up.discard("10.0.0.6")
    net.cves["10.0.0.5"] = [("CVE-2024-6387", Severity.CRITICAL), ("CVE-2025-26465", Severity.HIGH)]
    second = _submit(svc, eid, ["10.0.0.5", "10.0.0.6"])
    feed = _feed(sqlite_factory, second)
    by_kind = {k: (subj, msg) for k, subj, msg in feed}
    assert by_kind["host_new"] == ("astra-db01", "новых уязвимостей: 1 высокая · CVE-2025-26465")
    assert by_kind["host_fixed"] == ("astra-db01", "закрыто 1 · CVE-2023-48795")
    assert by_kind["host_gap"][0] == "10.0.0.6"
    assert by_kind["host_gap"][1].startswith(f"не проверен: {cv.STATUS_LABELS[cv.UNREACHABLE]}")
    kind, _, msg = feed[-1]
    assert kind == "run_finish" and msg.startswith("завершён частично, открытых 2, новых 1, закрыто 1")
    with session_scope(sqlite_factory) as s:
        new = s.scalars(select(RunEventRow).where(RunEventRow.scan_run_id == second,
                                                  RunEventRow.kind == "host_new")).one()
        assert (new.host, new.severity) == ("10.0.0.5", "high")


def test_module_error_and_false_positive_in_feed(svc, sqlite_factory, net):
    net.up.add("10.0.0.5")
    net.cves["10.0.0.5"] = [("CVE-1", Severity.HIGH)]
    eid = _eng(sqlite_factory)
    _submit(svc, eid, ["10.0.0.5"])
    net.cves["10.0.0.5"] = [("CVE-1", Severity.HIGH), ("CVE-2", Severity.HIGH)]
    _fp(sqlite_factory, eid, _f("10.0.0.5", "CVE-2"))
    rid = _submit(svc, eid, ["10.0.0.5"], ("discovery", "vuln", "broken"))
    feed = _feed(sqlite_factory, rid)
    assert ("module_error", "broken", "ошибка: RuntimeError: ssh unreachable") in feed
    assert not [k for k, *_ in feed if k == "host_new"]      # новая — ложное срабатывание
    assert feed[-1][2].startswith("завершён частично, открытых 1")


def test_feed_write_failure_does_not_break_run(svc, sqlite_factory, net, monkeypatch):
    net.up.add("10.0.0.5")
    eid = _eng(sqlite_factory)

    def boom(*a, **k):
        raise RuntimeError("no table")

    logged: list[str] = []
    monkeypatch.setattr(ev, "add", boom)
    # не caplog: alembic.fileConfig в PG-тестах отключает уже созданные логгеры
    monkeypatch.setattr(ev.log, "exception", lambda msg, *a: logged.append(msg % a))
    rid = _submit(svc, eid, ["10.0.0.5"])
    with session_scope(sqlite_factory) as s:
        assert repo.get_scan_run(s, rid).status == "done"
        assert ev.list_events(s, rid) == []
    assert logged and all("cannot write run events" in m for m in logged)


def test_stop_request_in_feed(svc, sqlite_factory):
    eid = _eng(sqlite_factory)
    with session_scope(sqlite_factory) as s:
        rid = repo.create_scan_run(s, engagement_id=eid, modules=["discovery"],
                                   targets=["10.0.0.5"])
    svc.request_stop(rid, actor="user:op")
    assert _feed(sqlite_factory, rid)[-1] == ("run_stop", "Прогон", "остановка по запросу: user:op")


# ---------- тренд за период ----------
def _run_with(factory, eid, counts: dict[str, int], *, status="done", days_ago=0) -> int:
    when = datetime.now(UTC) - timedelta(days=days_ago)
    with session_scope(factory) as s:
        rid = repo.create_scan_run(s, engagement_id=eid, modules=["vuln"], targets=["10.0.0.5"])
        run = s.get(ScanRun, rid)
        run.status, run.started_at, run.finished_at = status, when, when
        fs = [_f("10.0.0.5", f"CVE-{sev}-{i}", Severity(sev))
              for sev, n in counts.items() for i in range(n)]
        repo.save_findings(s, engagement_id=eid, scan_run_id=rid, findings=fs, statuses={})
    return rid


def test_trend_counts_per_run_and_period(sqlite_factory):
    eid = _eng(sqlite_factory)
    old = _run_with(sqlite_factory, eid, {"critical": 2, "low": 1}, days_ago=200)
    _run_with(sqlite_factory, eid, {"high": 5}, status="failed", days_ago=100)
    mid = _run_with(sqlite_factory, eid, {"high": 1, "info": 3}, days_ago=40)
    last = _run_with(sqlite_factory, eid, {"medium": 2, "high": 1}, days_ago=1)
    _fp(sqlite_factory, eid, _f("10.0.0.5", "CVE-medium-0", Severity.MEDIUM))
    with session_scope(sqlite_factory) as s:
        allr = fq.trend(s, eid)
        assert [r["scan_run_id"] for r in allr] == [old, mid, last]     # без «Ошибка»
        assert allr[0]["counts"] == {"critical": 2, "high": 0, "medium": 0, "low": 1}
        assert allr[1]["counts"]["high"] == 1                            # без info
        assert allr[2]["counts"] == {"critical": 0, "high": 1, "medium": 1, "low": 0}
        q = fq.trend(s, eid, since=datetime.now(UTC) - timedelta(days=90))
        assert [r["scan_run_id"] for r in q] == [mid, last]
        assert [r["scan_run_id"] for r in fq.trend(s, eid, limit=2)] == [mid, last]
        assert fq.trend(s, eid + 99) == []
