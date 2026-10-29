"""API + RBAC + оркестратор прогонов (SQLite в памяти, фиктивные модули)."""
from __future__ import annotations

from collections.abc import Callable

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from scanner.api.main import create_app
from scanner.api.security import (
    LoginThrottle,
    TokenSigner,
    hash_password,
    verify_password,
)
from scanner.api.settings import ApiSettings
from scanner.core.allowlist import AllowlistGate
from scanner.core.db import AuditLogRow, ScanRun
from scanner.core.models import Finding, FindingType, ServiceInfo, Severity
from scanner.core.orchestrator import inline_executor, order_modules, plan_targets
from scanner.modules.base import ScanContext, ScanModule
from scanner.reporting.remediation import RemediationResolver

SECRET = "x" * 40
PASSWORD = "correct-horse-battery"


# ---------- фиктивные модули ----------
class Recorder:
    def __init__(self):
        self.seen: dict[str, list[str]] = {}


class FakeDiscovery(ScanModule):
    name = "discovery"

    def __init__(self, rec: Recorder):
        self.rec = rec

    def run(self, ctx: ScanContext) -> list[Finding]:
        self.rec.seen[self.name] = list(ctx.targets)
        ctx.services = [ServiceInfo(t, 22, "tcp", "ssh", "OpenSSH", "7.4") for t in ctx.targets]
        return [Finding(module=self.name, host=t, finding_type=FindingType.INFO,
                        title="host up", vuln_id="INFO:host-up") for t in ctx.targets]


class FakeVuln(ScanModule):
    name = "vuln"

    def __init__(self, rec: Recorder, cves: list[str]):
        self.rec, self.cves = rec, cves

    def run(self, ctx: ScanContext) -> list[Finding]:
        self.rec.seen[self.name] = list(ctx.targets)
        assert ctx.services is not None, "discovery должен отработать раньше"
        return [Finding(module=self.name, host=s.host, port=s.port,
                        finding_type=FindingType.VULN, title=f"{cve} in OpenSSH",
                        severity=Severity.HIGH, vuln_id=cve, cve_ids=[cve],
                        bdu_ids=["BDU:2017-00001"], cvss=7.5)
                for s in ctx.services for cve in self.cves]


class FakeCred(ScanModule):
    name = "cred_audit"

    def __init__(self, rec: Recorder):
        self.rec = rec

    def run(self, ctx: ScanContext) -> list[Finding]:
        self.rec.seen[self.name] = list(ctx.targets)
        return []


class Broken(ScanModule):
    name = "config_audit"

    def run(self, ctx: ScanContext) -> list[Finding]:
        raise RuntimeError("ssh unreachable")


class DeferredExecutor:
    """Копит задачи — чтобы проверить остановку/allowlist до исполнения."""

    def __init__(self):
        self.jobs: list[Callable[[], object]] = []

    def submit(self, fn, *args):
        self.jobs.append(lambda: fn(*args))

    def run_all(self):
        while self.jobs:
            self.jobs.pop(0)()


# ---------- фикстуры ----------
@pytest.fixture
def rec():
    return Recorder()


@pytest.fixture
def cves():
    return ["CVE-2016-6210", "CVE-2016-10009"]


def _make(sqlite_factory, rec, cves, executor):
    registry = {"discovery": lambda: FakeDiscovery(rec),
                "vuln": lambda: FakeVuln(rec, cves),
                "cred_audit": lambda: FakeCred(rec),
                "config_audit": Broken}
    settings = ApiSettings(secret=SECRET, bootstrap_admin="root",
                           bootstrap_password=PASSWORD, login_max_failures=3)
    return create_app(session_factory=sqlite_factory, settings=settings,
                      registry=registry, executor=executor,
                      resolver_factory=lambda findings: RemediationResolver())


@pytest.fixture
def api(sqlite_factory, rec, cves):
    with TestClient(_make(sqlite_factory, rec, cves, inline_executor())) as c:
        yield Api(c)


@pytest.fixture
def deferred():
    return DeferredExecutor()


@pytest.fixture
def api_deferred(sqlite_factory, rec, cves, deferred):
    with TestClient(_make(sqlite_factory, rec, cves, deferred)) as c:
        yield Api(c)


class Api:
    def __init__(self, client: TestClient):
        self.c = client
        self.admin = self.login("root")

    def login(self, username: str, password: str = PASSWORD) -> dict[str, str]:
        r = self.c.post("/auth/token", json={"username": username, "password": password})
        assert r.status_code == 200, r.text
        return {"Authorization": f"Bearer {r.json()['access_token']}"}

    def user(self, username: str, *roles: str) -> dict[str, str]:
        r = self.c.post("/users", headers=self.admin,
                        json={"username": username, "password": PASSWORD,
                              "roles": list(roles)})
        assert r.status_code == 201, r.text
        return self.login(username)

    def engagement(self, *cidrs: str) -> int:
        r = self.c.post("/engagements", headers=self.admin,
                        json={"name": "ООО Ромашка", "client": "Ромашка",
                              "contract_ref": "Д-7/2026"})
        assert r.status_code == 201, r.text
        eid = r.json()["id"]
        for cidr in cidrs:
            r = self.c.post(f"/engagements/{eid}/allowlist", headers=self.admin,
                            json={"cidr": cidr, "note": "по договору"})
            assert r.status_code == 201, r.text
        return eid

    def audit(self, sqlite_factory) -> list[tuple[str, str, str | None, str | None]]:
        with sqlite_factory() as s:
            return [tuple(r) for r in s.execute(
                select(AuditLogRow.subject, AuditLogRow.action, AuditLogRow.target,
                       AuditLogRow.result).order_by(AuditLogRow.id))]


def _run(api: Api, eid: int, headers, targets, modules=("discovery", "vuln"), **kw):
    return api.c.post(f"/engagements/{eid}/runs", headers=headers,
                      json={"targets": list(targets), "modules": list(modules), **kw})


# ---------- аутентификация ----------
def test_requires_authentication(api):
    assert api.c.get("/health").status_code == 200
    assert api.c.get("/engagements").status_code == 401
    bad = {"Authorization": "Bearer abc.def"}
    assert api.c.get("/engagements", headers=bad).status_code == 401


def test_login_audited_and_throttled(api, sqlite_factory):
    for _ in range(3):
        r = api.c.post("/auth/token", json={"username": "root", "password": "wrong"})
        assert r.status_code == 401
    # после 3 неудач — пауза даже с верным паролем
    r = api.c.post("/auth/token", json={"username": "root", "password": PASSWORD})
    assert r.status_code == 429
    log = api.audit(sqlite_factory)
    assert ("user:root", "login", "testclient", "ok") in log
    assert sum(1 for e in log if e[1] == "login" and e[3] == "failure") == 3
    assert ("user:root", "login", "testclient", "locked") in log


def test_deactivated_user_token_is_rejected(api):
    op = api.user("op", "operator")
    assert api.c.get("/me", headers=op).status_code == 200
    uid = api.c.get("/me", headers=op).json()["id"]
    assert api.c.patch(f"/users/{uid}", headers=api.admin,
                       json={"is_active": False}).status_code == 200
    assert api.c.get("/me", headers=op).status_code == 401


def test_last_admin_cannot_be_removed(api):
    me = api.c.get("/me", headers=api.admin).json()
    assert "admin" in me["roles"] and "cred_audit" not in me["permissions"]
    r = api.c.put(f"/users/{me['id']}/roles", headers=api.admin, json={"roles": ["auditor"]})
    assert r.status_code == 409
    r = api.c.patch(f"/users/{me['id']}", headers=api.admin, json={"is_active": False})
    assert r.status_code == 409


# ---------- RBAC ----------
def test_rbac_matrix(api, sqlite_factory):
    eid = api.engagement("10.0.0.0/24")
    op = api.user("op", "operator")
    aud = api.user("aud", "auditor")

    cases = [
        # (кто, метод, путь, тело, ожидаемый код)
        (aud, "post", "/engagements", {"name": "x"}, 403),
        (op, "post", "/engagements", {"name": "x"}, 403),
        (op, "post", f"/engagements/{eid}/allowlist", {"cidr": "10.9.0.0/16"}, 403),
        (aud, "post", f"/engagements/{eid}/allowlist", {"cidr": "10.9.0.0/16"}, 403),
        (op, "get", "/users", None, 403),
        (op, "get", "/audit", None, 403),
        (aud, "post", f"/engagements/{eid}/runs",
         {"targets": ["10.0.0.1"], "modules": ["discovery"]}, 403),
        # admin управляет, но не сканирует (разделение обязанностей)
        (api.admin, "post", f"/engagements/{eid}/runs",
         {"targets": ["10.0.0.1"], "modules": ["discovery"]}, 403),
        (aud, "get", "/audit", None, 200),
        (aud, "get", f"/engagements/{eid}/allowlist", None, 200),
        (op, "get", f"/engagements/{eid}", None, 200),
    ]
    for headers, method, path, body, code in cases:
        r = api.c.request(method.upper(), path, headers=headers, json=body)
        assert r.status_code == code, (path, method, r.text)

    denied = [e for e in api.audit(sqlite_factory) if e[1] == "access_denied"]
    assert ("user:op", "access_denied", f"POST /engagements/{eid}/allowlist",
            "forbidden") in denied
    assert len(denied) == 8
    with sqlite_factory() as s:
        assert s.scalar(select(ScanRun.id)) is None     # ни один прогон не создан


def test_cred_audit_requires_separate_permission(api, sqlite_factory, rec):
    eid = api.engagement("10.0.0.0/24")
    op = api.user("op", "operator")
    r = _run(api, eid, op, ["10.0.0.1"], modules=["discovery", "cred_audit"])
    assert r.status_code == 403 and "cred_audit" in r.json()["detail"]
    with sqlite_factory() as s:
        assert s.scalar(select(ScanRun.id)) is None     # отказ — до постановки
    assert rec.seen == {}
    assert any(e[1] == "access_denied" and e[0] == "user:op"
               for e in api.audit(sqlite_factory))

    cred = api.user("cred", "operator", "cred_audit")
    r = _run(api, eid, cred, ["10.0.0.1"], modules=["cred_audit", "discovery"])
    assert r.status_code == 202, r.text
    assert r.json()["modules"] == ["discovery", "cred_audit"]   # порядок исполнения
    assert rec.seen["cred_audit"] == ["10.0.0.1"]


def test_allowlist_crud_validates_and_audits(api, sqlite_factory):
    eid = api.engagement()
    r = api.c.post(f"/engagements/{eid}/allowlist", headers=api.admin,
                   json={"cidr": "not-a-net"})
    assert r.status_code == 422
    r = api.c.post(f"/engagements/{eid}/allowlist", headers=api.admin,
                   json={"cidr": "10.0.0.7/24"})
    assert r.json()["cidr"] == "10.0.0.0/24"
    entry = r.json()["id"]
    assert api.c.delete(f"/engagements/{eid}/allowlist/{entry}",
                        headers=api.admin).status_code == 204
    assert api.c.get(f"/engagements/{eid}/allowlist", headers=api.admin).json() == []
    actions = [e[1] for e in api.audit(sqlite_factory)]
    assert "allowlist_add" in actions and "allowlist_remove" in actions


def test_allowlist_rejects_duplicates_after_normalization(api):
    eid = api.engagement()
    url = f"/engagements/{eid}/allowlist"

    def add(cidr):
        return api.c.post(url, headers=api.admin, json={"cidr": cidr})

    first = add("10.0.0.7/24")
    assert first.status_code == 201
    net_id = first.json()["id"]
    # та же подсеть в другой записи, адрес и подсеть внутри неё — дубли
    for cidr, exact in [("10.0.0.0/24", True), (" 10.0.0.0/24 ", True),
                        ("10.0.0.5", False), ("10.0.0.5/32", False),
                        ("10.0.0.128/25", False)]:
        r = add(cidr)
        assert r.status_code == 409, (cidr, r.text)
        d = r.json()["detail"]
        assert d["code"] == "allowlist_duplicate"
        assert d["existing_id"] == net_id and d["existing_cidr"] == "10.0.0.0/24"
        assert ("уже есть в allowlist" in d["message"]) is exact
    # IPv6: разная запись одного адреса
    assert add("2001:DB8::1").status_code == 201
    r = add("2001:0db8:0:0::1/128")
    assert r.status_code == 409 and r.json()["detail"]["existing_cidr"] == "2001:db8::1/128"
    # соседняя и более широкая подсети — новые цели, их добавить можно
    assert add("10.0.1.0/24").status_code == 201
    assert add("10.0.0.0/16").status_code == 201
    # точное совпадение важнее покрытия широкой подсетью
    assert add("10.0.0.0/24").json()["detail"]["existing_id"] == net_id
    cidrs = [e["cidr"] for e in api.c.get(url, headers=api.admin).json()]
    assert cidrs == ["10.0.0.0/24", "2001:db8::1/128", "10.0.1.0/24", "10.0.0.0/16"]


# ---------- прогоны и allowlist ----------
def test_run_drops_targets_outside_allowlist(api, sqlite_factory, rec):
    eid = api.engagement("10.0.0.0/24")
    op = api.user("op", "operator")
    r = _run(api, eid, op, ["10.0.0.5", "203.0.113.7", "10.0.0.0/30", "example.com",
                            "10.0.0.252/30"])
    assert r.status_code == 202, r.text
    body = r.json()
    # /30 -> .1,.2 ; /30 у края /24 -> .253,.254 (оба внутри) ; итого 5 адресов
    assert body["accepted_targets"] == 5
    assert {(d["target"], d["reason"]) for d in body["denied_targets"]} == {
        ("203.0.113.7", "not_in_allowlist"), ("example.com", "not_an_ip")}
    assert body["status"] == "done"
    assert sorted(rec.seen["discovery"]) == sorted(
        ["10.0.0.5", "10.0.0.1", "10.0.0.2", "10.0.0.253", "10.0.0.254"])
    assert rec.seen["vuln"] == rec.seen["discovery"]

    log = api.audit(sqlite_factory)
    assert ("scanner", "deny", "203.0.113.7", "not_in_allowlist") in log
    assert ("scanner", "deny", "example.com", "not_an_ip") in log
    assert any(e[0] == "user:op" and e[1] == "scan_queue" for e in log)
    assert ("scanner", "scan_finish", f"scan_run:{body['id']}", "done") in log

    hosts = {f["host"] for f in api.c.get(f"/runs/{body['id']}/findings",
                                          headers=op).json()}
    assert "203.0.113.7" not in hosts and "10.0.0.5" in hosts
    services = api.c.get(f"/runs/{body['id']}/services", headers=op).json()
    assert len(services) == 5


def test_run_partially_outside_subnet_is_trimmed(api, rec):
    eid = api.engagement("10.0.0.0/30")
    op = api.user("op", "operator")
    r = _run(api, eid, op, ["10.0.0.0/29"], modules=["discovery"])
    assert r.status_code == 202
    # хосты /29: .1–.6; в allowlist /30 попадают .1–.3
    assert sorted(rec.seen["discovery"]) == ["10.0.0.1", "10.0.0.2", "10.0.0.3"]
    assert r.json()["denied_targets"] == [
        {"target": "10.0.0.0/29", "reason": "not_in_allowlist", "count": 3}]


def test_run_with_no_allowed_targets_is_rejected(api, sqlite_factory, rec):
    eid = api.engagement("10.0.0.0/24")
    op = api.user("op", "operator")
    r = _run(api, eid, op, ["8.8.8.8", "192.168.0.0/16"])
    assert r.status_code == 422
    reasons = {d["target"]: d["reason"] for d in r.json()["detail"]["denied_targets"]}
    assert reasons == {"8.8.8.8": "not_in_allowlist", "192.168.0.0/16": "too_many_targets"}
    with sqlite_factory() as s:
        assert s.scalar(select(ScanRun.id)) is None
    assert rec.seen == {}
    assert any(e[1] == "scan_request" and e[3] == "rejected_no_targets"
               for e in api.audit(sqlite_factory))


def test_run_validates_modules_and_profile(api):
    eid = api.engagement("10.0.0.0/24")
    op = api.user("op", "operator")
    assert _run(api, eid, op, ["10.0.0.1"], modules=["exploit"]).status_code == 422
    assert _run(api, eid, op, ["10.0.0.1"], rate_profile="ludicrous").status_code == 422
    assert _run(api, 999, op, ["10.0.0.1"]).status_code == 404


def test_allowlist_is_reread_at_execution(api_deferred, deferred, sqlite_factory, rec):
    api = api_deferred
    eid = api.engagement("10.0.0.0/24")
    entry = api.c.get(f"/engagements/{eid}/allowlist", headers=api.admin).json()[0]["id"]
    op = api.user("op", "operator")
    r = _run(api, eid, op, ["10.0.0.1"])
    assert r.status_code == 202 and r.json()["status"] == "pending"
    # allowlist отозван после постановки, но до исполнения
    api.c.delete(f"/engagements/{eid}/allowlist/{entry}", headers=api.admin)
    deferred.run_all()
    assert rec.seen == {}
    run = api.c.get(f"/runs/{r.json()['id']}", headers=op).json()
    assert run["status"] == "failed"
    assert ("scanner", "deny", "10.0.0.1", "not_in_allowlist") in api.audit(sqlite_factory)


def test_stop_before_start(api_deferred, deferred, rec):
    api = api_deferred
    eid = api.engagement("10.0.0.0/24")
    op = api.user("op", "operator")
    run_id = _run(api, eid, op, ["10.0.0.1"]).json()["id"]
    r = api.c.post(f"/runs/{run_id}/stop", headers=op)
    assert r.status_code == 200 and r.json()["status"] == "stopped"
    deferred.run_all()
    assert rec.seen == {}
    assert api.c.get(f"/runs/{run_id}", headers=op).json()["status"] == "stopped"
    aud = api.user("aud", "auditor")
    assert api.c.post(f"/runs/{run_id}/stop", headers=aud).status_code == 403


def test_stop_between_modules(api_deferred, deferred, sqlite_factory, rec):
    api = api_deferred
    eid = api.engagement("10.0.0.0/24")
    op = api.user("op", "operator")
    run_id = _run(api, eid, op, ["10.0.0.1"]).json()["id"]
    runs = api.c.app.state.runs
    real = runs.registry["discovery"]

    def discovery_then_stop():
        mod = real()
        orig = mod.run

        def run(ctx):
            out = orig(ctx)
            runs.request_stop(run_id, actor="user:op")   # стоп во время discovery
            return out
        mod.run = run
        return mod
    runs.registry["discovery"] = discovery_then_stop
    deferred.run_all()
    assert "discovery" in rec.seen and "vuln" not in rec.seen
    assert api.c.get(f"/runs/{run_id}", headers=op).json()["status"] == "stopped"
    # частичные находки сохранены, но прогон не годится как базовый для diff
    assert len(api.c.get(f"/runs/{run_id}/findings", headers=op).json()) == 1
    assert ("scanner", "module_skip", "vuln", "stopped") in api.audit(sqlite_factory)


def test_module_error_fails_run_but_keeps_other_findings(api, sqlite_factory):
    eid = api.engagement("10.0.0.0/24")
    op = api.user("op", "operator")
    r = _run(api, eid, op, ["10.0.0.1"], modules=["discovery", "config_audit"])
    assert r.json()["status"] == "failed"
    assert len(api.c.get(f"/runs/{r.json()['id']}/findings", headers=op).json()) == 1
    assert ("scanner", "module_finish", "config_audit", "error") in api.audit(sqlite_factory)


# ---------- отчёты и сравнение ----------
def test_second_run_statuses_and_report_export(api, sqlite_factory, cves):
    eid = api.engagement("10.0.0.0/24")
    op = api.user("op", "operator")
    aud = api.user("aud", "auditor")
    first = _run(api, eid, op, ["10.0.0.1"]).json()["id"]
    cves[:] = ["CVE-2016-6210", "CVE-2018-15473"]       # одна закрыта, одна новая
    second = _run(api, eid, op, ["10.0.0.1"]).json()["id"]

    findings = api.c.get(f"/runs/{second}/findings", headers=aud,
                         params={"module": "vuln"}).json()
    by_vuln = {f["vuln_id"]: f["status"] for f in findings}
    assert by_vuln == {"CVE-2016-6210": "open", "CVE-2018-15473": "new"}
    assert findings[0]["bdu_ids"] == ["BDU:2017-00001"]

    r = api.c.get(f"/runs/{second}/report", headers=aud, params={"format": "json"})
    assert r.status_code == 200, r.text
    assert r.headers["content-type"].startswith("application/json")
    assert f"report-run-{second}.json" in r.headers["content-disposition"]
    report = r.json()
    assert report["meta"]["previous_run_id"] == first
    assert report["meta"]["customer"] == "Ромашка"
    html = api.c.get(f"/runs/{second}/report", headers=aud, params={"format": "html"})
    assert html.status_code == 200 and "Ромашка" in html.text
    assert api.c.get(f"/runs/{second}/report", headers=aud,
                     params={"format": "exe"}).status_code == 422
    brief = api.c.get(f"/runs/{second}/report", headers=aud,
                      params={"format": "json", "variant": "brief"})
    assert brief.status_code == 200, brief.text
    assert f"report-run-{second}-brief.json" in brief.headers["content-disposition"]
    assert brief.json()["meta"]["variant"] == "brief"
    assert "remediation_plan" not in brief.json()
    assert api.c.get(f"/runs/{second}/report", headers=aud,
                     params={"variant": "short"}).status_code == 422
    assert ("user:aud", "export", f"scan_run:{second}", "ok") in api.audit(sqlite_factory)

    runs = api.c.get(f"/engagements/{eid}/runs", headers=aud).json()
    assert [x["id"] for x in runs] == [first, second]


def test_report_not_available_while_running(api_deferred, deferred):
    api = api_deferred
    eid = api.engagement("10.0.0.0/24")
    op = api.user("op", "operator")
    run_id = _run(api, eid, op, ["10.0.0.1"]).json()["id"]
    assert api.c.get(f"/runs/{run_id}/report", headers=op).status_code == 409
    deferred.run_all()
    assert api.c.get(f"/runs/{run_id}/report", headers=op,
                     params={"format": "json"}).status_code == 200


def test_engagement_with_runs_cannot_be_deleted(api):
    eid = api.engagement("10.0.0.0/24")
    op = api.user("op", "operator")
    _run(api, eid, op, ["10.0.0.1"])
    assert api.c.delete(f"/engagements/{eid}", headers=api.admin).status_code == 409
    empty = api.engagement()
    assert api.c.delete(f"/engagements/{empty}", headers=api.admin).status_code == 204


def test_audit_endpoint_filters_and_pages(api):
    aud = api.user("aud", "auditor")
    rows = api.c.get("/audit", headers=aud, params={"action": "user_create"}).json()
    assert {r["target"] for r in rows} == {"user:root", "user:aud"}
    page = api.c.get("/audit", headers=aud, params={"limit": 1}).json()
    older = api.c.get("/audit", headers=aud,
                      params={"limit": 1, "before_id": page[0]["id"]}).json()
    assert older[0]["id"] < page[0]["id"]


# ---------- юнит-тесты ядра ----------
def test_plan_targets_units():
    gate = AllowlistGate(["10.0.0.0/24", "2001:db8::/120"])
    plan = plan_targets(gate, [" 10.0.0.1 ", "10.0.0.1", "2001:db8::5", "10.0.0.0/8",
                               "host.local", "10.0.1.1"], max_targets=1024)
    assert plan.allowed == ["10.0.0.1", "2001:db8::5"]
    assert [(d.target, d.reason) for d in plan.denied] == [
        ("10.0.0.0/8", "too_many_targets"), ("host.local", "not_an_ip"),
        ("10.0.1.1", "not_in_allowlist")]
    capped = plan_targets(gate, ["10.0.0.0/29", "10.0.0.8/29"], max_targets=10)
    assert len(capped.allowed) == 10
    assert [(d.reason, d.count) for d in capped.denied] == [("too_many_targets", 2)]
    assert order_modules(["vuln", "cred_audit", "discovery", "vuln"]) == [
        "discovery", "vuln", "cred_audit"]


def test_tokens_and_passwords():
    now = [1000.0]
    signer = TokenSigner(SECRET, 60, clock=lambda: now[0])
    tok = signer.issue(7)
    assert signer.verify(tok) == 7
    body, sig = tok.split(".")
    assert signer.verify(f"{body}.{sig[:-2]}AA") is None
    assert TokenSigner("y" * 40, 60, clock=lambda: now[0]).verify(tok) is None
    now[0] += 61
    assert signer.verify(tok) is None
    with pytest.raises(ValueError):
        TokenSigner("short", 60)

    h = hash_password("s3cret-password")
    assert verify_password("s3cret-password", h) and not verify_password("nope", h)
    assert not verify_password("x", "garbage")

    t = [0.0]
    th = LoginThrottle(2, 30, clock=lambda: t[0])
    th.failure("a")
    assert not th.locked("a")
    th.failure("a")
    assert th.locked("a")
    t[0] = 31
    assert not th.locked("a")


def test_engagement_hosts_inventory_spans_all_runs(api):
    eid = api.engagement("10.0.0.0/24")
    op = api.user("op", "operator")
    first = _run(api, eid, op, ["10.0.0.1", "10.0.0.2"]).json()["id"]
    second = _run(api, eid, op, ["10.0.0.2", "10.0.0.10"]).json()["id"]

    r = api.c.get(f"/engagements/{eid}/hosts", headers=op)
    assert r.status_code == 200, r.text
    hosts = r.json()
    # список один и тот же, какой бы прогон ни был выбран; сортировка по IP
    assert [h["host"] for h in hosts] == ["10.0.0.1", "10.0.0.2", "10.0.0.10"]
    by = {h["host"]: h for h in hosts}
    assert by["10.0.0.1"]["run_ids"] == [first]
    assert by["10.0.0.2"]["run_ids"] == [first, second]
    assert by["10.0.0.10"]["run_ids"] == [second]
    # сервисы — из последнего прогона, где хост был
    assert by["10.0.0.1"]["services_run_id"] == first
    assert by["10.0.0.2"]["services_run_id"] == second
    assert [s["port"] for s in by["10.0.0.2"]["services"]] == [22]

    aud = api.user("aud", "auditor")
    assert api.c.get(f"/engagements/{eid}/hosts", headers=aud).status_code == 200
    assert api.c.get("/engagements/999/hosts", headers=op).status_code == 404
