"""Профили соответствия ФСТЭК №17/21/239 и CIS (R5): каталог, движок, API, отчёт."""
from __future__ import annotations

import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from scanner.api.main import create_app
from scanner.api.settings import ApiSettings
from scanner.compliance.catalog import CatalogError, default_catalog, load_catalog
from scanner.compliance.engine import (
    FAILED,
    MANUAL,
    NA,
    PASSED,
    Selection,
    evaluate_run,
    summarize,
)
from scanner.compliance.facts import merge_run_facts
from scanner.core.models import Finding, FindingType, HostOs, ServiceInfo, Severity
from scanner.core.orchestrator import inline_executor
from scanner.modules.base import ScanContext, ScanModule
from scanner.modules.config_audit import parse_lynis_report, parse_openscap_results
from scanner.reporting.model import build_report
from scanner.reporting.remediation import RemediationResolver
from scanner.reporting.render import ReportRenderer

FIXTURES = Path(__file__).parent / "fixtures"
R = "xccdf_org.ssgproject.content_rule_"
LINUX, WIN, BARE = "10.0.0.5", "10.0.0.7", "10.0.0.9"


def cfg(host: str, rule: str, title: str = "нарушение") -> Finding:
    return Finding(module="config_audit", host=host, finding_type=FindingType.CONFIG,
                   title=f"[OpenSCAP] {title}", severity=Severity.MEDIUM, vuln_id=R + rule)


def policy(host: str, key: str) -> Finding:
    return Finding(module="password_policy", host=host, finding_type=FindingType.CONFIG,
                   title=key, severity=Severity.MEDIUM, vuln_id=f"POLICY:password-{key}")


@pytest.fixture
def catalog():
    return default_catalog()


@pytest.fixture
def fixture_run():
    """Linux-хост с OpenSCAP+парольной политикой, Windows-хост с параметрами
    безопасности, хост без учётки (только discovery)."""
    facts = {
        LINUX: {"openscap": {"profile": R.replace("rule", "profile") + "cis_level1_server",
                             "rules": {R + "accounts_passwords_pam_faillock_deny": "pass",
                                       R + "accounts_password_pam_minlen": "fail",
                                       R + "sshd_disable_root_login": "pass",
                                       R + "no_empty_passwords": "pass",
                                       R + "accounts_tmout": "notapplicable"},
                             "cis": {}},
                "password_policy": True, "discovery": True, "linux_inventory": True},
        WIN: {"windows": True, "discovery": True,
              "windows_policy": {"SMB1": "1", "RDP_fDenyTSConnections": "1",
                                 "LmCompatibilityLevel": "5", "UAC_EnableLUA": "1"}},
        BARE: {"discovery": True},
    }
    findings = [cfg(LINUX, "accounts_password_pam_minlen", "minlen"),
                policy(LINUX, "min-length")]
    services = [ServiceInfo(BARE, 23, "tcp", "telnet"), ServiceInfo(LINUX, 22, "tcp", "ssh")]
    return facts, findings, services


def rows_by(rows, profile, host=None):
    return {r.control: r for r in rows if r.profile == profile and r.host == host}


# ---------- каталог ----------
def test_catalog_loads_all_profiles(catalog):
    assert list(catalog.profiles) == ["fstec-17", "fstec-21", "fstec-239",
                                      "cis-controls-v8", "cis-benchmark"]
    p17 = catalog.profile("fstec-17")
    assert p17.levels == ("К1", "К2", "К3") and p17.default_level == "К2"
    # базовый набор растёт с классом: К3 ⊂ К2 ⊂ К1
    k3, k2, k1 = ({c.id for c in p17.base_set(lv)} for lv in ("К3", "К2", "К1"))
    assert k3 <= k2 <= k1 and "ИАФ.2" in k2 and "ИАФ.2" not in k3
    # организационные меры помечены как ручные, технические — со ссылками на проверки
    assert p17.control("ИНЦ.1").manual and not p17.control("УПД.6").manual
    for p in catalog.profiles.values():
        for c in p.controls:
            assert all(ch in catalog.checks for ch in c.checks)


def test_catalog_rejects_unknown_check(tmp_path):
    (tmp_path / "checks.yaml").write_text(
        "checks:\n  - {id: a, title: A, remediation: r, cred_audit: true}\n", "utf-8")
    (tmp_path / "p.yaml").write_text(
        "id: p\ntitle: P\nshort: P\ndocument: D\nurl: https://x\nlevel_label: L\n"
        "levels: [A]\ngroups:\n  - code: G\n    title: G\n    controls:\n"
        "      - {id: G.1, title: t, checks: [nope]}\n", "utf-8")
    with pytest.raises(CatalogError, match="нет проверок"):
        load_catalog(tmp_path)


# ---------- факты модулей ----------
def test_openscap_and_lynis_facts():
    facts: dict = {}
    parse_openscap_results((FIXTURES / "oscap_results.xml").read_bytes(), LINUX,
                           facts=facts)
    assert facts["profile"].endswith("profile_standard")
    assert facts["rules"][R + "sshd_disable_root_login"] == "fail"
    assert facts["rules"][R + "sshd_disable_empty_passwords"] == "pass"
    lf: dict = {}
    parse_lynis_report("tests_executed=AUTH-9262|SSH-7408|bogus|\n"
                       "suggestion[]=AUTH-9262|Install pam_pwquality|-|-|\n", LINUX, facts=lf)
    assert lf == {"executed": ["AUTH-9262", "SSH-7408"]}


def test_merge_run_facts_marks_coverage():
    class Inv:
        os_id = "windows"
    out = merge_run_facts({LINUX: {"lynis": {}}}, completed={"discovery", "password_policy",
                                                              "vuln"},
                          discovered={LINUX, WIN}, inventory={WIN: Inv()},
                          policy_hosts={LINUX}, targets=[LINUX, WIN, BARE])
    assert out[LINUX]["password_policy"] and out[LINUX]["network_vuln"]
    assert out[WIN]["windows"] and BARE not in out       # discovery его не нашёл


# ---------- движок ----------
def test_statuses_per_host(catalog, fixture_run):
    rows = evaluate_run(catalog, *fixture_run, profiles={"fstec-17"})
    lin, win, bare = (rows_by(rows, "fstec-17", h) for h in (LINUX, WIN, BARE))
    assert lin["УПД.6"].status == PASSED          # faillock deny: pass, политика без lockout
    assert lin["ИАФ.4"].status == FAILED          # minlen fail (OpenSCAP + политика)
    failures = [f for c in lin["ИАФ.4"].evidence["checks"] for f in c["failures"]]
    assert {f.get("vuln_id") for f in failures} >= {R + "accounts_password_pam_minlen",
                                                    "POLICY:password-min-length"}
    assert lin["УПД.10"].status == NA             # TMOUT notapplicable, sshd idle не в профиле
    assert win["ЗИС.11"].status == FAILED         # SMB1 = 1
    assert win["ИАФ.1"].status == PASSED          # LmCompatibilityLevel 5 ≥ 3
    assert bare["УПД.13"].status == FAILED        # telnet открыт
    # меры без автопроверки — по одной строке на профиль, без хоста
    manual = rows_by(rows, "fstec-17")
    assert manual and all(r.status == MANUAL for r in manual.values())
    assert "ИНЦ.1" in manual and "УПД.6" not in manual


def test_percent_ignores_manual_and_unchecked(catalog, fixture_run):
    p = catalog.profile("fstec-17")
    rows = evaluate_run(catalog, *fixture_run, profiles={p.id})
    s = summarize(p, catalog, rows, selection=Selection(level="К1"))
    c = s["counts"]
    assert c[MANUAL] > 0 and c[NA] > 0
    assert s["percent"] == round(100 * c[PASSED] / (c[PASSED] + c[FAILED]), 1)
    by_id = {i["id"]: i for i in s["controls"]}
    assert by_id["ИАФ.4"]["status"] == FAILED and by_id["УПД.6"]["status"] == PASSED
    assert {m["id"] for m in s["manual"]} >= {"ИНЦ.1", "УКФ.1"}
    # ручные и непроверенные меры не меняют процент: исключаем их из набора — то же число
    drop = frozenset(m["id"] for m in s["manual"]) | frozenset(
        i["id"] for i in s["controls"] if i["status"] == NA)
    s2 = summarize(p, catalog, rows, selection=Selection(level="К1", excluded=drop))
    assert s2["percent"] == s["percent"] and s2["counts"][MANUAL] == 0
    # провал — с рекомендацией и хостом
    fail = next(f for f in s["failures"] if f["id"] == "ИАФ.4")
    assert fail["failed_hosts"][0]["host"] == LINUX
    assert any(r["check"] == "password_length" and r["remediation"]
               for r in fail["recommendations"])


def test_exact_percent_on_fixture(catalog):
    """Три проверяемые меры: две выполнены, одна нет -> 66.7%."""
    facts = {LINUX: {"openscap": {"profile": "p", "rules": {
        R + "accounts_passwords_pam_faillock_deny": "pass",      # УПД.6
        R + "sshd_disable_root_login": "pass",                   # УПД.4
        R + "accounts_tmout": "fail"}}}}                         # УПД.10
    findings = [cfg(LINUX, "accounts_tmout")]
    p = catalog.profile("fstec-17")
    rows = evaluate_run(catalog, facts, findings, profiles={p.id})
    keep = {"УПД.4", "УПД.6", "УПД.10", "ИНЦ.1"}
    sel = Selection(level="К2", excluded=frozenset(c.id for c in p.controls) - keep)
    s = summarize(p, catalog, rows, selection=sel)
    assert s["counts"] == {PASSED: 2, FAILED: 1, MANUAL: 1, NA: 0}
    assert s["percent"] == 66.7 and s["hosts"][0]["percent"] == 66.7
    # отметка «ложное срабатывание» снимает провал
    s_fp = summarize(p, catalog, rows, selection=sel,
                     false_positives={findings[0].dedup_key()})
    assert s_fp["percent"] == 100.0 and not s_fp["failures"]


def test_levels_and_groups(catalog, fixture_run):
    p = catalog.profile("fstec-21")
    rows = evaluate_run(catalog, *fixture_run, profiles={p.id})
    uz4 = summarize(p, catalog, rows, selection=Selection(level="УЗ4"))
    uz1 = summarize(p, catalog, rows, selection=Selection(level="УЗ1"))
    assert uz4["automated"] < uz1["automated"]
    s = summarize(p, catalog, rows, groups={"Серверы": {LINUX}, "Пустая": {"10.9.9.9"}})
    assert [g["group"] for g in s["groups"]] == ["Серверы"]
    only = summarize(p, catalog, rows, hosts={WIN})
    assert [h["host"] for h in only["hosts"]] == [WIN]


def test_cis_benchmark_dynamic(catalog):
    facts = {LINUX: {"openscap": {
        "profile": "xccdf_org.ssgproject.content_profile_cis_level1_server",
        "rules": {R + "a": "pass", R + "b": "fail", R + "c": "pass"},
        "cis": {R + "a": {"refs": ["1.1.1"], "title": "A"},
                R + "b": {"refs": ["5.2.1"], "title": "B"},
                R + "c": {"refs": ["5.2.1"], "title": "C"}}}},
             WIN: {"openscap": {"profile": "standard", "rules": {R + "a": "pass"},
                                "cis": {R + "a": {"refs": ["1.1.1"]}}}}}
    p = catalog.profile("cis-benchmark")
    rows = evaluate_run(catalog, facts, [cfg(LINUX, "b")], profiles={p.id})
    assert {r.host for r in rows} == {LINUX}      # не CIS-профиль OpenSCAP — не входит
    s = summarize(p, catalog, rows)
    assert s["counts"][PASSED] == 1 and s["counts"][FAILED] == 1 and s["percent"] == 50.0


def test_windows_rdp_nla_condition(catalog):
    p = catalog.profile("fstec-17")
    on = {WIN: {"windows_policy": {"RDP_fDenyTSConnections": "0", "RDP_NLA": "0"}}}
    off = {WIN: {"windows_policy": {"RDP_fDenyTSConnections": "1"}}}
    a = evaluate_run(catalog, on, [], profiles={p.id})
    b = evaluate_run(catalog, off, [], profiles={p.id})
    chk = lambda rows: next(c for c in rows_by(rows, p.id, WIN)["УПД.13"].evidence["checks"]
                            if c["id"] == "rdp_nla")["status"]
    assert chk(a) == FAILED and chk(b) == PASSED


# ---------- отчёт ----------
def test_report_section(catalog, fixture_run):
    p = catalog.profile("fstec-17")
    rows = evaluate_run(catalog, *fixture_run, profiles={p.id})
    summary = summarize(p, catalog, rows)
    report = build_report(fixture_run[1], compliance=[summary])
    html = ReportRenderer().render(report, "html").decode()
    assert "Соответствие требованиям" in html and "Невыполненные меры" in html
    assert "Проверяется вручную" in html and "ИАФ.4" in html
    data = json.loads(ReportRenderer().render(report, "json"))
    assert data["compliance"][0]["percent"] == summary["percent"]
    brief = json.loads(ReportRenderer().render(report, "json", variant="brief"))
    rec = brief["compliance"][0]["failures"][0]["recommendations"][0]
    assert "remediation" not in rec and "doc" in rec
    assert ReportRenderer().render(report, "docx")[:2] == b"PK"


# ---------- API и прогон ----------
SECRET = "x" * 40
PASSWORD = "correct-horse-battery"


class FakeAudit(ScanModule):
    """Аудит конфигураций: факт OpenSCAP + одна находка, как у config_audit."""
    name = "config_audit"

    def run(self, ctx: ScanContext) -> list[Finding]:
        ctx.services = [ServiceInfo(t, 23, "tcp", "telnet") for t in ctx.targets]
        ctx.hosts = {t: HostOs(t, "Linux", "linux") for t in ctx.targets}
        for t in ctx.targets:
            ctx.compliance_facts[t] = {"openscap": {"profile": "standard", "rules": {
                R + "sshd_disable_root_login": "fail",
                R + "accounts_passwords_pam_faillock_deny": "pass"}}}
        return [cfg(t, "sshd_disable_root_login") for t in ctx.targets]


@pytest.fixture
def client(sqlite_factory):
    settings = ApiSettings(secret=SECRET, bootstrap_admin="root",
                           bootstrap_password=PASSWORD)
    app = create_app(session_factory=sqlite_factory, settings=settings,
                     registry={"config_audit": FakeAudit}, executor=inline_executor(),
                     resolver_factory=lambda f: RemediationResolver())
    with TestClient(app) as c:
        tok = c.post("/auth/token", json={"username": "root", "password": PASSWORD}).json()
        c.headers["Authorization"] = f"Bearer {tok['access_token']}"
        yield c


def test_api_end_to_end(client, sqlite_factory):
    from scanner.api.rbac import set_user_roles
    from scanner.core.db import User
    with sqlite_factory() as s:      # admin + право запуска для теста
        root = s.query(User).filter_by(username="root").one()
        set_user_roles(s, root.id, ["admin", "operator", "host_credentials"])
        s.commit()
    eid = client.post("/engagements", json={"name": "Д"}).json()["id"]
    client.post(f"/engagements/{eid}/allowlist", json={"cidr": "10.0.0.0/24"})
    assert client.get("/compliance/profiles").json()[0]["id"] == "fstec-17"
    r = client.put(f"/engagements/{eid}/compliance-profiles/fstec-17",
                   json={"level": "К9"})
    assert r.status_code == 422
    r = client.put(f"/engagements/{eid}/compliance-profiles/fstec-17",
                   json={"level": "К3", "excluded": ["УПД.13"]})
    assert r.status_code == 200 and r.json()["level"] == "К3"
    assert client.put(f"/engagements/{eid}/compliance-profiles/nope",
                      json={}).status_code == 404

    run = client.post(f"/engagements/{eid}/runs",
                      json={"targets": ["10.0.0.5"], "modules": ["config_audit"],
                            "credential_ids": []})
    if run.status_code == 422:      # модулю нужна учётка — заводим её
        cred = client.post(f"/engagements/{eid}/credentials", json={
            "name": "c", "auth": "password", "username": "u", "password": "p",
            "targets": ["10.0.0.0/24"]})
        assert cred.status_code == 201, cred.text
        run = client.post(f"/engagements/{eid}/runs",
                          json={"targets": ["10.0.0.5"], "modules": ["config_audit"],
                                "credential_ids": [cred.json()["id"]]})
    assert run.status_code in (200, 201, 202), run.text
    rid = run.json()["id"]
    s = client.get(f"/runs/{rid}/compliance", params={"profile": "fstec-17"}).json()
    assert s["has_results"] and s["level"] == "К3"
    ids = {c["id"]: c["status"] for c in s["controls"]}
    assert ids["УПД.4"] == FAILED and ids["УПД.6"] == PASSED and "УПД.13" not in ids
    assert s["adapted"]["excluded"] == ["УПД.13"]
    assert client.get(f"/runs/{rid}/compliance",
                      params={"profile": "fstec-17", "level": "Z"}).status_code == 422
    assert client.post(f"/runs/{rid}/compliance/recompute").json()["rows"] > 0
    rep = client.get(f"/runs/{rid}/report", params={"format": "json"}).json()
    assert rep["compliance"][0]["profile"]["id"] == "fstec-17"
    # профиль без «в отчёт» — раздела нет
    client.put(f"/engagements/{eid}/compliance-profiles/fstec-17",
               json={"level": "К3", "in_report": False})
    assert "compliance" not in client.get(f"/runs/{rid}/report",
                                          params={"format": "json"}).json()
