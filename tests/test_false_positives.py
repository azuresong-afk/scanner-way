"""Отметка «ложное срабатывание»: API, права, аудит, отчёты."""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from scanner.core.db import AuditLogRow
from scanner.core.models import FalsePositiveMark, Finding, FindingType, Severity
from scanner.core.orchestrator import inline_executor
from scanner.reporting.model import build_report
from scanner.reporting.render import ReportRenderer
from tests.test_api import Api, Recorder, _make, _run


@pytest.fixture
def api(sqlite_factory):
    app = _make(sqlite_factory, Recorder(), ["CVE-2016-6210", "CVE-2016-10009"],
                inline_executor())
    with TestClient(app) as c:
        yield Api(c)


def _vuln(api, run_id, headers, cve="CVE-2016-6210"):
    findings = api.c.get(f"/runs/{run_id}/findings", headers=headers).json()
    return next(f for f in findings if f["vuln_id"] == cve)


def test_mark_and_unmark_false_positive(api, sqlite_factory):
    eid = api.engagement("10.0.0.0/24")
    op = api.user("op", "operator")
    run_id = _run(api, eid, op, ["10.0.0.1"]).json()["id"]
    f = _vuln(api, run_id, op)
    assert f["false_positive"] is None and f["id"] and f["dedup_key"]

    r = api.c.put(f"/findings/{f['id']}/false-positive", headers=op,
                  json={"reason": "  бэкпорт патча в пакете дистрибутива  "})
    assert r.status_code == 200, r.text
    mark = r.json()["false_positive"]
    assert mark["reason"] == "бэкпорт патча в пакете дистрибутива"
    assert mark["marked_by"] == "op" and mark["marked_at"]
    assert _vuln(api, run_id, op)["false_positive"]["reason"] == mark["reason"]
    # другая находка того же хоста не задета
    other = _vuln(api, run_id, op, "CVE-2016-10009")
    assert other["false_positive"] is None

    listed = api.c.get(f"/engagements/{eid}/false-positives", headers=op).json()
    assert [(x["host"], x["vuln_id"]) for x in listed] == [("10.0.0.1", "CVE-2016-6210")]

    r = api.c.delete(f"/findings/{f['id']}/false-positive", headers=op)
    assert r.status_code == 200, r.text
    assert r.json()["false_positive"] is None
    assert _vuln(api, run_id, op)["false_positive"] is None
    assert api.c.delete(f"/findings/{f['id']}/false-positive",
                        headers=op).status_code == 404

    with sqlite_factory() as s:
        rows = list(s.scalars(select(AuditLogRow).where(
            AuditLogRow.action.like("false_positive_%")).order_by(AuditLogRow.id)))
    assert [(r.subject, r.action, r.target) for r in rows] == [
        ("user:op", "false_positive_mark", f"engagement:{eid}"),
        ("user:op", "false_positive_unmark", f"engagement:{eid}")]
    assert rows[0].details["reason"] == "бэкпорт патча в пакете дистрибутива"
    assert rows[0].details["host"] == "10.0.0.1"
    assert rows[0].details["vuln_id"] == "CVE-2016-6210"
    assert rows[1].details["previous_reason"] == "бэкпорт патча в пакете дистрибутива"


def test_mark_carries_over_to_next_runs(api):
    eid = api.engagement("10.0.0.0/24")
    op = api.user("op", "operator")
    first = _run(api, eid, op, ["10.0.0.1", "10.0.0.2"]).json()["id"]
    f = _vuln(api, first, op)
    assert api.c.put(f"/findings/{f['id']}/false-positive", headers=op,
                     json={}).status_code == 200
    second = _run(api, eid, op, ["10.0.0.1", "10.0.0.2"]).json()["id"]
    findings = api.c.get(f"/runs/{second}/findings", headers=op).json()
    marked = {(x["host"], x["vuln_id"]) for x in findings if x["false_positive"]}
    # только на том хосте, где отметили
    assert marked == {("10.0.0.1", "CVE-2016-6210")}
    # снять можно и из следующего прогона
    g = next(x for x in findings if x["false_positive"])
    assert api.c.delete(f"/findings/{g['id']}/false-positive",
                        headers=op).status_code == 200
    assert not any(x["false_positive"] for x in
                   api.c.get(f"/runs/{first}/findings", headers=op).json())


def test_triage_permission(api, sqlite_factory):
    eid = api.engagement("10.0.0.0/24")
    op = api.user("op", "operator")
    aud = api.user("aud", "auditor")
    run_id = _run(api, eid, op, ["10.0.0.1"]).json()["id"]
    f = _vuln(api, run_id, op)
    for headers in (aud, api.admin):
        assert api.c.put(f"/findings/{f['id']}/false-positive", headers=headers,
                         json={}).status_code == 403
        assert api.c.delete(f"/findings/{f['id']}/false-positive",
                            headers=headers).status_code == 403
    # смотреть перечень может и аудитор
    assert api.c.get(f"/engagements/{eid}/false-positives", headers=aud).status_code == 200
    assert api.c.put("/findings/999999/false-positive", headers=op,
                     json={}).status_code == 404
    log = api.audit(sqlite_factory)
    assert ("user:aud", "access_denied", f"PUT /findings/{f['id']}/false-positive",
            "forbidden") in log
    me = api.c.get("/me", headers=op).json()
    assert "triage_findings" in me["permissions"]


def test_report_excludes_false_positives(api):
    eid = api.engagement("10.0.0.0/24")
    op = api.user("op", "operator")
    first = _run(api, eid, op, ["10.0.0.1"]).json()["id"]
    f = _vuln(api, first, op)
    api.c.put(f"/findings/{f['id']}/false-positive", headers=op,
              json={"reason": "сервис не установлен"})
    second = _run(api, eid, op, ["10.0.0.1"]).json()["id"]

    rep = api.c.get(f"/runs/{second}/report", headers=op,
                    params={"format": "json", "compare_to": first}).json()
    ids = {x["vuln_id"] for x in rep["combined"]["findings"]}
    assert "CVE-2016-6210" not in ids and "CVE-2016-10009" in ids
    # ложное не считается ни открытым, ни устранённым
    assert rep["combined"]["trend"]["fixed"] == []
    assert [(x["vuln_id"], x["reason"], x["marked_by"])
            for x in rep["false_positives"]] == [("CVE-2016-6210", "сервис не установлен",
                                                   "op")]
    assert any("ложные срабатывания: 1" in p for p in rep["summary"]["key_points"])
    html = api.c.get(f"/runs/{second}/report", headers=op,
                     params={"format": "html"}).text
    assert "Ложные срабатывания" in html and "сервис не установлен" in html
    docx = api.c.get(f"/runs/{second}/report", headers=op, params={"format": "docx"})
    assert docx.status_code == 200


def test_build_report_without_marks_has_no_appendix():
    f = Finding(module="vuln", host="10.0.0.1", port=22, finding_type=FindingType.VULN,
                title="x", severity=Severity.HIGH, vuln_id="CVE-1")
    plain = build_report([f])
    assert plain.false_positives == [] and plain.summary.total == 1
    html = ReportRenderer().render_html(plain)
    assert "Ложные срабатывания" not in html
    marked = build_report([f], false_positives={
        f.dedup_key(): FalsePositiveMark(f.dedup_key(), reason=None, marked_by="op")})
    assert marked.summary.total == 0 and len(marked.false_positives) == 1
    assert "Ложные срабатывания" in ReportRenderer().render_html(marked)
