"""Приоритизация риска (R6): формула, EPSS/KEV, отчёт, JSON, API."""
from __future__ import annotations

import gzip
import json

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine

from scanner.core.models import Finding, FindingType, Severity
from scanner.core.orchestrator import inline_executor
from scanner.feeds.epss import lookup_epss, parse_epss, sync_epss
from scanner.feeds.kev import lookup_kev, parse_kev, sync_kev
from scanner.reporting.model import build_report
from scanner.reporting.render import ReportRenderer, section_numbers
from scanner.reporting.risk import (
    RiskContext,
    RiskFactors,
    assess,
    exploit_known,
    rank_findings,
)
from tests.test_api import Api, Recorder, _make, _run


def _f(host="10.0.0.1", cve="CVE-2024-0001", sev=Severity.HIGH, cvss=7.5, port=80,
       bdu=None, module="vuln"):
    return Finding(module=module, host=host, port=port, finding_type=FindingType.VULN,
                   title=f"Уязвимость {cve}", severity=sev, vuln_id=cve, cve_ids=[cve],
                   bdu_ids=bdu or [], cvss=cvss)


# ---------- формула ----------
def test_cvss_only_is_base_score():
    a = assess(RiskFactors(cvss=7.5, severity=Severity.HIGH))
    assert a.score == 75.0 and a.label == "high"
    assert a.reasons == ["CVSS 7.5"]


def test_no_cvss_falls_back_to_severity():
    a = assess(RiskFactors(cvss=None, severity=Severity.MEDIUM))
    assert a.score == 55.0 and a.label == "medium"


def test_info_is_not_ranked():
    assert assess(RiskFactors(cvss=None, severity=Severity.INFO)) is None


def test_kev_lifts_medium_to_high_and_is_explained():
    a = assess(RiskFactors(cvss=5.5, severity=Severity.MEDIUM, in_kev=True))
    assert a.score == 82.5 and a.label == "high"
    assert any("KEV" in r for r in a.reasons)


@pytest.mark.parametrize("epss,k", [(None, 1.0), (0.005, 1.0), (0.01, 1.05),
                                    (0.1, 1.15), (0.49, 1.15), (0.5, 1.30), (0.99, 1.30)])
def test_epss_thresholds(epss, k):
    a = assess(RiskFactors(cvss=5.0, severity=Severity.MEDIUM, epss=epss))
    assert a.score == round(50.0 * k, 1)


def test_exploit_and_criticality_multiply_and_cap_at_100():
    a = assess(RiskFactors(cvss=9.8, severity=Severity.CRITICAL, in_kev=True, epss=0.9,
                           exploit_available=True, criticality="critical"))
    assert a.score == 100.0 and a.label == "critical"
    low = assess(RiskFactors(cvss=5.0, severity=Severity.MEDIUM, criticality="low"))
    assert low.score == 40.0 and low.label == "medium"
    assert any("критичность актива" in r for r in low.reasons)


def test_unknown_criticality_means_medium():
    a = assess(RiskFactors(cvss=5.0, severity=Severity.MEDIUM, criticality="bogus"))
    assert a.score == 50.0


@pytest.mark.parametrize("text,expected", [
    ("Существует", True), ("Существует в открытом доступе", True),
    ("Данные уточняются", False), ("Отсутствует", False), ("", False), (None, False)])
def test_exploit_known(text, expected):
    assert exploit_known(text) is expected


# ---------- ранжирование ----------
def test_rank_is_deterministic_and_degrades_without_feeds():
    fs = [_f("10.0.0.2", "CVE-2024-0002"), _f("10.0.0.1", "CVE-2024-0001"),
          _f("10.0.0.3", "CVE-2024-0003", Severity.CRITICAL, 9.8)]
    r1 = rank_findings(fs)
    r2 = rank_findings(list(reversed(fs)))
    assert {k: v.rank for k, v in r1.items()} == {k: v.rank for k, v in r2.items()}
    assert r1[fs[2].dedup_key()].rank == 1             # критичный CVSS — первый
    assert r1[fs[1].dedup_key()].rank == 2             # равные баллы — по хосту


def test_context_epss_kev_exploit_criticality_change_order():
    a, b = _f("10.0.0.1", "CVE-2024-0001"), _f("10.0.0.2", "CVE-2024-0002", bdu=["BDU:2024-1"])
    ctx = RiskContext(epss={"CVE-2024-0002": (0.6, 0.97)}, kev=frozenset({"CVE-2024-0002"}),
                      exploit_bdu=frozenset({"BDU:2024-1"}), criticality={"10.0.0.1": "low"})
    r = rank_findings([a, b], ctx)
    assert r[b.dedup_key()].rank == 1 and r[a.dedup_key()].rank == 2
    d = r[b.dedup_key()].to_dict()
    assert d["factors"]["in_kev"] and d["factors"]["epss"] == 0.6
    assert d["factors"]["exploit_available"]


def test_info_findings_skipped_in_ranking():
    info = Finding(module="discovery", host="10.0.0.1", finding_type=FindingType.INFO,
                   title="ОС", severity=Severity.INFO, vuln_id="os")
    assert rank_findings([info]) == {}


# ---------- загрузчики ----------
CSV = ("#model_version:v2025.03.14,score_date:2026-10-30T00:00:00+0000\n"
       "cve,epss,percentile\nCVE-2024-0001,0.5,0.9\nbad,0.1,0.1\nCVE-2024-0002,2,0.1\n"
       "CVE-2024-0003,0.01,\n")


def test_parse_epss_handles_gzip_and_skips_garbage():
    rows, as_of = parse_epss(gzip.compress(CSV.encode()))
    assert [r.cve for r in rows] == ["CVE-2024-0001", "CVE-2024-0003"]
    assert as_of.startswith("2026-10-30") and rows[1].percentile is None


def test_epss_and_kev_roundtrip_replace_and_lookup():
    engine = create_engine("sqlite://")
    rows, as_of = parse_epss(CSV.encode())
    assert sync_epss(engine, rows, as_of) == 2
    assert lookup_epss(engine, ["cve-2024-0001", "CVE-1999-1"]) == {"CVE-2024-0001": (0.5, 0.9)}
    assert sync_epss(engine, rows[:1], as_of) == 1          # полная замена
    assert lookup_epss(engine, ["CVE-2024-0003"]) == {}

    doc = json.dumps({"vulnerabilities": [
        {"cveID": "CVE-2024-0001", "dateAdded": "2024-01-02", "dueDate": "2024-02-01"},
        {"cveID": "junk"}, {"cveID": "CVE-2024-0001"}]}).encode()
    entries = parse_kev(doc)
    assert entries == [("CVE-2024-0001", None)]
    assert sync_kev(engine, parse_kev(doc.replace(b'{"cveID": "CVE-2024-0001"}', b'{}'))) == 1
    assert lookup_kev(engine, ["CVE-2024-0001", "CVE-2024-0009"]) == {"CVE-2024-0001"}


def test_kev_rejects_wrong_document():
    with pytest.raises(ValueError):
        parse_kev(b'{"x": 1}')


def test_lookups_degrade_when_tables_missing():
    engine = create_engine("sqlite://")
    assert lookup_epss(engine, ["CVE-2024-0001"]) == {}
    assert lookup_kev(engine, ["CVE-2024-0001"]) == frozenset()


# ---------- отчёт ----------
def _report(ctx):
    fs = [_f("10.0.0.1", "CVE-2024-0001"),
          _f("10.0.0.2", "CVE-2024-0002", Severity.MEDIUM, 5.5)]
    return build_report(fs, risk=ctx)


def test_report_has_priority_section_with_factors_in_json_and_html():
    ctx = RiskContext(kev=frozenset({"CVE-2024-0002"}), criticality={"10.0.0.2": "critical"})
    rep = _report(ctx)
    assert [p.risk.rank for p in rep.priority] == [1, 2]
    assert rep.priority[0].view.finding.host == "10.0.0.2"
    data = json.loads(ReportRenderer().render(rep, "json"))
    items = data["priority"]["items"]
    assert items[0]["factors"]["in_kev"] is True
    assert items[0]["factors"]["asset_criticality"] == "critical"
    assert data["priority"]["formula"] and data["priority"]["hosts"][0]["best_rank"] == 1
    assert data["combined"]["findings"][0]["priority"]["rank"] in (1, 2)
    html = ReportRenderer().render(rep, "html").decode()
    assert "Исправить в первую очередь" in html and "CISA KEV" in html
    assert "срок" not in html.split("Исправить в первую очередь", 1)[1][:3000].lower()


def test_report_without_risk_is_unchanged():
    rep = build_report([_f()])
    assert not rep.has_priority and rep.priority == []
    data = json.loads(ReportRenderer().render(rep, "json"))
    assert "priority" not in data
    assert section_numbers(False) == {"summary": 1, "plan": 2, "trend": 3,
                                      "hosts": 4, "details": 5}
    assert section_numbers(True, True)["priority"] == 2


def test_docx_renders_priority():
    out = ReportRenderer().render(_report(RiskContext()), "docx")
    assert out[:2] == b"PK"


# ---------- API ----------
@pytest.fixture
def api(sqlite_factory):
    app = _make(sqlite_factory, Recorder(), ["CVE-2016-6210"], inline_executor())
    with TestClient(app) as c:
        yield Api(c)


def test_api_findings_carry_priority_and_asset_criticality_raises_it(api, sqlite_factory):
    eid = api.engagement("10.0.0.0/24")
    op = api.user("op", "operator")
    run = _run(api, eid, op, ["10.0.0.1"]).json()
    base = [f for f in api.c.get(f"/runs/{run['id']}/findings", headers=op).json()
            if f["priority"]]
    assert base and base[0]["priority"]["rank"] == 1
    before = base[0]["priority"]["score"]

    r = api.c.post(f"/engagements/{eid}/assets", headers=api.admin,
                   json={"address": "10.0.0.1", "criticality": "critical"})
    assert r.status_code == 201
    after = next(f for f in api.c.get(f"/runs/{run['id']}/findings", headers=op).json()
                 if f["priority"])["priority"]
    assert after["score"] >= before
    assert after["factors"]["asset_criticality"] == "critical"
    assert after["reasons"]

    rep = api.c.get(f"/runs/{run['id']}/report?format=json", headers=op)
    assert rep.status_code == 200 and rep.json()["priority"]["items"]
