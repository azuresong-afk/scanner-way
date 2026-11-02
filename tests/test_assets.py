"""Активы договора: CRUD, фильтры, права, аудит, отчёт по группе."""
from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient

from scanner.core import assets as svc
from scanner.core.models import Finding, FindingType, Severity
from scanner.core.orchestrator import inline_executor
from scanner.reporting.model import build_report
from tests.test_api import Api, Recorder, _make, _run


@pytest.fixture
def api(sqlite_factory):
    app = _make(sqlite_factory, Recorder(), ["CVE-2016-6210"], inline_executor())
    with TestClient(app) as c:
        yield Api(c)


def _mk(api, eid, address, **kw):
    r = api.c.post(f"/engagements/{eid}/assets", headers=api.admin,
                   json={"address": address, **kw})
    assert r.status_code == 201, r.text
    return r.json()


def test_create_normalizes_and_rejects_duplicates(api):
    eid = api.engagement("10.0.0.0/24")
    a = _mk(api, eid, " 10.0.0.5 ", owner=" Иванов ", criticality="high",
            tags=["Prod", "prod", " DMZ "], hostname="srv-1")
    assert a["address"] == "10.0.0.5" and a["owner"] == "Иванов"
    assert a["tags"] == ["dmz", "prod"] and a["criticality"] == "high"
    dup = api.c.post(f"/engagements/{eid}/assets", headers=api.admin,
                     json={"address": "10.0.0.5"})
    assert dup.status_code == 409
    # тот же адрес в другом договоре — можно
    other = api.engagement("10.0.0.0/24")
    _mk(api, other, "10.0.0.5")
    for bad in ({"address": "not-an-ip"}, {"address": "10.0.0.6", "criticality": "urgent"},
                {"address": "10.0.0.6", "tags": ["x" * 41]}):
        assert api.c.post(f"/engagements/{eid}/assets", headers=api.admin,
                          json=bad).status_code == 422


def test_default_criticality_and_update(api):
    eid = api.engagement("10.0.0.0/24")
    a = _mk(api, eid, "10.0.0.7")
    assert a["criticality"] == "medium"
    r = api.c.patch(f"/engagements/{eid}/assets/{a['id']}", headers=api.admin,
                    json={"owner": "ИТ", "criticality": "critical", "tags": ["db"],
                          "notes": "основная БД"})
    assert r.status_code == 200, r.text
    assert (r.json()["owner"], r.json()["criticality"], r.json()["tags"]) == (
        "ИТ", "critical", ["db"])
    # непереданные поля не трогаем; пустая строка очищает
    r = api.c.patch(f"/engagements/{eid}/assets/{a['id']}", headers=api.admin,
                    json={"owner": ""})
    assert r.json()["owner"] is None and r.json()["tags"] == ["db"]
    assert api.c.patch(f"/engagements/{eid}/assets/{a['id']}", headers=api.admin,
                       json={"criticality": None}).status_code == 422
    b = _mk(api, eid, "10.0.0.8")
    assert api.c.patch(f"/engagements/{eid}/assets/{b['id']}", headers=api.admin,
                       json={"address": "10.0.0.7"}).status_code == 409
    assert api.c.delete(f"/engagements/{eid}/assets/{b['id']}",
                        headers=api.admin).status_code == 204
    assert api.c.get(f"/engagements/{eid}/assets/{b['id']}",
                     headers=api.admin).status_code == 404


def test_groups_filters_and_bulk(api):
    eid = api.engagement("10.0.0.0/24")
    g = api.c.post(f"/engagements/{eid}/asset-groups", headers=api.admin,
                   json={"name": " Бухгалтерия "}).json()
    assert g["name"] == "Бухгалтерия" and g["asset_count"] == 0
    assert api.c.post(f"/engagements/{eid}/asset-groups", headers=api.admin,
                      json={"name": "бухгалтерия"}).status_code == 409
    ids = [_mk(api, eid, f"10.0.0.{i}")["id"] for i in (1, 2, 3)]
    _mk(api, eid, "10.0.0.20", criticality="low", owner="Петров")
    r = api.c.post(f"/engagements/{eid}/assets/bulk", headers=api.admin,
                   json={"asset_ids": ids[:2], "add_tags": ["Prod"],
                         "add_group_ids": [g["id"]], "criticality": "high"})
    assert r.status_code == 200, r.text
    assert all(a["tags"] == ["prod"] and a["criticality"] == "high"
               and a["groups"] == [{"id": g["id"], "name": "Бухгалтерия"}]
               for a in r.json())

    def q(**params):
        r = api.c.get(f"/engagements/{eid}/assets", headers=api.admin, params=params)
        assert r.status_code == 200, r.text
        return [a["address"] for a in r.json()]

    assert q() == ["10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.20"]  # числовой порядок
    assert q(tag="PROD") == ["10.0.0.1", "10.0.0.2"]
    assert q(group_id=g["id"]) == ["10.0.0.1", "10.0.0.2"]
    assert q(criticality="low") == ["10.0.0.20"]
    assert q(owner="петров") == ["10.0.0.20"]
    assert q(q="0.0.3") == ["10.0.0.3"]
    assert q(tag="prod", criticality="medium") == []
    assert api.c.get(f"/engagements/{eid}/asset-groups",
                     headers=api.admin).json()[0]["asset_count"] == 2
    assert api.c.get(f"/engagements/{eid}/asset-tags",
                     headers=api.admin).json() == [{"tag": "prod", "count": 2}]

    # снять тег и группу
    r = api.c.post(f"/engagements/{eid}/assets/bulk", headers=api.admin,
                   json={"asset_ids": ids[:1], "remove_tags": ["prod"],
                         "remove_group_ids": [g["id"]]})
    assert r.json()[0]["tags"] == [] and r.json()[0]["groups"] == []
    # чужие/несуществующие активы и группы
    assert api.c.post(f"/engagements/{eid}/assets/bulk", headers=api.admin,
                      json={"asset_ids": [ids[0], 9999]}).status_code == 404
    assert api.c.post(f"/engagements/{eid}/assets/bulk", headers=api.admin,
                      json={"asset_ids": ids, "add_group_ids": [9999]}).status_code == 422

    # переименование и удаление группы не удаляет активы
    assert api.c.patch(f"/engagements/{eid}/asset-groups/{g['id']}", headers=api.admin,
                       json={"name": "Финансы"}).json()["name"] == "Финансы"
    assert api.c.delete(f"/engagements/{eid}/asset-groups/{g['id']}",
                        headers=api.admin).status_code == 204
    assert len(q()) == 4 and q(group_id=g["id"]) == []


def test_group_of_other_engagement_is_rejected(api):
    e1, e2 = api.engagement("10.0.0.0/24"), api.engagement("10.0.0.0/24")
    g = api.c.post(f"/engagements/{e2}/asset-groups", headers=api.admin,
                   json={"name": "x"}).json()
    r = api.c.post(f"/engagements/{e1}/assets", headers=api.admin,
                   json={"address": "10.0.0.1", "group_ids": [g["id"]]})
    assert r.status_code == 422
    assert api.c.delete(f"/engagements/{e1}/asset-groups/{g['id']}",
                        headers=api.admin).status_code == 404


def test_permissions_and_audit(api, sqlite_factory):
    eid = api.engagement("10.0.0.0/24")
    auditor, op = api.user("aud", "auditor"), api.user("op", "operator")
    a = _mk(api, eid, "10.0.0.5")
    assert api.c.get(f"/engagements/{eid}/assets", headers=auditor).status_code == 200
    for h in (auditor, op):
        assert api.c.post(f"/engagements/{eid}/assets", headers=h,
                          json={"address": "10.0.0.9"}).status_code == 403
        assert api.c.delete(f"/engagements/{eid}/assets/{a['id']}",
                            headers=h).status_code == 403
    assert api.c.get(f"/engagements/{eid}/assets").status_code == 401
    api.c.patch(f"/engagements/{eid}/assets/{a['id']}", headers=api.admin,
                json={"owner": "ИТ"})
    actions = [x[1] for x in api.audit(sqlite_factory)]
    assert "asset_create" in actions and "asset_update" in actions
    assert actions.count("access_denied") >= 4


def test_enrichment_and_import_discovered(api):
    eid = api.engagement("10.0.0.0/24")
    op = api.user("op", "operator")
    run_id = _run(api, eid, op, ["10.0.0.1"]).json()["id"]
    r = api.c.post(f"/engagements/{eid}/assets/import-discovered", headers=api.admin)
    assert r.status_code == 201, r.text
    assert [a["address"] for a in r.json()] == ["10.0.0.1"]
    assert api.c.post(f"/engagements/{eid}/assets/import-discovered",
                      headers=api.admin).json() == []        # повторно — ничего нового
    got = api.c.get(f"/engagements/{eid}/assets", headers=api.admin).json()[0]
    assert got["last_run_id"] == run_id and got["findings_total"] >= 1
    assert sum(got["finding_counts"].values()) == got["findings_total"]
    # отметка «ложное срабатывание» убирает находку из счётчика
    f = next(x for x in api.c.get(f"/runs/{run_id}/findings", headers=op).json()
             if x["vuln_id"] == "CVE-2016-6210")
    api.c.put(f"/findings/{f['id']}/false-positive", headers=op, json={"reason": "тест"})
    after = api.c.get(f"/engagements/{eid}/assets", headers=api.admin).json()[0]
    assert after["findings_total"] == got["findings_total"] - 1


def test_report_by_group_contains_only_its_hosts(api):
    eid = api.engagement("10.0.0.0/24")
    op = api.user("op", "operator")
    run_id = _run(api, eid, op, ["10.0.0.1", "10.0.0.2"]).json()["id"]
    g = api.c.post(f"/engagements/{eid}/asset-groups", headers=api.admin,
                   json={"name": "DMZ"}).json()
    a = _mk(api, eid, "10.0.0.1", group_ids=[g["id"]])
    _mk(api, eid, "10.0.0.2")
    full = json.loads(api.c.get(f"/runs/{run_id}/report?format=json", headers=op).text)
    part = api.c.get(f"/runs/{run_id}/report?format=json&group_id={g['id']}", headers=op)
    assert part.status_code == 200, part.text
    assert "group-" in part.headers["content-disposition"]
    rep = json.loads(part.text)
    hosts = {f["host"] for f in rep["combined"]["findings"]}
    assert hosts == {"10.0.0.1"} and rep["meta"]["group"] == "DMZ"
    assert {f["host"] for f in full["combined"]["findings"]} == {"10.0.0.1", "10.0.0.2"}
    assert full["meta"]["group"] is None
    html = api.c.get(f"/runs/{run_id}/report?format=html&group_id={g['id']}", headers=op).text
    assert "Группа активов" in html
    assert api.c.get(f"/runs/{run_id}/report?format=json&group_id=9999",
                     headers=op).status_code == 404
    assert a["groups"] == [{"id": g["id"], "name": "DMZ"}]


def _f(host, vid="CVE-1", sev=Severity.HIGH):
    return Finding(module="vuln", finding_type=FindingType.VULN, host=host,
                   port=80, vuln_id=vid, title=vid, severity=sev, cve_ids=[vid])


def test_build_report_host_filter_is_optional():
    cur = [_f("10.0.0.1"), _f("10.0.0.2")]
    assert build_report(cur).summary.total == 2           # по умолчанию без фильтра
    rep = build_report(cur, previous=[_f("10.0.0.1"), _f("10.0.0.2", "CVE-9")],
                       hosts={"10.0.0.2"})
    assert [v.finding.host for v in rep.combined.findings] == ["10.0.0.2"]
    assert rep.combined.trend is not None
    assert build_report(cur, hosts=set()).summary.total == 0


def test_normalize_helpers():
    assert svc.normalize_address("10.0.0.5/32") == "10.0.0.5"
    assert svc.normalize_address("2001:DB8::1") == "2001:db8::1"
    assert svc.criticality_rank("critical") > svc.criticality_rank("high") > \
        svc.criticality_rank("low")
    with pytest.raises(svc.AssetError):
        svc.normalize_tags([f"t{i}" for i in range(21)])
