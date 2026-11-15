"""Отчёт по отдельному активу и открытые порты/сервисы в отчёте и карточке.

* /runs/{id}/report?host= — отчёт по одному хосту прогона (все форматы);
* /engagements/{id}/hosts/{host}/report — по последним данным актива;
* в разделе «Результаты по хостам» у каждого хоста таблица открытых портов,
  хосты без находок, но с открытыми портами, тоже есть;
* /engagements/{id}/hosts/{host}/ports — свежее из прогона и «Доступности».
"""
from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

from scanner.core import host_ports
from scanner.core import repository as repo
from scanner.core.db import PortScanRow, session_scope
from scanner.core.models import Finding, FindingType, ServiceInfo, Severity
from scanner.reporting.model import ReportContext, build_report
from scanner.reporting.render import ReportFormat, ReportRenderer
from tests.test_api import _run
from tests.test_assets import api  # noqa: F401 — фикстура API на SQLite


def _f(host, vid="CVE-1", sev=Severity.HIGH, port=22):
    return Finding(module="vuln", finding_type=FindingType.VULN, host=host, port=port,
                   vuln_id=vid, title=vid, severity=sev, cve_ids=[vid])


SVC = [ServiceInfo("10.0.0.1", 22, "tcp", "ssh", "OpenSSH", "7.4", "cpe:/a:openbsd:openssh:7.4"),
       ServiceInfo("10.0.0.1", 80, "tcp", "http", "nginx", "1.18.0"),
       ServiceInfo("10.0.0.2", 443, "tcp", "https"),
       ServiceInfo("10.0.0.3", 3389, "tcp", "ms-wbt-server")]


# ---------- модель и отрисовка ----------
def test_services_in_host_section_all_formats():
    rep = build_report([_f("10.0.0.1"), _f("10.0.0.2", "CVE-2", Severity.LOW, 443)],
                       services=SVC)
    assert [p["port"] for p in rep.services["10.0.0.1"]] == [22, 80]
    data = rep.to_dict()
    assert {s["host"] for s in data["services"]} == {"10.0.0.1", "10.0.0.2", "10.0.0.3"}
    html = ReportRenderer().render_html(rep)
    assert "Открытые порты и сервисы" in html and "OpenSSH 7.4" in html
    assert "nginx 1.18.0" in html and "80/tcp" in html
    # хост без находок, но с открытым портом — в разделе, в конце
    assert "3389/tcp" in html and "Уязвимостей не найдено." in html
    assert html.index("10.0.0.1") < html.index("10.0.0.3")
    docx = ReportRenderer().render(rep, ReportFormat.DOCX)
    assert docx[:2] == b"PK"


def test_without_services_report_is_unchanged():
    rep = build_report([_f("10.0.0.1")])
    assert rep.services is None and "services" not in rep.to_dict()
    html = ReportRenderer().render_html(rep)
    assert "Открытые порты и сервисы" not in html and "Порты: 22" in html


def test_host_filter_applies_to_services():
    rep = build_report([_f("10.0.0.1"), _f("10.0.0.2")], services=SVC, hosts={"10.0.0.2"},
                       context=ReportContext(host="10.0.0.2"))
    assert list(rep.services) == ["10.0.0.2"]
    html = ReportRenderer().render_html(rep)
    assert "Актив: <b>10.0.0.2</b>" in html and "OpenSSH" not in html
    assert "Открытых портов" in html
    assert rep.to_dict()["meta"]["host"] == "10.0.0.2"


# ---------- API: отчёт по прогону и по активу ----------
def test_run_report_for_one_host(api):  # noqa: F811
    eid = api.engagement("10.0.0.0/24")
    op = api.user("op", "operator")
    run_id = _run(api, eid, op, ["10.0.0.1", "10.0.0.2"]).json()["id"]
    full = json.loads(api.c.get(f"/runs/{run_id}/report?format=json", headers=op).text)
    assert {s["host"] for s in full["services"]} == {"10.0.0.1", "10.0.0.2"}
    r = api.c.get(f"/runs/{run_id}/report?format=json&host=10.0.0.2", headers=op)
    assert r.status_code == 200, r.text
    assert f"report-run-{run_id}-host-10.0.0.2.json" in r.headers["content-disposition"]
    rep = json.loads(r.text)
    assert {f["host"] for f in rep["combined"]["findings"]} == {"10.0.0.2"}
    assert rep["meta"]["host"] == "10.0.0.2"
    assert rep["services"] == [{"host": "10.0.0.2", "ports": [
        {"port": 22, "protocol": "tcp", "service": "ssh", "product": "OpenSSH",
         "version": "7.4", "cpe": None}]}]
    html = api.c.get(f"/runs/{run_id}/report?format=html&host=10.0.0.2&variant=brief",
                     headers=op)
    assert html.status_code == 200 and "Актив: <b>10.0.0.2</b>" in html.text
    assert "OpenSSH 7.4" in html.text
    docx = api.c.get(f"/runs/{run_id}/report?format=docx&host=10.0.0.2", headers=op)
    assert docx.status_code == 200 and docx.content[:2] == b"PK"
    assert api.c.get(f"/runs/{run_id}/report?host=bad", headers=op).status_code == 422


def test_latest_host_report_and_ports(api, sqlite_factory):  # noqa: F811
    eid = api.engagement("10.0.0.0/24")
    op = api.user("op", "operator")
    r1 = _run(api, eid, op, ["10.0.0.1"]).json()["id"]
    r = api.c.get(f"/engagements/{eid}/hosts/10.0.0.1/report?format=json", headers=op)
    assert r.status_code == 200, r.text
    assert "report-host-10.0.0.1.json" in r.headers["content-disposition"]
    rep = json.loads(r.text)
    assert rep["meta"]["host"] == "10.0.0.1" and rep["meta"]["run_id"] is None
    assert f"прогон {r1}" in rep["meta"]["sources"]
    assert rep["combined"]["findings"] and rep["services"][0]["ports"][0]["port"] == 22
    for fmt in ("html", "docx"):
        assert api.c.get(f"/engagements/{eid}/hosts/10.0.0.1/report?format={fmt}",
                         headers=op).status_code == 200
    ports = api.c.get(f"/engagements/{eid}/hosts/10.0.0.1/ports", headers=op).json()
    assert ports["source"] == "run" and ports["run_id"] == r1
    assert [s["port"] for s in ports["services"]] == [22]
    # хост без данных — 404; не IP — 422
    assert api.c.get(f"/engagements/{eid}/hosts/10.0.0.9/report",
                     headers=op).status_code == 404
    assert api.c.get(f"/engagements/{eid}/hosts/x/report", headers=op).status_code == 422
    assert api.c.get(f"/engagements/{eid}/hosts/10.0.0.1/report").status_code == 401
    # свежая «Доступность» без -sV: её порты, версии по 22 — из прогона
    with session_scope(sqlite_factory) as s:
        s.add(PortScanRow(engagement_id=eid, status="done", port_mode="top",
                          service_detection=False,
                          finished_at=datetime.now(UTC) + timedelta(minutes=5),
                          results=[{"host": "10.0.0.1", "up": True, "ports": [
                              {"port": 22, "protocol": "tcp", "service": "ssh"},
                              {"port": 8080, "protocol": "tcp", "service": "http-proxy"}]}]))
    ports = api.c.get(f"/engagements/{eid}/hosts/10.0.0.1/ports", headers=op).json()
    assert ports["source"] == "port_scan" and ports["versions_from_run"]
    assert [(s["port"], s["product"]) for s in ports["services"]] == \
        [(22, "OpenSSH"), (8080, None)]
    assert "версии ПО — из прогона" in ports["label"]
    rep = json.loads(api.c.get(f"/engagements/{eid}/hosts/10.0.0.1/report?format=json",
                               headers=op).text)
    assert [p["port"] for p in rep["services"][0]["ports"]] == [22, 8080]
    assert "проверка доступности" in rep["meta"]["sources"]


def test_port_check_only_host_has_report(api, sqlite_factory):  # noqa: F811
    eid = api.engagement("10.0.0.0/24")
    op = api.user("op", "operator")
    with session_scope(sqlite_factory) as s:
        s.add(PortScanRow(engagement_id=eid, status="done", port_mode="top",
                          service_detection=True, finished_at=datetime.now(UTC),
                          results=[{"host": "10.0.0.5", "up": True, "ports": [
                              {"port": 443, "protocol": "tcp", "service": "https",
                               "product": "nginx", "version": "1.24"}]},
                              {"host": "10.0.0.6", "up": False, "ports": []}]))
    r = api.c.get(f"/engagements/{eid}/hosts/10.0.0.5/report?format=html", headers=op)
    assert r.status_code == 200, r.text
    assert "nginx 1.24" in r.text and "Уязвимостей не найдено." in r.text
    assert api.c.get(f"/engagements/{eid}/hosts/10.0.0.6/report",
                     headers=op).status_code == 404


def test_list_mode_port_check_supplements_run(sqlite_factory):
    with session_scope(sqlite_factory) as s:
        eid = repo.create_engagement(s, name="Д")
        rid = repo.create_scan_run(s, engagement_id=eid, modules=["discovery"])
        repo.save_services(s, scan_run_id=rid, services=[SVC[0], SVC[1]])
        repo.set_scan_run_status(s, rid, "done")
        s.add(PortScanRow(engagement_id=eid, status="done", port_mode="list",
                          service_detection=True,
                          finished_at=datetime.now(UTC) + timedelta(hours=1),
                          results=[{"host": "10.0.0.1", "up": True, "ports": [
                              {"port": 443, "protocol": "tcp", "service": "https"}]}]))
    with session_scope(sqlite_factory) as s:
        hp = host_ports.latest_ports(s, eid, "10.0.0.1")
        assert [x.port for x in hp.services] == [22, 80, 443]
        assert hp.ports_from_run and f"остальные порты — из прогона {rid}" in hp.label
