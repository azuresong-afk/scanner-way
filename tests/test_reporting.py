"""Тесты отчётов: структура JSON, рекомендации, сравнение прогонов, 4 формата."""
import io
import json
import zipfile

import pytest

from scanner.core.models import Finding, FindingType, Severity
from scanner.reporting.diff import diff_by_module, diff_runs
from scanner.reporting.model import ReportContext, build_report
from scanner.reporting.remediation import RemediationResolver, RemediationSource
from scanner.reporting.render import ReportFormat, ReportRenderer
from tests import reporting_fixtures as fx


@pytest.fixture
def report():
    return build_report(
        fx.current_run(), previous=fx.previous_run(),
        historically_fixed=fx.historically_fixed(), resolver=fx.resolver(),
        context=ReportContext(customer="ООО «Заказчик»", engagement="Договор №42",
                              run_id=2, previous_run_id=1),
    )


@pytest.fixture
def data(report):
    return json.loads(ReportRenderer().render(report, ReportFormat.JSON))


# --- JSON структура -----------------------------------------------------------

def test_json_top_level_structure(data):
    assert data["schema_version"] == "1.0"
    assert set(data) >= {"meta", "summary", "remediation_plan", "combined", "modules"}
    assert data["meta"]["run_id"] == 2 and data["meta"]["previous_run_id"] == 1
    assert data["summary"]["total"] == 7
    assert data["summary"]["risk_level"] == "critical"
    assert data["summary"]["severity_counts"] == {
        "info": 1, "low": 1, "medium": 1, "high": 2, "critical": 2}
    assert [m["key"] for m in data["modules"]] == [
        "discovery", "vuln", "config_audit", "cred_audit"]
    assert sum(m["total"] for m in data["modules"]) == data["combined"]["total"]


def test_json_finding_fields(data):
    f = data["combined"]["findings"][0]
    assert set(f) >= {"id", "module", "title", "severity", "status", "host", "port",
                      "cve_ids", "bdu_ids", "cvss", "evidence", "remediation"}
    assert set(f["remediation"]) >= {"text", "source", "deadline_days", "references"}
    # сортировка: сначала критические
    assert f["severity"] == "critical"


# --- рекомендации ---------------------------------------------------------------

def test_every_finding_has_remediation(data):
    findings = data["combined"]["findings"] + data["combined"]["trend"]["fixed"]
    assert findings
    for f in findings:
        assert f["remediation"]["text"].strip(), f["title"]


def test_remediation_sources(data):
    by_title = {f["title"]: f["remediation"] for f in data["combined"]["findings"]}
    ssh = by_title["OpenSSH: удалённое выполнение кода через ssh-agent"]
    assert ssh["source"] == "bdu_fstec" and ssh["text"] == fx.BDU_REMEDIATION
    assert "https://bdu.fstec.ru/vul/2023-04110" in ssh["references"]
    assert ssh["deadline_days"] == 3
    # связь CVE -> БДУ через справочник, хотя в finding нет bdu_ids
    apache = by_title["Apache HTTP Server: обход каталога"]
    assert apache["source"] == "bdu_fstec" and "2.4.51" in apache["text"]
    assert "https://bdu.fstec.ru/vul/2021-04880" in apache["references"]
    assert by_title["RDP: BlueKeep"]["source"] == "nvd"
    assert by_title["Разрешён вход root по SSH"]["source"] == "benchmark"
    assert by_title["Не задан максимальный срок пароля"]["source"] == "generic"
    assert by_title["Стандартный пароль admin/admin на SSH"]["source"] == "generic"


def test_finding_own_remediation_wins():
    # Поле remediation в Finding может появиться позже (матчер/модули) —
    # резолвер уже учитывает его; эмулируем подклассом со слотом.
    WithRemediation = type("WithRemediation", (Finding,), {"__slots__": ("remediation",)})
    f = WithRemediation(module="config_audit", host="h", finding_type=FindingType.CONFIG,
                        title="t", vuln_id="r1")
    f.remediation = "своя мера"
    r = RemediationResolver(benchmark={"r1": "из бенчмарка"}).resolve(f)
    assert r.source is RemediationSource.FINDING and r.text == "своя мера"


def test_plan_groups_same_action_and_skips_info(report):
    actions = [p.action for p in report.plan]
    assert len(actions) == len(set(actions))
    assert all(p.severity is not Severity.INFO for p in report.plan)
    assert report.plan[0].severity is Severity.CRITICAL
    assert report.plan[0].deadline_days == 3


# --- сравнение прогонов ----------------------------------------------------------

def test_trend_combined(data):
    t = data["combined"]["trend"]
    assert t["counts"] == {"open": 2, "new": 4, "regression": 1, "fixed": 1}
    assert [f["vuln_id"] for f in t["fixed"]] == ["CVE-2022-0778"]
    dyn = {d["severity"]: d for d in t["severity_dynamics"]}
    assert dyn["critical"] == {"severity": "critical", "label": "Критический",
                               "previous": 1, "current": 2, "delta": 1}
    assert dyn["high"]["delta"] == 1
    statuses = {f["title"]: f["status"] for f in data["combined"]["findings"]}
    assert statuses["RDP: BlueKeep"] == "regression"
    assert statuses["Разрешён вход root по SSH"] == "open"
    assert statuses["Открыт Telnet"] == "new"


def test_trend_per_module_sums_to_combined(data):
    total = {"open": 0, "new": 0, "regression": 0, "fixed": 0}
    for m in data["modules"]:
        for k, v in m["trend"]["counts"].items():
            total[k] += v
    assert total == data["combined"]["trend"]["counts"]
    vuln = next(m for m in data["modules"] if m["key"] == "vuln")
    assert vuln["trend"]["counts"] == {"open": 1, "new": 1, "regression": 1, "fixed": 1}


def test_diff_by_module_matches_diff_runs():
    prev, cur, hf = fx.previous_run(), fx.current_run(), fx.historically_fixed()
    d = diff_runs(prev, cur, hf)
    per = diff_by_module(prev, cur, hf)
    for attr in ("open", "new", "regression", "fixed"):
        assert sum(len(getattr(x, attr)) for x in per.values()) == len(getattr(d, attr))


def test_first_run_has_no_trend():
    r = build_report(fx.current_run(), resolver=fx.resolver())
    data = r.to_dict()
    assert data["combined"]["trend"] is None
    assert all(f["status"] is None for f in data["combined"]["findings"])
    html = ReportRenderer().render_html(r)
    assert "это первый прогон" in html


def test_empty_report():
    r = build_report([], previous=[])
    assert r.summary.risk_level is None and r.plan == []
    for fmt in (ReportFormat.HTML, ReportFormat.JSON, ReportFormat.DOCX):
        assert ReportRenderer().render(r, fmt)


# --- форматы -------------------------------------------------------------------

def test_html_has_sections_and_escapes_evidence(report):
    html = ReportRenderer().render(report, ReportFormat.HTML).decode()
    for heading in ("Резюме для руководства", "План устранения",
                    "Сравнение с предыдущим прогоном", "Детальные результаты",
                    "Рекомендация по устранению", "Аудит конфигураций"):
        assert heading in html
    assert fx.BDU_REMEDIATION in html
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html


def test_docx_contains_remediation(report):
    raw = ReportRenderer().render(report, ReportFormat.DOCX)
    with zipfile.ZipFile(io.BytesIO(raw)) as z:
        xml = z.read("word/document.xml").decode()
    assert "Рекомендация по устранению" in xml
    assert "План устранения" in xml and "Сравнение с предыдущим прогоном" in xml
    assert "PermitRootLogin no" in xml


def test_pdf_renders(report):
    pytest.importorskip("weasyprint")
    try:
        raw = ReportRenderer().render(report, ReportFormat.PDF)
    except RuntimeError as e:  # нет системных библиотек Pango
        pytest.skip(str(e))
    assert raw.startswith(b"%PDF")
    assert len(raw) > 5000


def test_weak_credentials_get_urgent_deadline(report):
    cred = next(v for v in report.combined.findings if v.finding.module == "cred_audit")
    assert cred.finding.severity is Severity.HIGH
    assert cred.remediation.deadline_days == 3
