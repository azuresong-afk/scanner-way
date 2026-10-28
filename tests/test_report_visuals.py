"""Тесты графического оформления отчёта: дашборд и диаграммы в HTML/PDF/DOCX."""
import io
import json
import re
import zipfile

import pytest

from scanner.core.models import Finding, FindingType, Severity
from scanner.reporting import charts as ch
from scanner.reporting.charts import RunPoint
from scanner.reporting.model import ReportContext, build_report
from scanner.reporting.render import ReportFormat, ReportRenderer, build_charts
from tests import reporting_fixtures as fx

ALL_CHARTS = {"severity", "hosts", "modules", "waterfall", "trend"}


@pytest.fixture
def report():
    return build_report(
        fx.current_run(), previous=fx.previous_run(),
        historically_fixed=fx.historically_fixed(), resolver=fx.resolver(),
        context=ReportContext(run_id=2, previous_run_id=1),
    )


def _charts_in(html: str) -> set[str]:
    return set(re.findall(r'<svg[^>]*data-chart="([a-z]+)"', html))


# --- HTML ------------------------------------------------------------------------

def test_html_has_dashboard_and_all_charts(report):
    html = ReportRenderer().render_html(report)
    assert 'class="dashboard"' in html
    assert html.count('class="kpi') >= 4
    assert "Общий уровень риска" in html and "Критических и высоких" in html
    assert _charts_in(html) == ALL_CHARTS
    # диаграммы — самодостаточный inline-SVG: без JS и внешних ресурсов
    assert "<script" not in html
    for svg in re.findall(r"<svg.*?</svg>", html, flags=re.DOTALL):
        assert "href" not in svg and "url(" not in svg
        assert 'role="img"' in svg and "aria-label=" in svg


def test_html_severity_colors_and_tooltips(report):
    html = ReportRenderer().render_html(report)
    for color in ch.SEVERITY_HEX.values():
        assert color in html
    # нативные подсказки при наведении на элементы диаграмм
    assert "<title>Критический: 2 (29%)</title>" in html
    assert "<title>10.0.0.1 — Критический: 1</title>" in html


def test_first_run_has_no_trend_charts():
    r = build_report(fx.current_run(), resolver=fx.resolver())
    html = ReportRenderer().render_html(r)
    assert _charts_in(html) == {"severity", "hosts", "modules"}
    assert "первый прогон" in html


def test_empty_report_still_renders_dashboard():
    r = build_report([])
    html = ReportRenderer().render_html(r)
    assert _charts_in(html) == {"severity"}
    assert "Находок нет" in html


def test_chart_text_from_targets_is_escaped():
    evil = '<img src=x onerror="alert(1)">'
    f = Finding(module="vuln", host=evil, finding_type=FindingType.VULN, title="t",
                severity=Severity.HIGH, vuln_id="CVE-2020-0001")
    html = ReportRenderer().render_html(build_report([f]))
    assert "<img" not in html
    assert "&lt;img" in html


def test_custom_history_drives_trend_chart(report):
    history = [
        RunPoint("Июль", {Severity.CRITICAL: 3, Severity.HIGH: 1}),
        RunPoint("Август", {Severity.CRITICAL: 2}),
        RunPoint("Сентябрь", {Severity.HIGH: 4}),
    ]
    svg = build_charts(report, history)["trend"].to_svg()
    for label in ("Июль", "Август", "Сентябрь"):
        assert f">{label}</text>" in svg
    default = build_charts(report)["trend"].to_svg()
    assert ">Прогон 1</text>" in default and ">Прогон 2</text>" in default


def test_waterfall_balances(report):
    t = report.combined.trend.counts
    svg = build_charts(report)["waterfall"].to_svg()
    # было 3 (open 2 + fixed 1) -> −1 +4 +1 -> стало 7
    assert "Предыдущий прогон: 3" in svg and "Текущий прогон: 7" in svg
    assert sum(t.values()) - t["fixed"] == report.summary.total


def test_json_contract_unchanged(report):
    data = json.loads(ReportRenderer().render(report, ReportFormat.JSON))
    assert "charts" not in data and "svg" not in json.dumps(data)


# --- PDF -------------------------------------------------------------------------

def test_pdf_lays_out_dashboard_charts(report):
    weasyprint = pytest.importorskip("weasyprint")
    html = ReportRenderer().render_html(report)
    try:
        doc = weasyprint.HTML(string=html).render()
    except OSError as e:  # нет системных библиотек Pango
        pytest.skip(str(e))
    svgs = [b for p in doc.pages for b in p._page_box.descendants()
            if type(getattr(b, "replacement", None)).__name__ == "SVGImage"]
    assert len(svgs) == len(ALL_CHARTS)
    assert all(b.width > 100 and b.height > 50 for b in svgs)
    raw = ReportRenderer().render(report, ReportFormat.PDF)
    assert raw.startswith(b"%PDF")


# --- DOCX ------------------------------------------------------------------------

def test_docx_embeds_charts_as_png(report):
    pytest.importorskip("PIL")
    raw = ReportRenderer().render(report, ReportFormat.DOCX)
    with zipfile.ZipFile(io.BytesIO(raw)) as z:
        media = [n for n in z.namelist() if n.startswith("word/media/")]
        assert len(media) == len(ALL_CHARTS)
        for n in media:
            assert z.read(n).startswith(b"\x89PNG\r\n\x1a\n")


def test_png_matches_scene_size():
    from PIL import Image

    scene = ch.severity_donut({s: 1 for s in Severity})
    img = Image.open(io.BytesIO(scene.to_png(scale=2)))
    assert img.size == (scene.width * 2, scene.height * 2)
