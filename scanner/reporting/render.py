"""Рендер отчётов: HTML (Jinja2) -> PDF (WeasyPrint), DOCX (python-docx), JSON.

Разрезы: по каждому модулю раздельно, сводный по всем модулям, тренд между
прогонами (open/fixed/new/regression + динамика по severity). Все форматы
строятся из одной модели (`reporting.model.Report`), в каждой находке —
рекомендация по устранению.

Графика (дашборд руководителя, распределение по опасности, топ хостов, модули,
каскад изменений и тренд по прогонам) строится в `reporting.charts`: одна
геометрия — inline-SVG в HTML/PDF (без JS и внешних ресурсов) и PNG в DOCX.

Безопасность: данные находок (evidence, баннеры сервисов) приходят с целей и
считаются недоверенными — HTML экранируется (autoescape), WeasyPrint не
загружает внешние ресурсы, из DOCX вырезаются недопустимые в XML символы.
"""
from __future__ import annotations

import json
import re
from collections.abc import Sequence
from enum import StrEnum
from io import BytesIO
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape
from markupsafe import Markup

from scanner.core.models import FindingStatus, Severity
from scanner.reporting import charts as ch
from scanner.reporting.charts import SEVERITY_HEX, RunPoint, Scene
from scanner.reporting.model import (
    SEVERITY_LABELS,
    SEVERITY_ORDER,
    STATUS_LABELS,
    Report,
    Section,
    Trend,
)

TEMPLATES_DIR = Path(__file__).parent / "templates"

STATUS_ORDER: list[FindingStatus] = [
    FindingStatus.NEW, FindingStatus.REGRESSION, FindingStatus.OPEN, FindingStatus.FIXED,
]

SEVERITY_RGB: dict[Severity, tuple[int, int, int]] = {
    s: tuple(int(h[i:i + 2], 16) for i in (1, 3, 5))  # type: ignore[misc]
    for s, h in SEVERITY_HEX.items()
}


class ReportFormat(StrEnum):
    HTML = "html"
    PDF = "pdf"
    DOCX = "docx"
    JSON = "json"


CONTENT_TYPES: dict[ReportFormat, str] = {
    ReportFormat.HTML: "text/html; charset=utf-8",
    ReportFormat.PDF: "application/pdf",
    ReportFormat.DOCX: "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    ReportFormat.JSON: "application/json",
}


def _env() -> Environment:
    env = Environment(
        loader=FileSystemLoader(TEMPLATES_DIR),
        autoescape=select_autoescape(["html", "j2"]),
        trim_blocks=True,
        lstrip_blocks=True,
    )
    env.globals.update(
        SEVERITY_ORDER=SEVERITY_ORDER, SEVERITY_LABELS=SEVERITY_LABELS,
        STATUS_ORDER=STATUS_ORDER, STATUS_LABELS=STATUS_LABELS,
        SEVERITY_HEX={str(k): v for k, v in SEVERITY_HEX.items()},
    )
    return env


def _deny_fetch(url: str, *args, **kwargs):
    raise ValueError(f"загрузка внешних ресурсов в отчёт запрещена: {url}")


# Символы, недопустимые в XML 1.0 (python-docx на них падает)
_XML_BAD = re.compile("[\x00-\x08\x0b\x0c\x0e-\x1f￾￿]")


def _x(text: object) -> str:
    return _XML_BAD.sub("�", "" if text is None else str(text))


def _deadline(days: int | None) -> str:
    return "по плану" if days is None else f"до {days} дн."


def _run_label(run_id: object, fallback: str) -> str:
    return fallback if run_id is None else f"Прогон {run_id}"


def default_history(report: Report) -> list[RunPoint]:
    """Две точки тренда (предыдущий -> текущий прогон) из самой модели отчёта."""
    t = report.combined.trend
    if t is None:
        return []
    c = report.context
    return [
        RunPoint(_run_label(c.previous_run_id, "Предыдущий"),
                 {d.severity: d.previous for d in t.severity}),
        RunPoint(_run_label(c.run_id, "Текущий"), {d.severity: d.current for d in t.severity}),
    ]


def build_charts(report: Report, history: Sequence[RunPoint] | None = None
                 ) -> dict[str, Scene]:
    """Диаграммы отчёта по ключам; набор зависит от данных (тренд — со 2-го прогона).

    history — точки по прогонам в хронологическом порядке (последняя — текущий
    прогон); если не задана, берутся предыдущий и текущий прогон из отчёта.
    """
    s = report.summary
    out: dict[str, Scene] = {"severity": ch.severity_donut(s.severity_counts)}
    if s.top_hosts:
        out["hosts"] = ch.stacked_bars(
            "hosts", "Наиболее уязвимые хосты по уровню опасности",
            [(h.host, h.counts) for h in s.top_hosts], width=340, label_w=110)
    if report.modules:
        out["modules"] = ch.stacked_bars(
            "modules", "Находки по модулям и уровню опасности",
            [(m.label, m.severity_counts) for m in report.modules], width=680, label_w=170)
    t = report.combined.trend
    if t is not None:
        k = t.counts
        out["waterfall"] = ch.waterfall(
            k[FindingStatus.OPEN] + k[FindingStatus.FIXED], k[FindingStatus.FIXED],
            k[FindingStatus.NEW], k[FindingStatus.REGRESSION])
        points = list(history) if history else default_history(report)
        out["trend"] = ch.trend_columns(points)
    return out


class ReportRenderer:
    def render(self, report: Report, fmt: ReportFormat | str,
               history: Sequence[RunPoint] | None = None) -> bytes:
        fmt = ReportFormat(fmt)
        if fmt is ReportFormat.HTML:
            return self.render_html(report, history).encode("utf-8")
        if fmt is ReportFormat.PDF:
            return self.render_pdf(report, history)
        if fmt is ReportFormat.DOCX:
            return self.render_docx(report, history)
        return self.render_json(report)

    # --- JSON ---------------------------------------------------------------
    def render_json(self, report: Report) -> bytes:
        return json.dumps(report.to_dict(), ensure_ascii=False, indent=2).encode("utf-8")

    # --- HTML / PDF ---------------------------------------------------------
    def render_html(self, report: Report, history: Sequence[RunPoint] | None = None) -> str:
        # SVG собран из экранированных строк (charts.py) — помечаем как безопасный
        charts = {k: Markup(v.to_svg()) for k, v in build_charts(report, history).items()}
        return _env().get_template("report.html.j2").render(r=report, charts=charts)

    def render_pdf(self, report: Report, history: Sequence[RunPoint] | None = None) -> bytes:
        try:
            from weasyprint import HTML  # тяжёлая зависимость (pango) — лениво
        except (ImportError, OSError) as e:
            raise RuntimeError(
                "PDF недоступен: нужен WeasyPrint и системные библиотеки Pango") from e
        return HTML(string=self.render_html(report, history),
                    url_fetcher=_deny_fetch).write_pdf()

    # --- DOCX ---------------------------------------------------------------
    def render_docx(self, report: Report, history: Sequence[RunPoint] | None = None) -> bytes:
        from docx import Document
        from docx.shared import Cm, Pt, RGBColor

        doc = Document()
        style = doc.styles["Normal"]
        style.font.name = "DejaVu Sans"
        style.font.size = Pt(10)

        page_cm = 16.5  # ширина текста A4 при стандартных полях

        def table(header: list[str], rows: list[list[object]],
                  widths: list[float] | None = None, first_cm: float | None = None):
            t = doc.add_table(rows=1, cols=len(header))
            t.style = "Table Grid"
            if widths is None and first_cm is not None:
                rest = (page_cm - first_cm) / (len(header) - 1)
                widths = [first_cm] + [rest] * (len(header) - 1)
            for cell, h in zip(t.rows[0].cells, header):
                cell.text = ""
                cell.paragraphs[0].add_run(_x(h)).bold = True
            for row in rows:
                cells = t.add_row().cells
                for cell, v in zip(cells, row):
                    cell.text = _x(v)
            if widths:
                t.autofit = False
                for col, w in zip(t.columns, widths):
                    col.width = Cm(w)  # tblGrid — его читает LibreOffice
                for row in t.rows:
                    for cell, w in zip(row.cells, widths):
                        cell.width = Cm(w)
            doc.add_paragraph()  # отступ после таблицы
            return t

        scenes = build_charts(report, history) if ch.png_available() else {}

        def picture(key: str, width_cm: float):
            if key in scenes:
                doc.add_picture(BytesIO(scenes[key].to_png()), width=Cm(width_cm))

        def sev_run(par, s: Severity):
            run = par.add_run(f"[{SEVERITY_LABELS[s]}] ")
            run.bold = True
            run.font.color.rgb = RGBColor(*SEVERITY_RGB[s])

        def trend_block(t: Trend):
            doc.add_paragraph(_x(t.verdict)).runs[0].bold = True
            if t is report.combined.trend:
                picture("waterfall", 11.0)
                picture("trend", 10.0)
            table([STATUS_LABELS[s] for s in STATUS_ORDER],
                  [[t.counts[s] for s in STATUS_ORDER]])
            table(["Уровень опасности", "Предыдущий", "Текущий", "Изменение"],
                  [[d.label, d.previous, d.current, f"{d.delta:+d}" if d.delta else "0"]
                   for d in t.severity])
            if t.fixed:
                doc.add_paragraph("Устранено с предыдущего прогона:")
                table(["Опасность", "Находка", "Хост"],
                      [[v.severity_label, v.finding.title, v.target] for v in t.fixed],
                      widths=[3.0, 9.5, 4.0])

        def severity_table(sections: list[Section]):
            table(["Модуль"] + [SEVERITY_LABELS[s] for s in SEVERITY_ORDER] + ["Всего"],
                  [[m.label] + [m.severity_counts[s] for s in SEVERITY_ORDER]
                   + [len(m.findings)] for m in sections], first_cm=4.5)

        c = report.context
        doc.add_heading(_x(c.title), level=0)
        meta = []
        if c.customer:
            meta.append(f"Заказчик: {c.customer}")
        if c.engagement:
            meta.append(f"Договор / проект: {c.engagement}")
        if c.run_id is not None:
            meta.append(f"Прогон: {c.run_id}")
        if c.previous_run_id is not None:
            meta.append(f"Сравнение с прогоном: {c.previous_run_id}")
        meta.append(f"Сформирован: {c.generated_at:%d.%m.%Y %H:%M} UTC")
        doc.add_paragraph(_x(" · ".join(meta)))

        # 1. Резюме
        s = report.summary
        doc.add_heading("1. Резюме для руководства", level=1)
        p = doc.add_paragraph("Общий уровень риска: ")
        p.add_run(s.risk_label).bold = True
        p.add_run(f". Хостов с находками: {s.hosts}, всего находок: {s.total}.")
        table([SEVERITY_LABELS[x] for x in SEVERITY_ORDER],
              [[s.severity_counts[x] for x in SEVERITY_ORDER]])
        picture("severity", 10.5)
        for point in s.key_points:
            doc.add_paragraph(_x(point), style="List Bullet")
        if s.top_hosts:
            doc.add_heading("Наиболее уязвимые хосты", level=2)
            picture("hosts", 13.0)
            table(["Хост"] + [SEVERITY_LABELS[x] for x in SEVERITY_ORDER] + ["Всего"],
                  [[h.host] + [h.counts[x] for x in SEVERITY_ORDER] + [h.total]
                   for h in s.top_hosts], first_cm=3.5)
        doc.add_heading("Находки по модулям", level=2)
        picture("modules", 16.5)
        severity_table(report.modules)

        # 2. План устранения
        doc.add_heading("2. План устранения", level=1)
        if report.plan:
            table(["№", "Опасность", "Что сделать", "Где", "Срок"],
                  [[i, p.severity_label,
                    f"{p.action}\nИсточник: {p.source_label}. Находки: {'; '.join(p.titles)}",
                    ", ".join(p.targets), _deadline(p.deadline_days)]
                   for i, p in enumerate(report.plan, 1)],
                  widths=[0.8, 2.9, 7.8, 3.2, 1.8])
        else:
            doc.add_paragraph("Мер устранения не требуется.")

        # 3. Сравнение
        doc.add_heading("3. Сравнение с предыдущим прогоном", level=1)
        if report.combined.trend:
            trend_block(report.combined.trend)
            doc.add_heading("Динамика по модулям", level=2)
            table(["Модуль"] + [STATUS_LABELS[x] for x in STATUS_ORDER],
                  [[m.label] + [m.trend.counts[x] for x in STATUS_ORDER]
                   for m in report.modules if m.trend], first_cm=4.5)
        else:
            doc.add_paragraph("Предыдущий прогон не задан — это первый прогон, "
                              "сравнение будет доступно со следующего.")

        # 4. Детально
        doc.add_heading("4. Детальные результаты для инженеров", level=1)
        for i, m in enumerate(report.modules, 1):
            doc.add_heading(_x(f"4.{i}. {m.label}"), level=2)
            if not m.findings:
                doc.add_paragraph("Открытых находок нет.")
            for _, _, group in m.by_severity:
                for v in group:
                    f = v.finding
                    p = doc.add_paragraph()
                    sev_run(p, f.severity)
                    p.add_run(_x(f.title)).bold = True
                    if v.status_label:
                        p.add_run(f" · {v.status_label}").italic = True
                    details = [f"Хост: {v.target}"]
                    if f.vuln_id:
                        details.append(f"ID: {f.vuln_id}")
                    if f.cvss is not None:
                        details.append(f"CVSS: {f.cvss:.1f}")
                    if f.cve_ids:
                        details.append("CVE: " + ", ".join(f.cve_ids))
                    if f.bdu_ids:
                        details.append("БДУ: " + ", ".join(f.bdu_ids))
                    doc.add_paragraph(_x(" · ".join(details)))
                    if f.evidence:
                        ev = doc.add_paragraph()
                        r = ev.add_run(_x(f.evidence))
                        r.font.name = "DejaVu Sans Mono"
                        r.font.size = Pt(8)
                    rem = v.remediation
                    rp = doc.add_paragraph()
                    head = rp.add_run("Рекомендация по устранению: ")
                    head.bold = True
                    head.font.color.rgb = RGBColor(0x23, 0x73, 0x3F)
                    rp.add_run(_x(rem.text))
                    note = f"Источник: {rem.source_label}; срок: {_deadline(rem.deadline_days)}."
                    if rem.fix_method:
                        note += f" Способ устранения: {rem.fix_method}."
                    if rem.references:
                        note += " Ссылки: " + ", ".join(rem.references)
                    np_ = doc.add_paragraph()
                    nr = np_.add_run(_x(note))
                    nr.italic = True
                    nr.font.size = Pt(8)

        doc.add_paragraph("Отчёт сформирован по результатам авторизованного тестирования "
                          "в рамках договора. Сроки устранения — рекомендуемые и могут быть "
                          "скорректированы политикой заказчика.").runs[0].italic = True
        buf = BytesIO()
        doc.save(buf)
        return buf.getvalue()
