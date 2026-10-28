"""Рендер отчётов: HTML (Jinja2) -> PDF (WeasyPrint), DOCX (python-docx), JSON.

Разрезы: по каждому модулю раздельно, сводный по всем модулям, тренд между
прогонами (open/fixed/new/regression + динамика по severity).
"""
from __future__ import annotations

from enum import StrEnum


class ReportFormat(StrEnum):
    HTML = "html"
    PDF = "pdf"
    DOCX = "docx"
    JSON = "json"


class ReportRenderer:
    def render(self, scan_run_id: int, fmt: ReportFormat, *,
               per_module: bool = False) -> bytes:
        # TODO (итерация 4): собрать находки прогона из БД, построить модель
        # отчёта (по модулю / сводно / тренд) и отрендерить в нужный формат.
        raise NotImplementedError("рендер отчётов — итерация 4")
