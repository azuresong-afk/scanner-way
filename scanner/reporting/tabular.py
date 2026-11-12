"""Таблицы для выгрузки в CSV и Excel (XLSX).

Общий слой для «Все находки» и «Что исправить»: лист — заголовки колонок и
строки значений, дальше — сериализация. Значения приходят в том числе со
сканируемых хостов (баннеры, имена пакетов, вывод команд), поэтому:

* в CSV текст, начинающийся с = + - @ (и таба/CR), экранируется апострофом —
  защита от CSV-инъекций при открытии файла в Excel/LibreOffice;
* в XLSX все строки пишутся как текст (не как формулы), недопустимые в XML
  управляющие символы вырезаются, длина ячейки ограничена пределом Excel.

CSV — с BOM (иначе Excel показывает кириллицу кракозябрами) и разделителем «;»:
так файл двойным щелчком открывается по колонкам в Excel с русскими настройками.
"""
from __future__ import annotations

import csv
import io
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from typing import Any

# Потолок строк одной выгрузки: файл собирается в памяти процесса API.
MAX_EXPORT_ROWS = 100_000
# Предел длины ячейки Excel.
XLSX_CELL_MAX = 32_767
CSV_DELIMITER = ";"


class TableFormat(StrEnum):
    CSV = "csv"
    XLSX = "xlsx"


CONTENT_TYPES = {
    TableFormat.CSV: "text/csv; charset=utf-8",
    TableFormat.XLSX: "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
}


@dataclass(frozen=True, slots=True)
class Column:
    title: str
    width: int = 14          # ширина колонки в XLSX (символов)
    wrap: bool = False       # перенос строк (многострочные команды, ссылки)


@dataclass(slots=True)
class Sheet:
    title: str
    columns: Sequence[Column]
    rows: list[list[Any]] = field(default_factory=list)


def cell_text(value: Any) -> Any:
    """Значение ячейки: списки — по строке на элемент, bool — «да»/«нет»,
    None — пусто; числа остаются числами (в Excel по ним работает сортировка)."""
    if value is None:
        return ""
    if isinstance(value, bool):
        return "да" if value else "нет"
    if isinstance(value, int | float):
        return value
    if isinstance(value, datetime):
        return value.strftime("%Y-%m-%d %H:%M")
    if isinstance(value, list | tuple):
        return "\n".join(str(x) for x in value if x is not None and x != "")
    return str(value)


def _csv_cell(value: Any) -> str:
    v = cell_text(value)
    if not isinstance(v, str):
        return str(v)
    if v and v[0] in "=+-@\t\r":
        v = "'" + v
    return v


def to_csv(sheet: Sheet) -> bytes:
    buf = io.StringIO()
    w = csv.writer(buf, delimiter=CSV_DELIMITER, lineterminator="\r\n")
    w.writerow([c.title for c in sheet.columns])
    for row in sheet.rows:
        w.writerow([_csv_cell(v) for v in row])
    return ("﻿" + buf.getvalue()).encode("utf-8")


def _xlsx_text(text: str) -> str:
    from openpyxl.cell.cell import ILLEGAL_CHARACTERS_RE
    text = ILLEGAL_CHARACTERS_RE.sub("", text)
    if len(text) > XLSX_CELL_MAX:
        text = text[:XLSX_CELL_MAX - 1] + "…"
    return text


def to_xlsx(sheets: Iterable[Sheet]) -> bytes:
    """Книга Excel: на каждом листе жирная закреплённая шапка, автофильтр и
    ширины колонок. Режим write_only — память не растёт с числом ячеек."""
    from openpyxl import Workbook
    from openpyxl.cell import WriteOnlyCell
    from openpyxl.styles import Alignment, Font, PatternFill
    from openpyxl.utils import get_column_letter

    wb = Workbook(write_only=True)
    head_font = Font(bold=True, color="FFFFFF")
    head_fill = PatternFill("solid", fgColor="1F2937")
    top = Alignment(vertical="top")
    wrap = Alignment(vertical="top", wrap_text=True)
    for sheet in sheets:
        ws = wb.create_sheet(_xlsx_text(sheet.title)[:31])
        for i, col in enumerate(sheet.columns, start=1):
            ws.column_dimensions[get_column_letter(i)].width = col.width
        ws.freeze_panes = "A2"
        last = get_column_letter(max(1, len(sheet.columns)))
        ws.auto_filter.ref = f"A1:{last}{max(1, len(sheet.rows) + 1)}"
        head = []
        for col in sheet.columns:
            c = WriteOnlyCell(ws, value=col.title)
            c.font, c.fill, c.alignment = head_font, head_fill, wrap
            head.append(c)
        ws.append(head)
        for row in sheet.rows:
            out = []
            for col, value in zip(sheet.columns, row, strict=False):
                v = cell_text(value)
                if isinstance(v, str):
                    c = WriteOnlyCell(ws, value=_xlsx_text(v))
                    c.data_type = "s"          # «=…» из данных хоста — текст, не формула
                else:
                    c = WriteOnlyCell(ws, value=v)
                c.alignment = wrap if col.wrap else top
                out.append(c)
            ws.append(out)
    buf = io.BytesIO()
    wb.save(buf)
    return buf.getvalue()


def info_sheet(pairs: Sequence[tuple[str, Any]]) -> Sheet:
    """Лист «Сведения»: откуда выгрузка (договор, прогон, фильтры, время)."""
    return Sheet("Сведения", [Column("Параметр", 24), Column("Значение", 70, wrap=True)],
                 [[k, v] for k, v in pairs])


def render(fmt: TableFormat, main: Sheet, *extra: Sheet, info: Sheet | None = None) -> bytes:
    """CSV — только основной лист; XLSX — основной, дополнительные и «Сведения»."""
    if fmt is TableFormat.CSV:
        return to_csv(main)
    return to_xlsx([main, *extra, *([info] if info else [])])
