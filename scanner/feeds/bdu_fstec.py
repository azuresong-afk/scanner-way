"""Загрузка выгрузки БДУ ФСТЭК России в reference_bdu_entry.

Формат выгрузки (bdu.fstec.ru, файл вида vullist.xlsx):
  * книга Excel (.xlsx), лист «Уязвимости» (~98k строк);
  * строки 1-2 — групповые заголовки, строка 3 — названия колонок,
    данные с 4-й строки;
  * идентификатор БДУ в колонке «Идентификатор» (BDU:ГГГГ-NNNNN);
  * связь с CVE и другими системами — в колонке «Идентификаторы других
    систем описаний уязвимости» (строка вида "CVE-2013-5946, OSVDB ID:...");
  * CVSS 2.0/3.0/4.0 — отдельные колонки (2.0 обычно как вектор);
  * уровень опасности — текст с базовой оценкой, напр.
    "Критический уровень опасности (базовая оценка CVSS 2.0 составляет 10)".

Парсер маппит колонки ПО ИМЕНАМ из строки заголовка (а не по индексам),
поэтому устойчив к перестановке/добавлению колонок в новых выгрузках.
"""
from __future__ import annotations

import re
from collections.abc import Iterator
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from scanner.feeds.severity import bdu_best_score

if TYPE_CHECKING:
    from scanner.feeds.store import ReferenceStore

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)
# Базовая оценка идёт после слова "составляет", напр.
# "базовая оценка CVSS 2.0 составляет 10" -> 10 (а не 2.0 из названия шкалы).
CVSS_SCORE_RE = re.compile(r"составляет\s*([0-9]+(?:[.,][0-9]+)?)", re.IGNORECASE)

SHEET_NAME = "Уязвимости"

# Имя колонки в выгрузке -> поле записи
COLUMN_MAP: dict[str, str] = {
    "Идентификатор": "bdu_id",
    "Наименование уязвимости": "title",
    "Описание уязвимости": "description",
    "Вендор ПО": "vendor",
    "Название ПО": "software",
    "Версия ПО": "versions",
    "Тип ПО": "software_type",
    "Класс уязвимости": "vuln_class",
    "Дата выявления": "detection_date",
    "CVSS 2.0": "cvss2",
    "CVSS 3.0": "cvss3",
    "CVSS 4.0": "cvss4",
    "Уровень опасности уязвимости": "severity_text",
    "Возможные меры по устранению": "remediation",
    "Статус уязвимости": "status",
    "Наличие эксплойта": "exploit_available",
    "Ссылки на источники": "refs",
    "Идентификаторы других систем описаний уязвимости": "other_ids",
    "Способ устранения": "fix_method",
    "Дата публикации": "published_at",
    "Дата последнего обновления": "updated_at",
    "Тип ошибки CWE": "cwe",
}


@dataclass(slots=True)
class BduRecord:
    bdu_id: str
    title: str | None = None
    description: str | None = None
    vendor: str | None = None
    software: str | None = None
    versions: str | None = None
    software_type: str | None = None
    vuln_class: str | None = None
    detection_date: str | None = None
    cvss2: str | None = None
    cvss3: str | None = None
    cvss4: str | None = None
    severity_text: str | None = None
    cvss_score: float | None = None
    remediation: str | None = None
    status: str | None = None
    exploit_available: str | None = None
    refs: str | None = None
    other_ids: str | None = None
    fix_method: str | None = None
    published_at: str | None = None
    updated_at: str | None = None
    cwe: str | None = None
    cve_ids: list[str] = field(default_factory=list)


def _find_header(rows: list[tuple]) -> tuple[int, dict[int, str]]:
    """Находит строку заголовка (где есть ячейка 'Идентификатор') и строит
    отображение индекс_колонки -> имя_поля."""
    for idx, row in enumerate(rows):
        cells = [str(c).strip() if c is not None else "" for c in row]
        if "Идентификатор" in cells:
            mapping: dict[int, str] = {}
            for col_idx, name in enumerate(cells):
                field_name = COLUMN_MAP.get(name)
                if field_name and field_name not in mapping.values():
                    mapping[col_idx] = field_name
            return idx, mapping
    raise ValueError("Заголовок БДУ не найден (нет колонки 'Идентификатор')")


def _parse_score(rec: BduRecord) -> float | None:
    """Достаёт числовую базовую оценку CVSS из текста уровня опасности.

    В выгрузке часто две строки (CVSS 2.0 и 3.x) — берём оценку по самой
    новой версии CVSS; если версия не указана — первое найденное число.
    """
    if rec.severity_text:
        best = bdu_best_score(rec.severity_text)
        if best is not None:
            return best
        m = CVSS_SCORE_RE.search(rec.severity_text)
        if m:
            return float(m.group(1).replace(",", "."))
    return None


def parse_rows(rows: list[tuple]) -> Iterator[BduRecord]:
    """Разбирает строки листа «Уязвимости» в записи BduRecord.

    `rows` — список кортежей значений ячеек (как из openpyxl values_only).
    """
    header_idx, mapping = _find_header(rows)
    id_col = next((i for i, f in mapping.items() if f == "bdu_id"), None)
    if id_col is None:
        raise ValueError("В заголовке БДУ нет колонки идентификатора")

    for row in rows[header_idx + 1:]:
        if id_col >= len(row) or row[id_col] is None:
            continue
        bdu_id = str(row[id_col]).strip()
        if not bdu_id.upper().startswith("BDU:"):
            continue
        data: dict[str, object] = {}
        for col_idx, field_name in mapping.items():
            val = row[col_idx] if col_idx < len(row) else None
            if val is not None:
                data[field_name] = str(val).strip()
        rec = BduRecord(**data)  # type: ignore[arg-type]
        if rec.other_ids:
            rec.cve_ids = sorted({m.group(0).upper() for m in CVE_RE.finditer(rec.other_ids)})
        rec.cvss_score = _parse_score(rec)
        yield rec


class BduFstecFeed:
    def __init__(self, feed_path: str):
        self.feed_path = feed_path

    def iter_records(self) -> Iterator[BduRecord]:
        """Потоково читает XLSX-выгрузку и отдаёт записи БДУ."""
        import openpyxl  # локальный импорт: тяжёлая зависимость только для фида

        wb = openpyxl.load_workbook(self.feed_path, read_only=True, data_only=True)
        ws = wb[SHEET_NAME] if SHEET_NAME in wb.sheetnames else wb[wb.sheetnames[0]]
        rows = list(ws.iter_rows(values_only=True))
        yield from parse_rows(rows)

    def sync(self, store: ReferenceStore, *, batch_size: int = 1000) -> int:
        """Upsert всех записей выгрузки в reference_bdu_entry (вместе с cve_ids[]).

        Повторная загрузка новой выгрузки обновляет записи по bdu_id.
        Возвращает число загруженных записей.
        """
        total, batch = 0, []
        for rec in self.iter_records():
            batch.append(rec)
            if len(batch) >= batch_size:
                total += store.upsert_bdu(batch)
                batch = []
        if batch:
            total += store.upsert_bdu(batch)
        return total


# ---------- Разбор поля «Версия ПО» ----------

@dataclass(frozen=True, slots=True)
class BduVersionSpec:
    """Одна позиция поля «Версия ПО»: «от 2.4.0 до 2.4.51 включительно (HTTP Server)»."""
    software: str
    exact: str | None = None
    start: str | None = None          # «от X» — включительно
    end: str | None = None            # «до Y»
    end_inclusive: bool = False       # «до Y включительно»
    unknown: bool = False             # «-» — версия не указана


_RANGE_RE = re.compile(
    r"^(?:от\s+(?P<start>\S+))?\s*(?:до\s+(?P<end>\S+))?\s*(?P<incl>включительно)?$",
    re.IGNORECASE)


def _split_top_level(text: str) -> list[str]:
    """Делит строку по запятым вне скобок (в названиях ПО бывают вложенные скобки)."""
    items, cur, depth = [], [], 0
    for ch in text:
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth = max(0, depth - 1)
        if ch == "," and depth == 0:
            items.append("".join(cur).strip())
            cur = []
        else:
            cur.append(ch)
    if "".join(cur).strip():
        items.append("".join(cur).strip())
    return items


def parse_bdu_versions(versions: str | None) -> list[BduVersionSpec]:
    """Разбирает поле «Версия ПО» в список (ПО, версия/диапазон)."""
    specs: list[BduVersionSpec] = []
    for item in _split_top_level(versions or ""):
        if not item.endswith(")") or "(" not in item:
            continue
        # Последняя сбалансированная группа скобок — название ПО.
        depth = 0
        for pos in range(len(item) - 1, -1, -1):
            if item[pos] == ")":
                depth += 1
            elif item[pos] == "(":
                depth -= 1
                if depth == 0:
                    break
        expr, software = item[:pos].strip(), item[pos + 1:-1].strip()
        if not software:
            continue
        if expr in ("", "-"):
            specs.append(BduVersionSpec(software, unknown=True))
            continue
        m = _RANGE_RE.match(expr)
        if m and (m.group("start") or m.group("end")):
            specs.append(BduVersionSpec(
                software, start=m.group("start"), end=m.group("end"),
                end_inclusive=bool(m.group("incl"))))
        else:
            specs.append(BduVersionSpec(software, exact=expr))
    return _join_split_ranges(specs)


def _join_split_ranges(specs: list[BduVersionSpec]) -> list[BduVersionSpec]:
    """«от 7.62.0 (Libcurl), до 7.64.1 включительно (Libcurl)» — один диапазон.

    В выгрузке БДУ границы диапазона нередко записаны двумя соседними
    позициями. По отдельности «от 7.62.0» означало бы «все версии начиная с
    7.62.0» — и любая новая версия ложно попадала бы в уязвимые.
    """
    out: list[BduVersionSpec] = []
    for spec in specs:
        prev = out[-1] if out else None
        if (prev is not None and prev.software == spec.software
                and prev.start and not prev.end and not prev.exact
                and spec.end and not spec.start and not spec.exact):
            out[-1] = BduVersionSpec(spec.software, start=prev.start, end=spec.end,
                                     end_inclusive=spec.end_inclusive)
        else:
            out.append(spec)
    return out
