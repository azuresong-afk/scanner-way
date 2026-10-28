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
    """Достаёт числовую базовую оценку CVSS из текста уровня опасности."""
    if rec.severity_text:
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

    def sync(self) -> int:
        # TODO (итерация 3): upsert записей в reference_bdu_entry, заполнить
        # cve_ids[] для связи с reference_nvd_cve. Парсинг уже реализован выше.
        count = 0
        for _rec in self.iter_records():
            count += 1
        return count
