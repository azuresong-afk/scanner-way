"""Выгрузка «Все находки» и «Что исправить» в таблицы (CSV / Excel).

Колонки — те же сведения, что на экране: находки с рекомендацией и ссылками на
устранение (ссылки — общая логика RemediationResolver.references, как в
отчёте), план исправлений с командами, проверкой и списком хостов. Сроков
устранения в выгрузке нет (требование к отчётам: каждая организация устраняет
в своём темпе).
"""
from __future__ import annotations

from collections.abc import Sequence
from typing import TYPE_CHECKING

from scanner.core.confidence import CONFIDENCE_LABELS, SOURCE_LABELS
from scanner.core.models import FindingStatus, Severity
from scanner.reporting.fixplan import KIND_LABELS
from scanner.reporting.model import MODULE_LABELS, SEVERITY_LABELS, STATUS_LABELS
from scanner.reporting.tabular import Column, Sheet

if TYPE_CHECKING:
    from scanner.api.schemas import FindingOut
    from scanner.reporting.fixplan import FixTask
    from scanner.reporting.remediation import Remediation

FINDING_COLUMNS = (
    Column("ID", 8), Column("Хост", 15), Column("Порт", 7), Column("Уровень", 14),
    Column("CVSS", 7), Column("Ранг приоритета", 10), Column("Приоритет", 12),
    Column("Название", 50, wrap=True), Column("Идентификатор", 18),
    Column("CVE", 18, wrap=True), Column("БДУ ФСТЭК", 18, wrap=True),
    Column("ПО", 20), Column("Версия ПО", 16), Column("Модуль", 22),
    Column("Статус", 16), Column("Достоверность", 18), Column("Как выявлено", 22),
    Column("Ложное срабатывание", 22, wrap=True), Column("Рекомендация", 60, wrap=True),
    Column("Источник рекомендации", 20), Column("Ссылки на устранение", 50, wrap=True),
    Column("Обнаружено", 16), Column("Доказательство", 60, wrap=True),
)

TASK_COLUMNS = (
    Column("№", 6), Column("Приоритет (балл)", 10), Column("Приоритет", 12),
    Column("Уровень", 14), Column("Действие", 50, wrap=True), Column("Вид", 18),
    Column("ОС", 16), Column("Пакеты", 24, wrap=True), Column("Исправленная версия", 20),
    Column("ПО", 18), Column("Что сделать", 50, wrap=True), Column("Команды", 50, wrap=True),
    Column("Проверка результата", 40, wrap=True), Column("Перезагрузка", 12),
    Column("Хостов", 8), Column("Хосты", 22, wrap=True), Column("Находок", 9),
    Column("CVE", 18, wrap=True), Column("БДУ ФСТЭК", 18, wrap=True),
    Column("Бюллетени", 20, wrap=True), Column("Ссылки на устранение", 50, wrap=True),
    Column("Меры по описанию уязвимости", 60, wrap=True),
)

TASK_HOST_COLUMNS = (
    Column("№ действия", 9), Column("Действие", 50, wrap=True), Column("Уровень", 14),
    Column("ОС", 16), Column("Хост", 15), Column("Порты", 12),
    Column("Установлено", 24), Column("Примечание", 30, wrap=True),
    Column("Находки", 30, wrap=True), Column("Команды", 50, wrap=True),
)


SEVERITY_BY_VALUE = {str(k): v for k, v in SEVERITY_LABELS.items()}
STATUS_BY_VALUE = {str(k): v for k, v in STATUS_LABELS.items()}


def _sev(value: str) -> str:
    try:
        return SEVERITY_LABELS[Severity(value)]
    except ValueError:
        return value


def _status(value: str | None) -> str | None:
    if not value:
        return None
    try:
        return STATUS_LABELS[FindingStatus(value)]
    except ValueError:
        return value


def findings_sheet(items: Sequence[tuple[FindingOut, Remediation | None]]) -> Sheet:
    """«Все находки»: строка на находку."""
    rows = []
    for f, rem in items:
        fp = f.false_positive
        rows.append([
            f.id, f.host, f.port, _sev(f.severity), f.cvss,
            f.priority.rank if f.priority else None,
            f.priority.label_ru if f.priority else None,
            f.title, f.vuln_id, f.cve_ids, f.bdu_ids,
            f.software, f.software_version, MODULE_LABELS.get(f.module, f.module),
            _status(f.status),
            CONFIDENCE_LABELS.get(f.confidence or "", f.confidence),
            SOURCE_LABELS.get(f.source or "", f.source),
            None if fp is None else (f"да: {fp.reason}" if fp.reason else "да"),
            rem.text if rem else None, rem.source_label if rem else None,
            rem.references if rem else None,
            f.detected_at, f.evidence,
        ])
    return Sheet("Все находки", FINDING_COLUMNS, rows)


def _host_label(h) -> str:
    return h.host + (":" + ",".join(str(p) for p in sorted(h.ports)) if h.ports else "")


def fix_plan_sheets(tasks: Sequence[FixTask]) -> tuple[Sheet, Sheet]:
    """«Что исправить»: (строка на действие, строка на действие × хост)."""
    main, per_host = [], []
    for i, t in enumerate(tasks, start=1):
        p = t.priority
        sev = SEVERITY_LABELS.get(t.severity, str(t.severity))
        main.append([
            i, round(p.score) if p else None, p.label_ru if p else None, sev,
            t.title, KIND_LABELS.get(t.kind, t.kind), t.os, t.packages, t.fixed_version,
            t.software, t.steps, t.commands, t.verify, t.reboot, len(t.hosts),
            [_host_label(h) for h in t.hosts], t.findings, t.cves, t.bdu_ids,
            t.advisories, [u for u in t.references if u.startswith(("http://", "https://"))],
            t.details,
        ])
        for h in t.hosts:
            per_host.append([
                i, t.title, sev, t.os, h.host, ", ".join(str(x) for x in sorted(h.ports)),
                h.installed, h.note, [x.label for x in h.findings], t.commands,
            ])
    return (Sheet("Что исправить", TASK_COLUMNS, main),
            Sheet("По хостам", TASK_HOST_COLUMNS, per_host))
