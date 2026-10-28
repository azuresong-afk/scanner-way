"""Рекомендации по устранению для каждой находки.

Источники в порядке приоритета:
  1. рекомендация, уже записанная в саму находку (поле `remediation`, если его
     заполнил модуль/матчер — например, правило бенчмарка в config audit);
  2. БДУ ФСТЭК: «Возможные меры по устранению» + «Способ устранения»
     (по `bdu_ids` находки или через связь CVE -> БДУ);
  3. NVD / вендор: меры и ссылки на бюллетени по CVE;
  4. правила бенчмарка (CIS / ФСТЭК / ГОСТ) по идентификатору правила;
  5. типовая рекомендация по типу находки — чтобы в отчёте не было находок
     без указаний, что делать.

Справочники передаются извне (из БД или фидов), поэтому модуль не зависит от
persistence и тестируется на фикстурах.
"""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Protocol

from scanner.core.models import Finding, FindingType, Severity


class RemediationSource(StrEnum):
    FINDING = "finding"
    BDU = "bdu_fstec"
    NVD = "nvd"
    BENCHMARK = "benchmark"
    GENERIC = "generic"


SOURCE_LABELS: dict[RemediationSource, str] = {
    RemediationSource.FINDING: "Модуль сканирования",
    RemediationSource.BDU: "БДУ ФСТЭК России",
    RemediationSource.NVD: "NVD / производитель",
    RemediationSource.BENCHMARK: "Правило бенчмарка",
    RemediationSource.GENERIC: "Типовая рекомендация",
}

# Рекомендуемые сроки устранения по уровню опасности (дни). Значения по
# умолчанию — типовая практика; переопределяются через RemediationResolver.
DEFAULT_DEADLINES: dict[Severity, int | None] = {
    Severity.CRITICAL: 3,
    Severity.HIGH: 14,
    Severity.MEDIUM: 30,
    Severity.LOW: 90,
    Severity.INFO: None,
}


class BduLike(Protocol):
    """Минимум полей записи БДУ (совместимо с feeds.bdu_fstec.BduRecord)."""
    bdu_id: str
    remediation: str | None
    fix_method: str | None
    cve_ids: list[str]


@dataclass(slots=True)
class Remediation:
    text: str
    source: RemediationSource
    references: list[str] = field(default_factory=list)
    deadline_days: int | None = None
    fix_method: str | None = None

    @property
    def source_label(self) -> str:
        return SOURCE_LABELS[self.source]

    def to_dict(self) -> dict:
        return {
            "text": self.text,
            "source": str(self.source),
            "source_label": self.source_label,
            "fix_method": self.fix_method,
            "deadline_days": self.deadline_days,
            "references": list(self.references),
        }


def bdu_url(bdu_id: str) -> str:
    """BDU:2023-00001 -> https://bdu.fstec.ru/vul/2023-00001"""
    return f"https://bdu.fstec.ru/vul/{bdu_id.split(':', 1)[-1]}"


def nvd_url(cve_id: str) -> str:
    return f"https://nvd.nist.gov/vuln/detail/{cve_id}"


_GENERIC: dict[FindingType, str] = {
    FindingType.VULN: (
        "Установите обновление производителя, устраняющее уязвимость, или "
        "обновите ПО до поддерживаемой версии. Если обновление невозможно — "
        "ограничьте сетевой доступ к сервису (межсетевой экран, сегментация) "
        "и усильте мониторинг до устранения."
    ),
    FindingType.CONFIG: (
        "Приведите настройку в соответствие с требованием бенчмарка "
        "(CIS / ФСТЭК / ГОСТ), внесите изменение в эталонную конфигурацию и "
        "проверьте повторным сканированием."
    ),
    FindingType.CRED: (
        "Немедленно смените пароль учётной записи на стойкий (не менее 12 "
        "символов, не словарный), отключите учётные записи по умолчанию, "
        "включите блокировку после неудачных попыток и, где возможно, "
        "многофакторную аутентификацию."
    ),
    FindingType.INFO: (
        "Проверьте, что сервис необходим и доступен только из доверенных "
        "сегментов сети; отключите неиспользуемые сервисы."
    ),
}


def _clean(text: str | None) -> str | None:
    if text is None:
        return None
    text = text.strip()
    return text or None


class RemediationResolver:
    """Подбирает рекомендацию по устранению для находки."""

    def __init__(
        self,
        *,
        bdu: Mapping[str, BduLike] | None = None,
        nvd: Mapping[str, str] | None = None,
        benchmark: Mapping[str, str] | None = None,
        deadlines: Mapping[Severity, int | None] | None = None,
    ):
        # bdu: bdu_id -> запись БДУ; nvd: cve_id -> текст мер;
        # benchmark: id правила -> текст исправления.
        self.bdu = {k.upper(): v for k, v in (bdu or {}).items()}
        self.nvd = {k.upper(): v for k, v in (nvd or {}).items()}
        self.benchmark = dict(benchmark or {})
        self.deadlines = dict(DEFAULT_DEADLINES if deadlines is None else deadlines)
        # обратный индекс CVE -> записи БДУ (одна CVE может быть в нескольких)
        self._bdu_by_cve: dict[str, list[BduLike]] = {}
        for rec in self.bdu.values():
            for cve in rec.cve_ids or []:
                self._bdu_by_cve.setdefault(cve.upper(), []).append(rec)

    def _cves(self, f: Finding) -> list[str]:
        ids = [c.upper() for c in f.cve_ids]
        if f.vuln_id and f.vuln_id.upper().startswith("CVE-") and f.vuln_id.upper() not in ids:
            ids.insert(0, f.vuln_id.upper())
        return ids

    def _bdus(self, f: Finding) -> list[str]:
        ids = [b.upper() for b in f.bdu_ids]
        if f.vuln_id and f.vuln_id.upper().startswith("BDU:") and f.vuln_id.upper() not in ids:
            ids.insert(0, f.vuln_id.upper())
        return ids

    def references(self, f: Finding) -> list[str]:
        return [bdu_url(b) for b in self._bdus(f)] + [nvd_url(c) for c in self._cves(f)]

    def resolve(self, f: Finding) -> Remediation:
        deadline = self.deadlines.get(f.severity)
        if f.finding_type is FindingType.CRED:
            # подобранный пароль эксплуатируется сразу — срок как у критических
            deadline = self.deadlines.get(Severity.CRITICAL, deadline)
        refs = self.references(f)

        own = _clean(getattr(f, "remediation", None))
        if own:
            return Remediation(own, RemediationSource.FINDING, refs, deadline)

        bdu_records = [self.bdu[b] for b in self._bdus(f) if b in self.bdu]
        if not bdu_records:
            for cve in self._cves(f):
                bdu_records.extend(self._bdu_by_cve.get(cve, []))
        for rec in bdu_records:
            text = _clean(rec.remediation)
            if text:
                extra = [bdu_url(rec.bdu_id)] if bdu_url(rec.bdu_id) not in refs else []
                return Remediation(text, RemediationSource.BDU, refs + extra, deadline,
                                   fix_method=_clean(rec.fix_method))

        for cve in self._cves(f):
            text = _clean(self.nvd.get(cve))
            if text:
                return Remediation(text, RemediationSource.NVD, refs, deadline)

        if f.finding_type is FindingType.CONFIG and f.vuln_id:
            text = _clean(self.benchmark.get(f.vuln_id))
            if text:
                return Remediation(text, RemediationSource.BENCHMARK, refs, deadline)

        return Remediation(_GENERIC[f.finding_type], RemediationSource.GENERIC, refs, deadline)
