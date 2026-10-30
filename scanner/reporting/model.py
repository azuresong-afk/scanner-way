"""Модель отчёта — общий источник данных для всех форматов (HTML/PDF/DOCX/JSON).

Строится один раз из списка находок текущего (и, опционально, предыдущего)
прогона; рендеры только отображают её, поэтому содержимое форматов совпадает.

Структура:
  * summary — краткое резюме для руководителя (уровень риска, ключевые выводы);
  * plan — план устранения: одинаковые меры объединены по хостам и
    отсортированы по опасности/сроку;
  * combined — сводный раздел по всем модулям;
  * modules — разделы по каждому модулю раздельно;
  * trend — сравнение с предыдущим прогоном (open/fixed/new/regression +
    динамика по severity) сводно и в каждом модульном разделе.

Краткая версия (`brief_report`) — та же модель без плана устранения; вместо
текстовых рекомендаций по каждой находке остаются только ссылки на устранение.

Находки, отмеченные как ложные срабатывания (`false_positives`), в отчёт и
сравнение не входят: они перечислены отдельным разделом (`false_positives`).
"""
from __future__ import annotations

import ipaddress
from collections.abc import Collection, Iterable, Mapping
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime

from scanner.core.models import (
    FalsePositiveMark,
    Finding,
    FindingStatus,
    FindingType,
    Severity,
)
from scanner.reporting.diff import RunDiff, diff_by_module, diff_runs, severity_counts
from scanner.reporting.remediation import Remediation, RemediationResolver

SCHEMA_VERSION = "1.0"

# Отсылка к плану в ключевых выводах — в краткой версии плана нет
_PLAN_HINT = " (см. план устранения)"


def _generator_version() -> str:
    from importlib.metadata import PackageNotFoundError, version
    try:
        return version("scanner")
    except PackageNotFoundError:  # пакет не установлен (запуск из исходников)
        return "dev"

SEVERITY_ORDER: list[Severity] = [
    Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO,
]
_RANK = {s: i for i, s in enumerate(SEVERITY_ORDER)}

SEVERITY_LABELS: dict[Severity, str] = {
    Severity.CRITICAL: "Критический",
    Severity.HIGH: "Высокий",
    Severity.MEDIUM: "Средний",
    Severity.LOW: "Низкий",
    Severity.INFO: "Информационный",
}

STATUS_LABELS: dict[FindingStatus, str] = {
    FindingStatus.NEW: "Новая",
    FindingStatus.OPEN: "Не устранена",
    FindingStatus.REGRESSION: "Повторно выявлена",
    FindingStatus.FIXED: "Устранена",
}

MODULE_LABELS: dict[str, str] = {
    "discovery": "Инвентаризация сети",
    "vuln": "Уязвимости ПО",
    "auth_inventory": "Уязвимости ПО по учётной записи",
    "config_audit": "Аудит конфигураций",
    "cred_audit": "Аудит учётных записей",
}


def module_label(module: str) -> str:
    return MODULE_LABELS.get(module, module)


def _host_key(host: object) -> str:
    """Адрес в каноническом виде; не-IP (имя хоста) остаётся как есть."""
    text = str(host).split("/")[0]
    try:
        return str(ipaddress.ip_address(text))
    except ValueError:
        return text


def _sort_key(f: Finding) -> tuple:
    return (_RANK[f.severity], -(f.cvss or 0.0), f.host, f.port or 0, f.title)


@dataclass(slots=True)
class ReportContext:
    """Метаданные отчёта (заполняет вызывающий код: API/оркестратор)."""
    title: str = "Отчёт о результатах анализа защищённости"
    customer: str | None = None
    engagement: str | None = None        # договор / проект
    run_id: str | int | None = None
    previous_run_id: str | int | None = None
    group: str | None = None             # группа активов, если отчёт — разрез по группе
    generated_at: datetime = field(default_factory=lambda: datetime.now(UTC))


@dataclass(slots=True)
class FindingView:
    finding: Finding
    remediation: Remediation
    status: FindingStatus | None = None   # None — нет предыдущего прогона

    @property
    def severity_label(self) -> str:
        return SEVERITY_LABELS[self.finding.severity]

    @property
    def status_label(self) -> str | None:
        return STATUS_LABELS[self.status] if self.status else None

    @property
    def module_label(self) -> str:
        return module_label(self.finding.module)

    @property
    def target(self) -> str:
        f = self.finding
        return f"{f.host}:{f.port}" if f.port is not None else f.host

    def to_dict(self) -> dict:
        f = self.finding
        return {
            "id": f.dedup_key(),
            "module": f.module,
            "module_label": self.module_label,
            "type": str(f.finding_type),
            "title": f.title,
            "severity": str(f.severity),
            "severity_label": self.severity_label,
            "status": str(self.status) if self.status else None,
            "status_label": self.status_label,
            "host": f.host,
            "port": f.port,
            "vuln_id": f.vuln_id,
            "cve_ids": list(f.cve_ids),
            "bdu_ids": list(f.bdu_ids),
            "cvss": f.cvss,
            "evidence": f.evidence,
            "detected_at": f.detected_at.isoformat(),
            "remediation": self.remediation.to_dict(),
        }


@dataclass(slots=True)
class SeverityDelta:
    severity: Severity
    previous: int
    current: int

    @property
    def delta(self) -> int:
        return self.current - self.previous

    @property
    def label(self) -> str:
        return SEVERITY_LABELS[self.severity]

    def to_dict(self) -> dict:
        return {"severity": str(self.severity), "label": self.label,
                "previous": self.previous, "current": self.current, "delta": self.delta}


@dataclass(slots=True)
class Trend:
    counts: dict[FindingStatus, int]
    severity: list[SeverityDelta]
    fixed: list[FindingView]

    @property
    def verdict(self) -> str:
        c = self.counts
        bad = c[FindingStatus.NEW] + c[FindingStatus.REGRESSION]
        good = c[FindingStatus.FIXED]
        if good > bad:
            return "Положительная динамика: устранено больше, чем выявлено новых и повторных."
        if bad > good:
            return "Отрицательная динамика: новых и повторно выявленных больше, чем устранённых."
        return "Без существенных изменений по сравнению с предыдущим прогоном."

    def to_dict(self) -> dict:
        return {
            "counts": {str(k): v for k, v in self.counts.items()},
            "verdict": self.verdict,
            "severity_dynamics": [d.to_dict() for d in self.severity],
            "fixed": [v.to_dict() for v in self.fixed],
        }


@dataclass(slots=True)
class Section:
    key: str              # имя модуля или "combined"
    label: str
    findings: list[FindingView]
    trend: Trend | None = None

    @property
    def severity_counts(self) -> dict[Severity, int]:
        return severity_counts([v.finding for v in self.findings])

    @property
    def by_severity(self) -> list[tuple[Severity, str, list[FindingView]]]:
        """Группы находок по уровню опасности (только непустые)."""
        out = []
        for s in SEVERITY_ORDER:
            group = [v for v in self.findings if v.finding.severity is s]
            if group:
                out.append((s, SEVERITY_LABELS[s], group))
        return out

    def to_dict(self) -> dict:
        return {
            "key": self.key,
            "label": self.label,
            "total": len(self.findings),
            "severity_counts": {str(k): v for k, v in self.severity_counts.items()},
            "findings": [v.to_dict() for v in self.findings],
            "trend": self.trend.to_dict() if self.trend else None,
        }


@dataclass(slots=True)
class FalsePositiveView:
    """Находка прогона, исключённая из отчёта как ложное срабатывание."""
    finding: Finding
    mark: FalsePositiveMark

    @property
    def severity_label(self) -> str:
        return SEVERITY_LABELS[self.finding.severity]

    @property
    def module_label(self) -> str:
        return module_label(self.finding.module)

    @property
    def target(self) -> str:
        f = self.finding
        return f"{f.host}:{f.port}" if f.port is not None else f.host

    def to_dict(self) -> dict:
        f, m = self.finding, self.mark
        return {
            "id": f.dedup_key(),
            "module": f.module,
            "module_label": self.module_label,
            "title": f.title,
            "severity": str(f.severity),
            "severity_label": self.severity_label,
            "host": f.host,
            "port": f.port,
            "vuln_id": f.vuln_id,
            "cve_ids": list(f.cve_ids),
            "bdu_ids": list(f.bdu_ids),
            "reason": m.reason,
            "marked_by": m.marked_by,
            "marked_at": m.marked_at.isoformat() if m.marked_at else None,
        }


@dataclass(slots=True)
class PlanItem:
    """Одна мера устранения, применимая к нескольким находкам/хостам."""
    severity: Severity
    action: str
    source_label: str
    deadline_days: int | None
    titles: list[str]
    targets: list[str]
    references: list[str]

    @property
    def severity_label(self) -> str:
        return SEVERITY_LABELS[self.severity]

    def to_dict(self) -> dict:
        return {
            "severity": str(self.severity), "severity_label": self.severity_label,
            "action": self.action, "source_label": self.source_label,
            "deadline_days": self.deadline_days, "titles": self.titles,
            "targets": self.targets, "references": self.references,
        }


@dataclass(slots=True)
class HostRisk:
    host: str
    counts: dict[Severity, int]

    @property
    def total(self) -> int:
        return sum(self.counts.values())

    def to_dict(self) -> dict:
        return {"host": self.host, "total": self.total,
                "severity_counts": {str(k): v for k, v in self.counts.items()}}


@dataclass(slots=True)
class Summary:
    total: int
    hosts: int
    severity_counts: dict[Severity, int]
    risk_level: Severity | None
    top_hosts: list[HostRisk]
    key_points: list[str]

    @property
    def risk_label(self) -> str:
        return SEVERITY_LABELS[self.risk_level] if self.risk_level else "Не выявлен"

    def to_dict(self) -> dict:
        return {
            "total": self.total, "hosts": self.hosts,
            "severity_counts": {str(k): v for k, v in self.severity_counts.items()},
            "risk_level": str(self.risk_level) if self.risk_level else None,
            "risk_label": self.risk_label,
            "top_hosts": [h.to_dict() for h in self.top_hosts],
            "key_points": list(self.key_points),
        }


@dataclass(slots=True)
class Report:
    context: ReportContext
    summary: Summary
    plan: list[PlanItem]
    combined: Section
    modules: list[Section]
    brief: bool = False   # краткая версия: без плана и текстов рекомендаций
    false_positives: list[FalsePositiveView] = field(default_factory=list)

    @property
    def has_trend(self) -> bool:
        return self.combined.trend is not None

    @property
    def variant(self) -> str:
        return "brief" if self.brief else "full"

    def to_dict(self) -> dict:
        c = self.context
        out = {
            "schema_version": SCHEMA_VERSION,
            "generator": {"name": "scanner", "version": _generator_version()},
            "meta": {
                "title": c.title, "customer": c.customer, "engagement": c.engagement,
                "run_id": c.run_id, "previous_run_id": c.previous_run_id,
                "group": c.group,
                "generated_at": c.generated_at.isoformat(),
                "variant": self.variant,
            },
            "summary": self.summary.to_dict(),
            "remediation_plan": [p.to_dict() for p in self.plan],
            "combined": self.combined.to_dict(),
            "modules": [m.to_dict() for m in self.modules],
            "false_positives": [v.to_dict() for v in self.false_positives],
        }
        if self.brief:
            del out["remediation_plan"]
            for sec in [out["combined"], *out["modules"]]:
                views = sec["findings"] + (sec["trend"]["fixed"] if sec["trend"] else [])
                for f in views:
                    f["remediation"] = {"references": f["remediation"]["references"]}
        return out


def brief_report(report: Report) -> Report:
    """Краткая версия отчёта: без плана устранения, по находкам — только ссылки."""
    points = [p.replace(_PLAN_HINT, "") for p in report.summary.key_points]
    return replace(report, plan=[], brief=True,
                   summary=replace(report.summary, key_points=points))


# --- построение -------------------------------------------------------------

def _status_map(d: RunDiff) -> dict[str, FindingStatus]:
    out: dict[str, FindingStatus] = {}
    for status, items in ((FindingStatus.OPEN, d.open), (FindingStatus.NEW, d.new),
                          (FindingStatus.REGRESSION, d.regression)):
        for f in items:
            out[f.dedup_key()] = status
    return out


def _trend(d: RunDiff, previous: list[Finding], current: list[Finding],
           resolver: RemediationResolver) -> Trend:
    prev_c, cur_c = severity_counts(previous), severity_counts(current)
    return Trend(
        counts={FindingStatus.OPEN: len(d.open), FindingStatus.NEW: len(d.new),
                FindingStatus.REGRESSION: len(d.regression),
                FindingStatus.FIXED: len(d.fixed)},
        severity=[SeverityDelta(s, prev_c[s], cur_c[s]) for s in SEVERITY_ORDER],
        fixed=[FindingView(f, resolver.resolve(f), FindingStatus.FIXED)
               for f in sorted(d.fixed, key=_sort_key)],
    )


def _plan(views: list[FindingView]) -> list[PlanItem]:
    groups: dict[str, list[FindingView]] = {}
    for v in views:
        if v.finding.severity is Severity.INFO:
            continue
        groups.setdefault(v.remediation.text, []).append(v)
    items = []
    for action, vs in groups.items():
        worst = min((v.finding.severity for v in vs), key=_RANK.__getitem__)
        deadlines = [v.remediation.deadline_days for v in vs
                     if v.remediation.deadline_days is not None]
        items.append(PlanItem(
            severity=worst,
            action=action,
            source_label=vs[0].remediation.source_label,
            deadline_days=min(deadlines) if deadlines else None,
            titles=sorted({v.finding.title for v in vs}),
            targets=sorted({v.target for v in vs}),
            references=sorted({r for v in vs for r in v.remediation.references}),
        ))
    items.sort(key=lambda p: (_RANK[p.severity], -len(p.targets), p.action))
    return items


def _summary(views: list[FindingView], trend: Trend | None,
             false_positives: int = 0) -> Summary:
    findings = [v.finding for v in views]
    counts = severity_counts(findings)
    risk = next((s for s in SEVERITY_ORDER[:-1] if counts[s]), None)
    per_host: dict[str, list[Finding]] = {}
    for f in findings:
        per_host.setdefault(f.host, []).append(f)
    hosts = [HostRisk(h, severity_counts(fs)) for h, fs in per_host.items()]
    hosts.sort(key=lambda h: tuple(-h.counts[s] for s in SEVERITY_ORDER) + (h.host,))

    points: list[str] = []
    urgent = counts[Severity.CRITICAL] + counts[Severity.HIGH]
    if urgent:
        urgent_hosts = len({f.host for f in findings
                            if f.severity in (Severity.CRITICAL, Severity.HIGH)})
        points.append(
            f"Находок критического и высокого уровня: {urgent} (хостов: {urgent_hosts}). "
            f"Их устранение — первоочередная задача{_PLAN_HINT}.")
    else:
        points.append("Находок критического и высокого уровня не выявлено.")
    creds = [f for f in findings if f.finding_type is FindingType.CRED]
    if creds:
        points.append(f"Выявлены слабые или стандартные учётные данные: {len(creds)}. "
                      "Требуется немедленная смена паролей.")
    if trend:
        c = trend.counts
        points.append(
            f"По сравнению с предыдущим прогоном: устранено {c[FindingStatus.FIXED]}, "
            f"новых {c[FindingStatus.NEW]}, повторно выявлено {c[FindingStatus.REGRESSION]}, "
            f"не устранено {c[FindingStatus.OPEN]}.")
        if c[FindingStatus.REGRESSION]:
            points.append("Повторное появление ранее устранённых уязвимостей указывает на "
                          "проблемы в процессе управления изменениями или обновлениями.")
    if false_positives:
        points.append(f"Исключено как ложные срабатывания: {false_positives} "
                      "(перечень — в разделе «Ложные срабатывания»).")
    return Summary(total=len(findings), hosts=len(per_host), severity_counts=counts,
                   risk_level=risk, top_hosts=hosts[:5], key_points=points)


def build_report(
    current: Iterable[Finding],
    *,
    previous: Iterable[Finding] | None = None,
    historically_fixed: set[str] | None = None,
    resolver: RemediationResolver | None = None,
    context: ReportContext | None = None,
    false_positives: Mapping[str, FalsePositiveMark] | None = None,
    hosts: Collection[str] | None = None,
) -> Report:
    """Строит модель отчёта.

    previous=None — первый прогон, раздел сравнения не формируется.
    historically_fixed — ключи, помеченные fixed в более ранних прогонах
    (для определения regression, см. diff_runs).
    false_positives — {dedup_key: отметка}: такие находки исключаются из обоих
    прогонов (не считаются ни открытыми, ни устранёнными) и идут в отдельный раздел.
    hosts — адреса хостов (например, активов группы): в отчёт попадают только
    находки этих хостов; None — без фильтра (поведение по умолчанию).
    """
    resolver = resolver or RemediationResolver()
    context = context or ReportContext()
    fp = false_positives or {}
    if hosts is not None:
        allowed = {_host_key(h) for h in hosts}
        current = [f for f in current if _host_key(f.host) in allowed]
        if previous is not None:
            previous = [f for f in previous if _host_key(f.host) in allowed]
    cur_all = sorted(current, key=_sort_key)
    cur = [f for f in cur_all if f.dedup_key() not in fp]
    fp_views = [FalsePositiveView(f, fp[f.dedup_key()])
                for f in cur_all if f.dedup_key() in fp]
    prev = ([f for f in previous if f.dedup_key() not in fp]
            if previous is not None else None)

    statuses: dict[str, FindingStatus] = {}
    combined_trend = None
    module_diffs: dict[str, RunDiff] = {}
    if prev is not None:
        d = diff_runs(prev, cur, historically_fixed)
        statuses = _status_map(d)
        combined_trend = _trend(d, prev, cur, resolver)
        module_diffs = diff_by_module(prev, cur, historically_fixed)

    views = [FindingView(f, resolver.resolve(f), statuses.get(f.dedup_key())) for f in cur]

    modules: list[Section] = []
    names = sorted({f.module for f in cur} | set(module_diffs),
                   key=lambda m: (list(MODULE_LABELS).index(m) if m in MODULE_LABELS
                                  else len(MODULE_LABELS), m))
    for m in names:
        trend = None
        if prev is not None:
            trend = _trend(module_diffs[m], [f for f in prev if f.module == m],
                           [f for f in cur if f.module == m], resolver)
        modules.append(Section(m, module_label(m),
                               [v for v in views if v.finding.module == m], trend))

    return Report(
        context=context,
        summary=_summary(views, combined_trend, len(fp_views)),
        plan=_plan(views),
        combined=Section("combined", "Сводно по всем модулям", views, combined_trend),
        modules=modules,
        false_positives=fp_views,
    )
