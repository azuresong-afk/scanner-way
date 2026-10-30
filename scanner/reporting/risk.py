"""Приоритизация находок: «что исправлять первым» поверх CVSS (R6).

Формула намеренно простая и прозрачная — заказчик видит из чего сложился
приоритет (факторы выводятся в отчёте, JSON и подсказке в интерфейсе).

    приоритет = min(100, базовый_балл × K_kev × K_epss × K_exploit × K_актив)

* базовый балл — CVSS × 10 (0–100); если CVSS нет — по уровню опасности
  (критический 95, высокий 80, средний 55, низкий 25);
* K_kev     — 1.50, если CVE есть в каталоге CISA KEV (эксплуатируется в реальных атаках);
* K_epss    — по вероятности эксплуатации EPSS (максимум по CVE находки):
              ≥ 0.50 → 1.30; ≥ 0.10 → 1.15; ≥ 0.01 → 1.05; иначе 1.00;
* K_exploit — 1.20, если БДУ ФСТЭК отмечает наличие эксплойта;
* K_актив   — по критичности актива (R7): low 0.80, medium 1.00, high 1.15, critical 1.30.

Ярлык: ≥ 85 — критический приоритет, ≥ 65 — высокий, ≥ 40 — средний, иначе низкий.
Информационные находки не ранжируются. Без загруженных EPSS/KEV и без критичности
актива работают оставшиеся факторы (CVSS и критичность по умолчанию medium).

Ранг — порядковый номер по убыванию балла; при равенстве — по уровню опасности,
хосту, порту, идентификатору и модулю, поэтому порядок детерминирован.
Сроков и дат устранения приоритет не содержит.
"""
from __future__ import annotations

import ipaddress
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field

from scanner.core.models import Finding, Severity

K_KEV = 1.50
K_EXPLOIT = 1.20
# (порог EPSS, множитель) — по убыванию порога
EPSS_STEPS: tuple[tuple[float, float], ...] = ((0.50, 1.30), (0.10, 1.15), (0.01, 1.05))
K_CRITICALITY: Mapping[str, float] = {"low": 0.80, "medium": 1.00, "high": 1.15,
                                      "critical": 1.30}
DEFAULT_CRITICALITY = "medium"
SEVERITY_BASE: Mapping[Severity, float] = {
    Severity.CRITICAL: 95.0, Severity.HIGH: 80.0, Severity.MEDIUM: 55.0,
    Severity.LOW: 25.0, Severity.INFO: 0.0}
LABEL_STEPS: tuple[tuple[float, str, str], ...] = (
    (85.0, "critical", "Критический приоритет"),
    (65.0, "high", "Высокий приоритет"),
    (40.0, "medium", "Средний приоритет"),
    (0.0, "low", "Низкий приоритет"))
CRITICALITY_LABELS = {"low": "низкая", "medium": "средняя", "high": "высокая",
                      "critical": "критическая"}

FORMULA_TEXT = (
    "Приоритет = CVSS×10 × (1,5 при наличии в CISA KEV) × (1,05 / 1,15 / 1,30 при EPSS "
    "≥ 1% / 10% / 50%) × (1,2 при известном эксплойте в БДУ ФСТЭК) × (0,8 / 1,0 / 1,15 / "
    "1,3 по критичности актива: низкая / средняя / высокая / критическая); не более 100. "
    "Критический ≥ 85, высокий ≥ 65, средний ≥ 40, иначе низкий.")


def exploit_known(text: str | None) -> bool:
    """Поле БДУ «Наличие эксплойта»: «Существует…» — да; «Данные уточняются», «Нет данных»,
    «Отсутствует» — нет."""
    return bool(text) and text.strip().lower().startswith("существует")


@dataclass(frozen=True, slots=True)
class RiskFactors:
    """Входные факторы одной находки (всё необязательно — деградация без данных)."""
    cvss: float | None = None
    severity: Severity = Severity.INFO
    in_kev: bool = False
    epss: float | None = None
    epss_percentile: float | None = None
    exploit_available: bool = False
    criticality: str = DEFAULT_CRITICALITY


@dataclass(frozen=True, slots=True)
class RiskAssessment:
    score: float
    label: str                 # critical | high | medium | low
    label_ru: str
    factors: RiskFactors
    reasons: list[str] = field(default_factory=list)
    rank: int | None = None    # проставляется rank_findings

    def to_dict(self) -> dict:
        f = self.factors
        return {
            "rank": self.rank, "score": self.score, "label": self.label,
            "label_ru": self.label_ru, "reasons": list(self.reasons),
            "factors": {"cvss": f.cvss, "in_kev": f.in_kev, "epss": f.epss,
                        "epss_percentile": f.epss_percentile,
                        "exploit_available": f.exploit_available,
                        "asset_criticality": f.criticality},
        }


def epss_multiplier(epss: float | None) -> float:
    if epss is None:
        return 1.0
    for threshold, k in EPSS_STEPS:
        if epss >= threshold:
            return k
    return 1.0


def base_score(factors: RiskFactors) -> float:
    if factors.cvss is not None:
        return max(0.0, min(10.0, float(factors.cvss))) * 10.0
    return SEVERITY_BASE[factors.severity]


def label_of(score: float) -> tuple[str, str]:
    for threshold, key, ru in LABEL_STEPS:
        if score >= threshold:
            return key, ru
    return LABEL_STEPS[-1][1], LABEL_STEPS[-1][2]


def assess(factors: RiskFactors) -> RiskAssessment | None:
    """Оценка находки; None — для информационных (не ранжируются)."""
    if factors.severity is Severity.INFO:
        return None
    crit = factors.criticality if factors.criticality in K_CRITICALITY else DEFAULT_CRITICALITY
    base = base_score(factors)
    score = base
    reasons = [f"CVSS {factors.cvss:.1f}" if factors.cvss is not None
               else "CVSS не указан, оценка по уровню опасности"]
    if factors.in_kev:
        score *= K_KEV
        reasons.append("входит в каталог CISA KEV (эксплуатируется в реальных атаках)")
    k_epss = epss_multiplier(factors.epss)
    score *= k_epss
    if k_epss > 1.0:
        reasons.append(f"высокая вероятность эксплуатации EPSS {factors.epss:.1%}")
    if factors.exploit_available:
        score *= K_EXPLOIT
        reasons.append("в БДУ ФСТЭК отмечено наличие эксплойта")
    score *= K_CRITICALITY[crit]
    if crit != DEFAULT_CRITICALITY:
        reasons.append(f"критичность актива: {CRITICALITY_LABELS[crit]}")
    score = round(min(100.0, score), 1)
    key, ru = label_of(score)
    return RiskAssessment(score=score, label=key, label_ru=ru, factors=factors,
                          reasons=reasons)


@dataclass(slots=True)
class RiskContext:
    """Справочные данные для оценки находок: EPSS, KEV, эксплойты БДУ, критичность активов.

    Любое из полей может быть пустым — приоритет тогда считается по оставшимся факторам.
    """
    epss: Mapping[str, tuple[float, float | None]] = field(default_factory=dict)  # CVE → (score, percentile)
    kev: frozenset[str] = frozenset()
    exploit_bdu: frozenset[str] = frozenset()      # БДУ-идентификаторы с эксплойтом (верхний регистр)
    criticality: Mapping[str, str] = field(default_factory=dict)   # адрес (нормализованный) → уровень

    def factors_for(self, f: Finding) -> RiskFactors:
        cves = {c.upper() for c in f.cve_ids}
        if f.vuln_id and f.vuln_id.upper().startswith("CVE-"):
            cves.add(f.vuln_id.upper())
        bdus = {b.upper() for b in f.bdu_ids}
        if f.vuln_id and f.vuln_id.upper().startswith("BDU:"):
            bdus.add(f.vuln_id.upper())
        known = [(self.epss[c]) for c in sorted(cves) if c in self.epss]
        best = max(known, key=lambda p: p[0]) if known else None
        return RiskFactors(
            cvss=f.cvss, severity=f.severity,
            in_kev=any(c in self.kev for c in cves),
            epss=best[0] if best else None,
            epss_percentile=best[1] if best else None,
            exploit_available=bool(bdus & self.exploit_bdu),
            criticality=self.criticality.get(normalize_host(f.host), DEFAULT_CRITICALITY))


def normalize_host(host: object) -> str:
    try:
        return str(ipaddress.ip_address(str(host).strip().split("/")[0]))
    except ValueError:
        return str(host)


def _tiebreak(f: Finding) -> tuple:
    try:
        ip = (0, int(ipaddress.ip_address(normalize_host(f.host))))
    except ValueError:
        ip = (1, 0)
    return (ip, f.port if f.port is not None else -1, f.vuln_id or "", f.module,
            f.dedup_key())


def rank_findings(findings: Iterable[Finding],
                  ctx: RiskContext | None = None) -> dict[str, RiskAssessment]:
    """{dedup_key: оценка с рангом}. Детерминированно; info-находки пропускаются."""
    ctx = ctx or RiskContext()
    scored: list[tuple[Finding, RiskAssessment]] = []
    for f in findings:
        a = assess(ctx.factors_for(f))
        if a is not None:
            scored.append((f, a))
    scored.sort(key=lambda p: (-p[1].score, -list(Severity).index(p[0].severity)) + _tiebreak(p[0]))
    out: dict[str, RiskAssessment] = {}
    for rank, (f, a) in enumerate(scored, 1):
        key = f.dedup_key()
        if key not in out:
            out[key] = RiskAssessment(a.score, a.label, a.label_ru, a.factors, a.reasons, rank)
    return out


def build_risk_context(session, findings: Iterable[Finding], engagement_id: int
                       ) -> RiskContext:
    """Собирает справочные данные по находкам: EPSS/KEV, эксплойты БДУ, критичность активов.

    Любой недоступный справочник (таблица не создана, БДУ не загружен) даёт пустой
    результат — приоритет считается по оставшимся факторам.
    """
    from sqlalchemy import select
    from sqlalchemy.exc import SQLAlchemyError

    from scanner.core.db import AssetRow
    from scanner.feeds.epss import lookup_epss
    from scanner.feeds.kev import lookup_kev
    from scanner.feeds.store import SqlReferenceStore

    findings = list(findings)
    engine = session.get_bind()
    cves: set[str] = set()
    bdus: set[str] = set()
    for f in findings:
        cves |= {c.upper() for c in f.cve_ids}
        bdus |= {b.upper() for b in f.bdu_ids}
        if f.vuln_id:
            v = f.vuln_id.upper()
            (cves if v.startswith("CVE-") else bdus if v.startswith("BDU:") else set()).add(v)
    exploit: set[str] = set()
    if bdus:
        store = SqlReferenceStore(engine)
        try:
            for b in sorted(bdus):
                rec = store.get_bdu(b)
                if rec is not None and exploit_known(rec.exploit_available):
                    exploit.add(b)
        except SQLAlchemyError:
            exploit = set()
    crit = {normalize_host(a): c for a, c in session.execute(
        select(AssetRow.address, AssetRow.criticality)
        .where(AssetRow.engagement_id == engagement_id))}
    return RiskContext(epss=lookup_epss(engine, cves), kev=lookup_kev(engine, cves),
                       exploit_bdu=frozenset(exploit), criticality=crit)
