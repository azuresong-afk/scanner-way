"""Единая шкала критичности (critical/high/medium/low/info) из CVSS и из БДУ."""
from __future__ import annotations

import re

from scanner.core.models import Severity

_ORDER = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]

# Текстовый уровень опасности БДУ -> шкала. Порядок важен: проверяем по началу строки.
_BDU_LEVELS: list[tuple[str, Severity]] = [
    ("критический", Severity.CRITICAL),
    ("высокий", Severity.HIGH),
    ("средний", Severity.MEDIUM),
    ("низкий", Severity.LOW),
    ("нет опасности", Severity.INFO),
]

# "… (базовая оценка CVSS 3.0 составляет 9,8)" -> ("3.0", "9,8")
_BDU_SCORE_RE = re.compile(
    r"CVSS\s*([0-9.]+)\s*составляет\s*([0-9]+(?:[.,][0-9]+)?)", re.IGNORECASE)


def severity_rank(sev: Severity) -> int:
    return _ORDER.index(sev)


def max_severity(*sevs: Severity | None) -> Severity:
    present = [s for s in sevs if s is not None]
    return max(present, key=severity_rank) if present else Severity.INFO


def severity_from_cvss(score: float | None) -> Severity | None:
    """Качественная шкала CVSS v3: 0 — none, 0.1–3.9 low, 4–6.9 medium, 7–8.9 high, 9+ critical."""
    if score is None:
        return None
    if score >= 9.0:
        return Severity.CRITICAL
    if score >= 7.0:
        return Severity.HIGH
    if score >= 4.0:
        return Severity.MEDIUM
    if score > 0.0:
        return Severity.LOW
    return Severity.INFO


def bdu_scores(severity_text: str | None) -> dict[str, float]:
    """Все базовые оценки из текста уровня опасности БДУ: {версия CVSS: оценка}."""
    if not severity_text:
        return {}
    return {ver: float(score.replace(",", "."))
            for ver, score in _BDU_SCORE_RE.findall(severity_text)}


def bdu_best_score(severity_text: str | None) -> float | None:
    """Оценка по самой новой версии CVSS из текста БДУ (4.0 > 3.1 > 3.0 > 2.0)."""
    scores = bdu_scores(severity_text)
    if not scores:
        return None
    newest = max(scores, key=lambda v: tuple(int(x) for x in v.split(".") if x.isdigit()))
    return scores[newest]


def severity_from_bdu_text(severity_text: str | None) -> Severity | None:
    """Уровень опасности БДУ. Если строк несколько (CVSS 2.0 и 3.x) — берётся
    уровень по самой новой версии CVSS, как и базовая оценка."""
    if not severity_text:
        return None
    lines = [ln.strip() for ln in severity_text.splitlines() if ln.strip()]
    best_line, best_ver = None, (-1,)
    for ln in lines:
        m = _BDU_SCORE_RE.search(ln)
        ver = tuple(int(x) for x in m.group(1).split(".") if x.isdigit()) if m else (0,)
        if ver >= best_ver:
            best_line, best_ver = ln, ver
    low = (best_line or "").lower()
    for prefix, sev in _BDU_LEVELS:
        if low.startswith(prefix):
            return sev
    return None
