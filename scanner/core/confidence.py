"""Уверенность и источник находки; ограничения достоверности прогона.

Источник (source):
  authenticated_package — версия пакета, прочитанная на хосте по учётной записи
                          (без данных вендора — по версии апстрима);
  vendor_advisory       — подтверждено бюллетенем дистрибутива/MSRC
                          (с учётом бэкпортов);
  banner                — только версия из сетевого баннера (потенциальное
                          совпадение, бэкпорты не учтены);
  nuclei                — сработал активный шаблон Nuclei;
  config                — нарушение конфигурации (OpenSCAP/Lynis/политика);
  credential            — подобран пароль (аудит учёток);
  inventory             — сведения инвентаризации (порт, ОС, сводки).

Уверенность (confidence): high — подтверждено на хосте или вендором;
medium — аутентифицированная проверка без данных вендора, шаблон Nuclei;
low — только баннер.
"""
from __future__ import annotations

from collections.abc import Iterable, Mapping

from scanner.core.models import Finding, FindingType

SOURCES = ("authenticated_package", "vendor_advisory", "banner", "nuclei", "config",
           "credential", "inventory")
LEVELS = ("high", "medium", "low")

SOURCE_LABELS = {
    "authenticated_package": "пакет на хосте (по учётной записи)",
    "vendor_advisory": "бюллетень вендора",
    "banner": "сетевой баннер",
    "nuclei": "шаблон Nuclei",
    "config": "аудит конфигурации",
    "credential": "проверка пароля",
    "inventory": "инвентаризация",
}
CONFIDENCE_LABELS = {"high": "подтверждено", "medium": "вероятно",
                     "low": "потенциально (не подтверждено)"}


def infer(f: Finding) -> tuple[str, str]:
    """(source, confidence) для находки без явной разметки (по модулю/типу)."""
    if f.source and f.confidence:
        return f.source, f.confidence
    if f.finding_type is FindingType.INFO:
        return f.source or "inventory", f.confidence or "high"
    if f.finding_type is FindingType.CONFIG:
        return f.source or "config", f.confidence or "high"
    if f.finding_type is FindingType.CRED:
        return f.source or "credential", f.confidence or "high"
    m = f.module
    if m == "auth_inventory":
        return f.source or "authenticated_package", f.confidence or "medium"
    if m == "win_inventory":
        # MSRC: недостающее обновление по сборке ОС — данные вендора
        msrc = "MSRC" in (f.evidence or "") or (f.vuln_id or "").startswith("KB")
        return (f.source or ("vendor_advisory" if msrc else "authenticated_package"),
                f.confidence or ("high" if msrc else "medium"))
    if m == "vuln":
        return f.source or "nuclei", f.confidence or "medium"
    if m in ("config_audit", "password_policy"):
        return f.source or "config", f.confidence or "high"
    if m == "cred_audit":
        return f.source or "credential", f.confidence or "high"
    return f.source or "inventory", f.confidence or "medium"


def apply_confidence(findings: Iterable[Finding]) -> None:
    for f in findings:
        f.source, f.confidence = infer(f)


def supersede_banner(findings: list[Finding], assessed: Mapping[str, Mapping[str, str]]
                     ) -> tuple[list[Finding], list[Finding]]:
    """Находки «по баннеру» на хостах, где те же CVE уже проверены по пакетам
    (auth_inventory): точный результат главнее. Закрытые бюллетенем вендора
    (бэкпорт) или уже отражённые находкой по пакету — убираются.
    Возвращает (оставшиеся, убранные)."""
    keep, dropped = [], []
    for f in findings:
        if f.source == "banner" and f.finding_type is FindingType.VULN:
            checked = assessed.get(f.host) or {}
            cves = {c.upper() for c in (f.vuln_id, *f.cve_ids)
                    if c and c.upper().startswith("CVE-")}
            if cves and checked and cves <= set(checked):
                dropped.append(f)
                continue
        keep.append(f)
    return keep, dropped


def warnings_for(findings: Iterable[Finding], notes: Iterable[Mapping],
                 coverage=None) -> list[dict]:
    """Ограничения достоверности прогона для API, интерфейса и отчёта."""
    out = [dict(n) for n in notes]
    # одна запись на выпуск ОС: хосты перечисляются в ней
    merged: dict[tuple, dict] = {}
    rest = []
    for n in out:
        if n.get("kind") == "advisories_missing":
            key = (n.get("family"), n.get("release"))
            m = merged.get(key)
            if m is None:
                merged[key] = {**n, "hosts": [n.get("host")]}
            else:
                m["hosts"].append(n.get("host"))
        else:
            rest.append(n)
    out = rest + list(merged.values())
    for m in merged.values():
        hosts = [h for h in m["hosts"] if h]
        what = f"{m.get('family')}:{m.get('release')}" if m.get("release") else m.get("os")
        m["message"] = (f"Бэкпорты не учтены: нет бюллетеней {what} "
                        f"(хосты: {', '.join(hosts[:5])}"
                        + (f" и ещё {len(hosts) - 5}" if len(hosts) > 5 else "")
                        + "). Находки по пакетам определены по версии апстрима и могут "
                        "быть уже исправлены вендором — загрузите бюллетени и повторите "
                        "прогон.")
    banner = [f for f in findings if f.source == "banner"
              and f.finding_type is FindingType.VULN]
    if banner:
        hosts = sorted({f.host for f in banner})
        unconfirmed = hosts
        if coverage is not None:
            unconfirmed = [h for h in hosts if not coverage.covered(h, "auth_inventory")]
        out.append({"kind": "banner_only", "count": len(banner), "hosts": hosts,
                    "message": (f"{len(banner)} находок определены только по версии в "
                                "сетевом баннере (низкая уверенность): бэкпорты "
                                "дистрибутива не учтены"
                                + (f"; на хостах {', '.join(unconfirmed[:5])} нет проверки "
                                   "по учётной записи" if unconfirmed else "")
                                + ".")})
    return out
