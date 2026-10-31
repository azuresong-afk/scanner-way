"""Хранение соответствия (R5): факты и результаты прогона, профили договора."""
from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any

from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from scanner.compliance.catalog import Catalog, Profile, default_catalog
from scanner.compliance.engine import ResultRow, Selection, evaluate_run, summarize
from scanner.core.db import (
    ComplianceFactsRow,
    ComplianceProfileRow,
    ComplianceResultRow,
)


def save_run(session: Session, scan_run_id: int, facts: Mapping[str, Mapping[str, Any]],
             rows: Iterable[ResultRow]) -> int:
    """Заменить факты и результаты прогона. Возвращает число строк результатов."""
    session.execute(delete(ComplianceFactsRow).where(
        ComplianceFactsRow.scan_run_id == scan_run_id))
    session.execute(delete(ComplianceResultRow).where(
        ComplianceResultRow.scan_run_id == scan_run_id))
    for host, f in facts.items():
        session.add(ComplianceFactsRow(scan_run_id=scan_run_id, host=host, facts=dict(f)))
    n = 0
    for r in rows:
        session.add(ComplianceResultRow(scan_run_id=scan_run_id, profile=r.profile,
                                        host=r.host, control=r.control, status=r.status,
                                        evidence=r.evidence))
        n += 1
    session.flush()
    return n


def load_facts(session: Session, scan_run_id: int) -> dict[str, dict]:
    rows = session.scalars(select(ComplianceFactsRow).where(
        ComplianceFactsRow.scan_run_id == scan_run_id))
    return {str(r.host).split("/")[0]: dict(r.facts or {}) for r in rows}


def load_rows(session: Session, scan_run_id: int, profile: str | None = None
              ) -> list[ResultRow]:
    q = select(ComplianceResultRow).where(ComplianceResultRow.scan_run_id == scan_run_id)
    if profile is not None:
        q = q.where(ComplianceResultRow.profile == profile)
    return [ResultRow(r.profile, str(r.host).split("/")[0] if r.host else None, r.control,
                      r.status, dict(r.evidence or {}))
            for r in session.scalars(q.order_by(ComplianceResultRow.id))]


def has_results(session: Session, scan_run_id: int) -> bool:
    return session.scalar(select(ComplianceResultRow.id).where(
        ComplianceResultRow.scan_run_id == scan_run_id).limit(1)) is not None


def recompute(session: Session, scan_run_id: int, catalog: Catalog | None = None) -> int:
    """Пересчитать результаты по сохранённым фактам и находкам (после обновления
    профилей). Прогон до миграции 0015 фактов не имеет — результат будет пустым."""
    from scanner.core import repository as repo
    facts = load_facts(session, scan_run_id)
    rows = evaluate_run(catalog or default_catalog(), facts,
                        repo.get_findings(session, scan_run_id),
                        repo.get_services(session, scan_run_id))
    return save_run(session, scan_run_id, facts, rows)


# ---------- профили договора ----------

def list_profiles(session: Session, engagement_id: int) -> list[ComplianceProfileRow]:
    return list(session.scalars(select(ComplianceProfileRow).where(
        ComplianceProfileRow.engagement_id == engagement_id).order_by(
        ComplianceProfileRow.id)))


def get_profile_row(session: Session, engagement_id: int, profile: str
                    ) -> ComplianceProfileRow | None:
    return session.scalar(select(ComplianceProfileRow).where(
        ComplianceProfileRow.engagement_id == engagement_id,
        ComplianceProfileRow.profile == profile))


def validate_selection(profile: Profile, level: str | None, excluded: Iterable[str],
                       added: Iterable[str]) -> tuple[str | None, list[str], list[str]]:
    """Проверить уровень и меры адаптации; ValueError — понятная причина (422)."""
    if profile.levels:
        level = level or profile.default_level
        if level not in profile.levels:
            raise ValueError(f"{profile.level_label}: допустимо {', '.join(profile.levels)}")
    else:
        level = None
    exc, add = sorted(set(excluded)), sorted(set(added))
    unknown = [c for c in [*exc, *add] if profile.control(c) is None]
    if unknown and not profile.dynamic:
        raise ValueError(f"нет таких мер в профиле: {', '.join(unknown)}")
    return level, exc, add


def upsert_profile(session: Session, engagement_id: int, profile: Profile, *,
                   level: str | None, excluded: Iterable[str] = (),
                   added: Iterable[str] = (), in_report: bool = True,
                   user_id: int | None = None) -> ComplianceProfileRow:
    level, exc, add = validate_selection(profile, level, excluded, added)
    row = get_profile_row(session, engagement_id, profile.id)
    if row is None:
        row = ComplianceProfileRow(engagement_id=engagement_id, profile=profile.id)
        session.add(row)
    row.level, row.excluded, row.added = level, exc, add
    row.in_report, row.updated_by = in_report, user_id
    session.flush()
    return row


def selection_of(row: ComplianceProfileRow | None, profile: Profile,
                 level: str | None = None) -> Selection:
    """Выбор мер: из профиля договора; level — явный уровень (переопределяет)."""
    if row is None:
        return Selection(level=level or profile.default_level)
    return Selection(level=level or row.level or profile.default_level,
                     excluded=frozenset(row.excluded or ()),
                     added=frozenset(row.added or ()))


def run_summary(session: Session, scan_run_id: int, engagement_id: int, profile: Profile,
                *, catalog: Catalog | None = None, level: str | None = None,
                hosts: Iterable[str] | None = None,
                false_positives: Iterable[str] | None = None) -> dict:
    """Сводка соответствия прогона профилю с учётом настроек договора, отметок
    «ложное срабатывание» и групп активов (R7)."""
    from scanner.core import assets as asset_svc
    from scanner.core import repository as repo
    catalog = catalog or default_catalog()
    sel = selection_of(get_profile_row(session, engagement_id, profile.id), profile, level)
    fp = (set(false_positives) if false_positives is not None
          else set(repo.false_positive_marks(session, engagement_id)))
    groups = {g["name"]: asset_svc.group_hosts(session, g["id"])
              for g in asset_svc.group_views(session, engagement_id)}
    out = summarize(profile, catalog, load_rows(session, scan_run_id, profile.id),
                    selection=sel, false_positives=fp,
                    hosts=set(hosts) if hosts is not None else None, groups=groups)
    out["run_id"] = scan_run_id
    return out
