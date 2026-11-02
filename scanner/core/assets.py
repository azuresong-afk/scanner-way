"""Управление активами договора: теги, группы, владельцы, критичность.

Актив — запись об хосте договора (адрес уникален в договоре). Реестр ничего не
сканирует и на allowlist не влияет: это справочник для отчётов по группам и
приоритизации (критичность — вход R6). При чтении актив дополняется данными
последних прогонов: ОС и число открытых находок по уровням опасности.
"""
from __future__ import annotations

import ipaddress
from collections import defaultdict
from collections.abc import Iterable, Sequence

from sqlalchemy import delete, func, insert, select
from sqlalchemy.orm import Session

from scanner.core import repository as repo
from scanner.core.db import (
    AssetGroupRow,
    AssetRow,
    FindingRow,
    asset_group_members,
    asset_tags,
)

# Порядок важен: больший индекс — выше критичность (сравнивает R6).
CRITICALITY: tuple[str, ...] = ("low", "medium", "high", "critical")
CRITICALITY_LABEL = {"low": "Низкая", "medium": "Средняя", "high": "Высокая",
                     "critical": "Критическая"}
DEFAULT_CRITICALITY = "medium"
MAX_TAGS = 20
MAX_TAG_LEN = 40


class AssetError(ValueError):
    """Ошибка в данных актива (адрес, тег, критичность)."""


class DuplicateError(AssetError):
    """Актив с таким адресом (или группа с таким именем) уже есть в договоре."""


def criticality_rank(value: str | None) -> int:
    return CRITICALITY.index(value) if value in CRITICALITY else CRITICALITY.index(
        DEFAULT_CRITICALITY)


def normalize_address(raw: str) -> str:
    try:
        return str(ipaddress.ip_address(raw.strip().split("/")[0]))
    except ValueError as e:
        raise AssetError(f"некорректный адрес: {raw!r}") from e


def normalize_tags(tags: Iterable[str]) -> list[str]:
    """Теги без пробелов по краям, в нижнем регистре, без повторов; порядок сохранён."""
    out: list[str] = []
    for t in tags:
        t = " ".join(str(t).split()).lower()
        if not t:
            continue
        if len(t) > MAX_TAG_LEN:
            raise AssetError(f"тег длиннее {MAX_TAG_LEN} символов: {t[:20]}…")
        if t not in out:
            out.append(t)
    if len(out) > MAX_TAGS:
        raise AssetError(f"у актива не больше {MAX_TAGS} тегов")
    return out


def check_criticality(value: str) -> str:
    if value not in CRITICALITY:
        raise AssetError(f"критичность: одно из {', '.join(CRITICALITY)}")
    return value


def _clean(text: str | None) -> str | None:
    text = (text or "").strip()
    return text or None


def host_key(host: object) -> str:
    return str(ipaddress.ip_address(str(host).split("/")[0]))


# ---- чтение ------------------------------------------------------------

def _tags_map(session: Session, asset_ids: Sequence[int]) -> dict[int, list[str]]:
    out: dict[int, list[str]] = defaultdict(list)
    if asset_ids:
        for aid, tag in session.execute(
                select(asset_tags.c.asset_id, asset_tags.c.tag)
                .where(asset_tags.c.asset_id.in_(asset_ids)).order_by(asset_tags.c.tag)):
            out[aid].append(tag)
    return out


def _groups_map(session: Session, asset_ids: Sequence[int]) -> dict[int, list[dict]]:
    out: dict[int, list[dict]] = defaultdict(list)
    if asset_ids:
        for aid, gid, name in session.execute(
                select(asset_group_members.c.asset_id, AssetGroupRow.id, AssetGroupRow.name)
                .join(AssetGroupRow, AssetGroupRow.id == asset_group_members.c.group_id)
                .where(asset_group_members.c.asset_id.in_(asset_ids))
                .order_by(AssetGroupRow.name)):
            out[aid].append({"id": gid, "name": name})
    return out


def _finding_counts(session: Session, engagement_id: int,
                    hosts: dict[str, dict]) -> dict[str, dict[str, int]]:
    """Открытые находки хоста в последнем прогоне, где он встречался
    (без отмеченных ложными срабатываниями)."""
    wanted: dict[int, set[str]] = defaultdict(set)
    for key, info in hosts.items():
        if info["run_ids"]:
            wanted[max(info["run_ids"])].add(key)
    marks = set(repo.false_positive_marks(session, engagement_id))
    counts: dict[str, dict[str, int]] = {}
    for run_id, keys in wanted.items():
        for host, severity, dedup in session.execute(
                select(FindingRow.host, FindingRow.severity, FindingRow.dedup_key)
                .where(FindingRow.scan_run_id == run_id)):
            h = host_key(host)
            if h in keys and dedup not in marks:
                c = counts.setdefault(h, {})
                c[severity] = c.get(severity, 0) + 1
    return counts


def asset_views(session: Session, engagement_id: int, rows: Sequence[AssetRow]
                ) -> list[dict]:
    """Активы с тегами, группами и данными последних прогонов (ОС, находки)."""
    ids = [r.id for r in rows]
    tags, groups = _tags_map(session, ids), _groups_map(session, ids)
    inv = {h["host"]: h for h in repo.engagement_hosts(session, engagement_id)}
    counts = _finding_counts(session, engagement_id, inv)
    out = []
    for r in rows:
        addr = host_key(r.address)
        h = inv.get(addr)
        c = counts.get(addr, {})
        out.append({
            "id": r.id, "engagement_id": r.engagement_id, "address": addr,
            "hostname": r.hostname, "owner": r.owner, "criticality": r.criticality,
            "notes": r.notes, "tags": tags.get(r.id, []),
            "groups": groups.get(r.id, []), "created_at": r.created_at,
            "os_guess": h["os_guess"] if h else None,
            "os_family": h["os_family"] if h else None,
            "os_family_label": h["os_family_label"] if h else None,
            "last_run_id": max(h["run_ids"]) if h and h["run_ids"] else None,
            "finding_counts": c, "findings_total": sum(c.values()),
        })
    return out


def list_assets(session: Session, engagement_id: int, *, tag: str | None = None,
                group_id: int | None = None, criticality: str | None = None,
                owner: str | None = None, q: str | None = None) -> list[AssetRow]:
    stmt = select(AssetRow).where(AssetRow.engagement_id == engagement_id)
    if tag:
        stmt = stmt.where(AssetRow.id.in_(
            select(asset_tags.c.asset_id).where(asset_tags.c.tag == tag.strip().lower())))
    if group_id is not None:
        stmt = stmt.where(AssetRow.id.in_(
            select(asset_group_members.c.asset_id)
            .where(asset_group_members.c.group_id == group_id)))
    if criticality:
        stmt = stmt.where(AssetRow.criticality == criticality)
    rows = list(session.scalars(stmt))
    if owner:   # регистр сравниваем в Python: lower() СУБД не гарантирует кириллицу
        rows = [r for r in rows if (r.owner or "").strip().lower() == owner.strip().lower()]
    if q and q.strip():
        needle = q.strip().lower()
        rows = [r for r in rows if needle in " ".join(
            filter(None, [host_key(r.address), r.hostname, r.owner, r.notes])).lower()]
    return sorted(rows, key=lambda r: (ipaddress.ip_address(host_key(r.address)).version,
                                       int(ipaddress.ip_address(host_key(r.address)))))


def tag_counts(session: Session, engagement_id: int) -> list[tuple[str, int]]:
    return [(t, n) for t, n in session.execute(
        select(asset_tags.c.tag, func.count())
        .join(AssetRow, AssetRow.id == asset_tags.c.asset_id)
        .where(AssetRow.engagement_id == engagement_id)
        .group_by(asset_tags.c.tag).order_by(asset_tags.c.tag))]


# ---- запись ------------------------------------------------------------

def get_asset(session: Session, engagement_id: int, asset_id: int) -> AssetRow | None:
    row = session.get(AssetRow, asset_id)
    return row if row is not None and row.engagement_id == engagement_id else None


def _find_by_address(session: Session, engagement_id: int, address: str) -> AssetRow | None:
    for r in session.scalars(select(AssetRow).where(AssetRow.engagement_id == engagement_id)):
        if host_key(r.address) == address:
            return r
    return None


def set_tags(session: Session, asset_id: int, tags: Iterable[str]) -> None:
    session.execute(delete(asset_tags).where(asset_tags.c.asset_id == asset_id))
    tags = normalize_tags(tags)
    if tags:
        session.execute(insert(asset_tags), [{"asset_id": asset_id, "tag": t} for t in tags])


def set_groups(session: Session, engagement_id: int, asset_id: int,
               group_ids: Iterable[int]) -> None:
    ids = sorted(set(group_ids))
    valid = set(session.scalars(select(AssetGroupRow.id).where(
        AssetGroupRow.engagement_id == engagement_id, AssetGroupRow.id.in_(ids)))) if ids else set()
    if set(ids) - valid:
        raise AssetError(f"группа не найдена в этом договоре: {sorted(set(ids) - valid)}")
    session.execute(delete(asset_group_members)
                    .where(asset_group_members.c.asset_id == asset_id))
    if ids:
        session.execute(insert(asset_group_members),
                        [{"asset_id": asset_id, "group_id": g} for g in ids])


def create_asset(session: Session, engagement_id: int, *, address: str,
                 hostname: str | None = None, owner: str | None = None,
                 criticality: str = DEFAULT_CRITICALITY, notes: str | None = None,
                 tags: Iterable[str] = (), group_ids: Iterable[int] = (),
                 created_by: int | None = None) -> AssetRow:
    address = normalize_address(address)
    check_criticality(criticality)
    tags = normalize_tags(tags)
    if _find_by_address(session, engagement_id, address) is not None:
        raise DuplicateError(f"актив {address} уже есть в договоре")
    row = AssetRow(engagement_id=engagement_id, address=address, hostname=_clean(hostname),
                   owner=_clean(owner), criticality=criticality, notes=_clean(notes),
                   created_by=created_by)
    session.add(row)
    session.flush()
    set_tags(session, row.id, tags)
    set_groups(session, engagement_id, row.id, group_ids)
    session.flush()
    return row


def update_asset(session: Session, row: AssetRow, changes: dict) -> AssetRow:
    """Частичная правка; ключи — только те, что переданы клиентом."""
    if "address" in changes:
        address = normalize_address(changes["address"])
        other = _find_by_address(session, row.engagement_id, address)
        if other is not None and other.id != row.id:
            raise DuplicateError(f"актив {address} уже есть в договоре")
        row.address = address
    if "criticality" in changes:
        row.criticality = check_criticality(changes["criticality"])
    for f in ("hostname", "owner", "notes"):
        if f in changes:
            setattr(row, f, _clean(changes[f]))
    if "tags" in changes:
        set_tags(session, row.id, changes["tags"])
    if "group_ids" in changes:
        set_groups(session, row.engagement_id, row.id, changes["group_ids"])
    session.flush()
    return row


def bulk_update(session: Session, engagement_id: int, rows: Sequence[AssetRow], *,
                add_tags: Iterable[str] = (), remove_tags: Iterable[str] = (),
                add_group_ids: Iterable[int] = (), remove_group_ids: Iterable[int] = (),
                criticality: str | None = None, owner: str | None = None) -> None:
    add_t, rem_t = normalize_tags(add_tags), set(normalize_tags(remove_tags))
    add_g, rem_g = set(add_group_ids), set(remove_group_ids)
    if criticality is not None:
        check_criticality(criticality)
    valid = set(session.scalars(select(AssetGroupRow.id).where(
        AssetGroupRow.engagement_id == engagement_id,
        AssetGroupRow.id.in_(add_g | rem_g)))) if add_g | rem_g else set()
    if (add_g | rem_g) - valid:
        raise AssetError(f"группа не найдена в этом договоре: {sorted((add_g | rem_g) - valid)}")
    for row in rows:
        have_t = set(_tags_map(session, [row.id]).get(row.id, []))
        new_t = [t for t in [*sorted(have_t), *add_t] if t not in rem_t]
        if new_t != sorted(have_t):
            set_tags(session, row.id, new_t)
        have_g = set(session.scalars(select(asset_group_members.c.group_id)
                                     .where(asset_group_members.c.asset_id == row.id)))
        new_g = (have_g | add_g) - rem_g
        if new_g != have_g:
            set_groups(session, engagement_id, row.id, new_g)
        if criticality is not None:
            row.criticality = criticality
        if owner is not None:
            row.owner = _clean(owner)
    session.flush()


def delete_asset(session: Session, row: AssetRow) -> None:
    session.delete(row)
    session.flush()


def import_discovered(session: Session, engagement_id: int,
                      created_by: int | None = None) -> list[AssetRow]:
    """Создать активы для хостов инвентаря договора, которых ещё нет в реестре."""
    known = {host_key(r.address) for r in session.scalars(
        select(AssetRow).where(AssetRow.engagement_id == engagement_id))}
    created = []
    for h in repo.engagement_hosts(session, engagement_id):
        if h["host"] not in known:
            created.append(create_asset(session, engagement_id, address=h["host"],
                                        created_by=created_by))
    return created


# ---- группы ------------------------------------------------------------

def group_views(session: Session, engagement_id: int) -> list[dict]:
    counts = dict(session.execute(
        select(asset_group_members.c.group_id, func.count())
        .join(AssetGroupRow, AssetGroupRow.id == asset_group_members.c.group_id)
        .where(AssetGroupRow.engagement_id == engagement_id)
        .group_by(asset_group_members.c.group_id)).all())
    return [{"id": g.id, "engagement_id": g.engagement_id, "name": g.name,
             "asset_count": counts.get(g.id, 0), "created_at": g.created_at}
            for g in session.scalars(select(AssetGroupRow)
                                     .where(AssetGroupRow.engagement_id == engagement_id)
                                     .order_by(AssetGroupRow.name))]


def get_group(session: Session, engagement_id: int, group_id: int) -> AssetGroupRow | None:
    g = session.get(AssetGroupRow, group_id)
    return g if g is not None and g.engagement_id == engagement_id else None


def _group_name_taken(session: Session, engagement_id: int, name: str,
                      except_id: int | None = None) -> bool:
    return any(g.id != except_id and g.name.lower() == name.lower()
               for g in session.scalars(select(AssetGroupRow).where(
                   AssetGroupRow.engagement_id == engagement_id)))


def create_group(session: Session, engagement_id: int, name: str) -> AssetGroupRow:
    name = " ".join(name.split())
    if not name:
        raise AssetError("имя группы не может быть пустым")
    if _group_name_taken(session, engagement_id, name):
        raise DuplicateError(f"группа «{name}» уже есть в договоре")
    g = AssetGroupRow(engagement_id=engagement_id, name=name)
    session.add(g)
    session.flush()
    return g


def rename_group(session: Session, group: AssetGroupRow, name: str) -> AssetGroupRow:
    name = " ".join(name.split())
    if not name:
        raise AssetError("имя группы не может быть пустым")
    if _group_name_taken(session, group.engagement_id, name, except_id=group.id):
        raise DuplicateError(f"группа «{name}» уже есть в договоре")
    group.name = name
    session.flush()
    return group


def group_hosts(session: Session, group_id: int) -> set[str]:
    """Адреса активов группы — для фильтра отчёта."""
    return {host_key(a) for a in session.scalars(
        select(AssetRow.address).join(asset_group_members,
                                      asset_group_members.c.asset_id == AssetRow.id)
        .where(asset_group_members.c.group_id == group_id))}
