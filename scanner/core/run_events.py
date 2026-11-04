"""Лента событий прогона (миграция 0024) для «Сводки».

Пишет сканер: начало и итог прогона, модули (начат / готов / ошибка / пропущен),
по хосту после сохранения находок — новые и вернувшиеся уязвимости, закрытые,
хост не проверен. События по хостам ограничены (MAX_HOST_EVENTS): на сотнях
хостов лента остаётся читаемой, остальное — одной строкой «ещё N хостов».

Лента вторична к прогону: ошибка записи события не должна его ронять, поэтому
RunService пишет события через safe_add в отдельной короткой транзакции.
"""
from __future__ import annotations

import logging
from collections import Counter, defaultdict
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field

from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from scanner.core.db import RunEventRow, session_scope
from scanner.core.models import Finding

log = logging.getLogger(__name__)

MAX_HOST_EVENTS = 30
MAX_REFS = 3
LIST_LIMIT_MAX = 200

SUBJECT_RUN = "Прогон"

MODULE_LABELS: dict[str, str] = {
    "discovery": "Обнаружение",
    "vuln": "Уязвимости ПО",
    "auth_inventory": "По учётной записи (Linux)",
    "win_inventory": "По учётной записи (Windows)",
    "config_audit": "Аудит конфигураций",
    "password_policy": "Парольная политика",
    "cred_audit": "Аудит учётных записей",
}

RUN_STATUS_TEXT: dict[str, str] = {
    "done": "завершён",
    "partial": "завершён частично",
    "stopped": "остановлен",
    "interrupted": "прерван",
    "failed": "завершился ошибкой",
}

_SEV_ORDER = ("critical", "high", "medium", "low", "info")
_SEV_GEN = {  # «3 критических»
    "critical": ("критическая", "критические", "критических"),
    "high": ("высокая", "высокие", "высоких"),
    "medium": ("средняя", "средние", "средних"),
    "low": ("низкая", "низкие", "низких"),
}


def plural(n: int, forms: tuple[str, str, str]) -> str:
    m10, m100 = n % 10, n % 100
    if m10 == 1 and m100 != 11:
        return forms[0]
    if 2 <= m10 <= 4 and not 12 <= m100 <= 14:
        return forms[1]
    return forms[2]


def module_label(name: str) -> str:
    return MODULE_LABELS.get(name, name)


def _inline(name: str) -> str:
    """Подпись модуля внутри фразы: «уязвимости ПО» (аббревиатуры не трогаем)."""
    label = module_label(name)
    return label[:1].lower() + label[1:]


@dataclass(slots=True)
class Event:
    kind: str
    subject: str
    message: str
    host: str | None = None
    severity: str | None = None
    details: dict | None = field(default=None)


def add(session: Session, scan_run_id: int, ev: Event) -> None:
    session.add(RunEventRow(scan_run_id=scan_run_id, kind=ev.kind, subject=ev.subject,
                            host=ev.host, severity=ev.severity,
                            message=ev.message[:1000], details=ev.details))


def safe_add(sessions: sessionmaker[Session], scan_run_id: int,
             events: Iterable[Event]) -> None:
    """Записывает события; ошибка (нет таблицы, БД недоступна) — только в лог."""
    events = list(events)
    if not events:
        return
    try:
        with session_scope(sessions) as s:
            for ev in events:
                add(s, scan_run_id, ev)
    except Exception:  # noqa: BLE001 — лента вторична к прогону
        log.exception("scan_run %s: cannot write run events", scan_run_id)


def recorder(sessions: sessionmaker[Session], scan_run_id: int) -> Callable[[Event], None]:
    return lambda ev: safe_add(sessions, scan_run_id, [ev])


def list_events(session: Session, scan_run_id: int, limit: int = 50) -> list[RunEventRow]:
    """События прогона, новые сверху."""
    limit = max(1, min(int(limit), LIST_LIMIT_MAX))
    return list(session.scalars(
        select(RunEventRow).where(RunEventRow.scan_run_id == scan_run_id)
        .order_by(RunEventRow.id.desc()).limit(limit)))


# ---------- события модулей и прогона ----------
def module_start(name: str, targets: int) -> Event:
    return Event("module_start", module_label(name),
                 f"начат: {targets} {plural(targets, ('цель', 'цели', 'целей'))}")


def module_finish(name: str, findings: int) -> Event:
    what = (f"готов: {findings} {plural(findings, ('находка', 'находки', 'находок'))}"
            if findings else "готов, находок нет")
    return Event("module_finish", module_label(name), what)


def module_error(name: str, error: str) -> Event:
    return Event("module_error", module_label(name), f"ошибка: {error}"[:500])


def module_skip(name: str) -> Event:
    return Event("module_skip", module_label(name), "пропущен: прогон остановлен")


def run_start(targets: int, modules: Iterable[str]) -> Event:
    mods = ", ".join(_inline(m) for m in modules)
    return Event("run_start", SUBJECT_RUN,
                 f"начат: {targets} {plural(targets, ('цель', 'цели', 'целей'))}"
                 + (f"; модули: {mods}" if mods else ""))


def run_finish(status: str, *, open_issues: int | None = None, new: int = 0,
               fixed: int = 0, message: str | None = None) -> Event:
    parts = [RUN_STATUS_TEXT.get(status, status)]
    if open_issues is not None and status in ("done", "partial"):
        parts.append(f"открытых {open_issues}")
        if new:
            parts.append(f"новых {new}")
        if fixed:
            parts.append(f"закрыто {fixed}")
    text = ", ".join(parts)
    if message and status not in ("done",):
        text += f". {message}"
    return Event("run_finish", SUBJECT_RUN, text[:1000])


# ---------- события по хостам ----------
def _refs(findings: list[Finding]) -> list[str]:
    out: list[str] = []
    for f in sorted(findings, key=lambda x: _SEV_ORDER.index(str(x.severity))):
        for ref in [*f.cve_ids, *f.bdu_ids] or [f.title]:
            if ref and ref not in out:
                out.append(ref)
            if len(out) >= MAX_REFS:
                return out
    return out


def _top(findings: list[Finding]) -> str:
    return min((str(f.severity) for f in findings), key=_SEV_ORDER.index)


def _sev_text(findings: list[Finding]) -> str:
    c = Counter(str(f.severity) for f in findings)
    parts = [f"{c[s]} {plural(c[s], _SEV_GEN[s])}" for s in ("critical", "high") if c[s]]
    rest = len(findings) - c["critical"] - c["high"]
    if rest:
        parts.append(f"{rest} {plural(rest, ('прочая', 'прочие', 'прочих'))}" if parts
                     else f"{rest}")
    return ", ".join(parts)


def host_events(findings: Iterable[Finding], statuses: Mapping[str, str],
                fixed: Iterable[Finding] = (), gaps: Iterable[tuple[str, str, str]] = (),
                *, false_positive_keys: set[str] | frozenset[str] = frozenset(),
                hostnames: Mapping[str, str] | None = None,
                limit: int = MAX_HOST_EVENTS) -> list[Event]:
    """События по хостам после прогона, самые важные первыми.

    statuses — {dedup_key: new|regression|open}; fixed — исчезнувшие находки
    базы; gaps — (хост, модуль, причина) непроверенного. Информационные находки
    и ложные срабатывания не учитываются."""
    names = hostnames or {}

    def who(host: str) -> str:
        return names.get(host) or host

    def live(f: Finding) -> bool:
        return str(f.severity) != "info" and f.dedup_key() not in false_positive_keys

    new: dict[str, list[Finding]] = defaultdict(list)
    regr: dict[str, list[Finding]] = defaultdict(list)
    for f in findings:
        if not live(f):
            continue
        st = statuses.get(f.dedup_key())
        if st == "new":
            new[str(f.host)].append(f)
        elif st == "regression":
            regr[str(f.host)].append(f)
    gone: dict[str, list[Finding]] = defaultdict(list)
    for f in fixed:
        if live(f):
            gone[str(f.host)].append(f)

    ranked: list[tuple[tuple, Event]] = []
    for host, fs in regr.items():
        top = _top(fs)
        ranked.append(((0, _SEV_ORDER.index(top), -len(fs)), Event(
            "host_regression", who(host), host=host, severity=top,
            message=f"вернулись после исправления: {len(fs)} · " + ", ".join(_refs(fs)))))
    for host, fs in new.items():
        top = _top(fs)
        ranked.append(((1, _SEV_ORDER.index(top), -len(fs)), Event(
            "host_new", who(host), host=host, severity=top,
            message=f"новых уязвимостей: {_sev_text(fs)} · " + ", ".join(_refs(fs)))))
    # по хосту одна строка на причину: «хост недоступен» не дублируется по модулям
    holes: dict[tuple[str, str], list[str]] = defaultdict(list)
    for host, mod, reason in gaps:
        mods = holes[(str(host), reason)]
        if _inline(mod) not in mods:
            mods.append(_inline(mod))
    for (host, reason), mods in holes.items():
        ranked.append(((2, 0, -len(mods)), Event(
            "host_gap", who(host), host=host,
            message=f"не проверен: {reason} ({', '.join(mods)})")))
    for host, fs in gone.items():
        ranked.append(((3, _SEV_ORDER.index(_top(fs)), -len(fs)), Event(
            "host_fixed", who(host), host=host, severity="ok",
            message=f"закрыто {len(fs)} · " + ", ".join(_refs(fs)))))
    ranked.sort(key=lambda x: x[0])
    out = [ev for _, ev in ranked[:limit]]
    if len(ranked) > limit:
        rest = len(ranked) - limit
        out.append(Event("hosts_more", SUBJECT_RUN,
                         f"ещё {rest} {plural(rest, ('событие', 'события', 'событий'))} "
                         "по хостам — подробности в «Находках» и «Активах»"))
    # в ленте новые сверху: самое важное пишем последним
    return list(reversed(out))
