"""Текст сообщений для почты и Telegram (тело — сводка и ссылка, без секретов)."""
from __future__ import annotations

from scanner.integrations.events import (
    EVENT_TITLES,
    FEED_STALE,
    NEW_CRITICAL,
    RUN_FINISHED,
    SEVERITIES,
    STATUS_TITLES,
    Event,
    Item,
)

SEVERITY_RU = {"critical": "критических", "high": "высоких", "medium": "средних",
               "low": "низких", "info": "информационных"}
PRIORITY_RU = {"critical": "критический", "high": "высокий", "medium": "средний",
               "low": "низкий"}
SEVERITY_ONE = {"critical": "критическая", "high": "высокая", "medium": "средняя",
                "low": "низкая", "info": "информационная"}


def _clean(text: str, limit: int = 200) -> str:
    t = " ".join(str(text).split())
    return t if len(t) <= limit else t[: limit - 1] + "…"


def item_line(i: Item) -> str:
    where = f"{i.host}:{i.port}" if i.port else i.host
    tail = [SEVERITY_ONE.get(i.severity, i.severity)]
    if i.priority:
        tail.append(f"приоритет: {PRIORITY_RU.get(i.priority, i.priority)}")
    if i.in_kev:
        tail.append("в CISA KEV")
    ids = ", ".join(([i.vuln_id] if i.vuln_id else []) + [b for b in i.bdu_ids
                                                          if b != i.vuln_id][:2])
    head = f"{where} — {_clean(i.title, 120)}"
    return f"{head} ({'; '.join(tail)}{'; ' + ids if ids else ''})"


def subject_of(ev: Event) -> str:
    eng = f" · {ev.engagement_name}" if ev.engagement_name else ""
    if ev.kind == RUN_FINISHED:
        what = ev.run_name or f"прогон №{ev.scan_run_id}"
        return f"{what}: {STATUS_TITLES.get(ev.run_status or '', 'завершён')}{eng}"
    if ev.kind == NEW_CRITICAL:
        return f"Новых критичных находок: {len(ev.items) + ev.items_omitted}{eng}"
    return _clean(ev.title, 150)


def render_text(ev: Event) -> tuple[str, str]:
    """(тема, тело) — обычный текст."""
    lines: list[str] = [EVENT_TITLES.get(ev.kind, ev.title)]
    if ev.kind == FEED_STALE:
        lines.append(f"Справочник: {ev.title}")
        if ev.message:
            lines.append(_clean(ev.message, 500))
    elif ev.kind in (RUN_FINISHED, NEW_CRITICAL):
        if ev.engagement_name:
            lines.append(f"Договор: {ev.engagement_name}")
        if ev.run_name or ev.scan_run_id:
            status = (f" ({STATUS_TITLES.get(ev.run_status or '', ev.run_status)})"
                      if ev.run_status else "")
            lines.append(f"Прогон: {ev.run_name or '№' + str(ev.scan_run_id)}{status}")
        if ev.kind == RUN_FINISHED:
            c = ev.counts
            total = sum(c.values())
            if total:
                parts = ", ".join(f"{SEVERITY_RU[s]}: {c[s]}" for s in reversed(SEVERITIES)
                                  if c.get(s))
                lines.append(f"Хостов: {ev.hosts_total}; находок: {total} — {parts}")
            else:
                lines.append(f"Хостов: {ev.hosts_total}; находок нет")
            lines.append(f"Новых: {ev.new_total}"
                         + (f"; устранено: {ev.fixed_total}" if ev.fixed_total is not None
                            else ""))
        shown = ev.top_items() if ev.kind == RUN_FINISHED else ev.items[:15]
        if shown:
            lines.append("")
            lines.append("Первыми стоит разобрать:" if ev.kind == RUN_FINISHED
                         else "Новые критичные находки:")
            lines += [f"• {item_line(i)}" for i in shown]
            rest = len(ev.items) + ev.items_omitted - len(shown)
            if rest > 0 and ev.kind == NEW_CRITICAL:
                lines.append(f"… и ещё {rest}")
    elif ev.message:
        lines.append(ev.message)
    if ev.link:
        lines += ["", f"Отчёт: {ev.link}"]
    return "[Scanner] " + subject_of(ev), "\n".join(lines)
