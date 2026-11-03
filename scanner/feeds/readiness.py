"""Готовность справочников — для мастера первоначальной настройки.

По каждому источнику: есть ли данные (сколько записей), идёт ли загрузка,
чем закончилась последняя попытка и что сделать оператору. Отдельно —
выпуски ОС, встреченные на хостах в прогонах, для которых нет бюллетеней
(«Бэкпорты не учтены»): их можно загрузить одним действием.
"""
from __future__ import annotations

from datetime import UTC, datetime, timedelta

from sqlalchemy import func, select, text
from sqlalchemy.orm import Session

from scanner.core.db import DistroAdvisoryRow, FeedSync, ScanRun

READY, MISSING, RUNNING, ERROR, STALE = "ready", "missing", "running", "error", "stale"

# Что даёт источник и насколько он нужен (для текста мастера).
PURPOSE = {
    "bdu": ("БДУ ФСТЭК — привязка находок к БДУ (главная функция отчёта)", True),
    "nvd": ("NVD — CVE, CVSS и сопоставление версий ПО", True),
    "advisories": ("Бюллетени дистрибутивов — учёт бэкпортов (без них возможны ложные "
                   "срабатывания по пакетам)", True),
    "nuclei": ("Шаблоны Nuclei — сетевые проверки", True),
    "epss": ("EPSS — вероятность эксплуатации для приоритизации", False),
    "kev": ("CISA KEV — эксплуатируемые уязвимости для приоритизации", False),
    "msrc": ("MSRC — обновления Microsoft для аудита Windows", False),
}

HINTS = {
    "bdu": ("Загрузите файл vullist.xlsx с bdu.fstec.ru кнопкой «Загрузить файл БДУ» "
            "или положите его в ./data (BDU_FSTEC_FEED_PATH), либо задайте "
            "BDU_FSTEC_FEED_URL и нажмите «Обновить сейчас»."),
    "nvd": ("Нажмите «Обновить сейчас». Первая полная загрузка без ключа API занимает "
            "несколько часов — задайте NVD_API_KEY (бесплатный ключ NVD), тогда "
            "примерно в 10 раз быстрее."),
    "advisories": ("Загрузите бюллетени выпусков ОС ваших хостов (кнопка у выпуска) или "
                   "включите автообновление — тогда сканер подгрузит их сам при первом "
                   "прогоне по хосту."),
    "nuclei": "Нажмите «Обновить сейчас» (nuclei -update-templates, нужен интернет).",
    "epss": "Нажмите «Обновить сейчас» (CSV FIRST EPSS, ~10 МБ).",
    "kev": "Нажмите «Обновить сейчас» (каталог CISA KEV, JSON).",
    "msrc": "Нужен для Windows: нажмите «Обновить сейчас» (бюллетени MSRC за последние месяцы).",
}


def _count(session: Session, table: str) -> int | None:
    try:
        return int(session.execute(text(f"SELECT count(*) FROM {table}")).scalar() or 0)
    except Exception:  # noqa: BLE001 — таблицы нет (старая схема/SQLite в тестах)
        session.rollback()
        return None


def record_counts(session: Session) -> dict[str, int | None]:
    from scanner.feeds.sources import count_templates, nuclei_templates_dir
    return {
        "bdu": _count(session, "reference_bdu_entry"),
        "nvd": _count(session, "reference_nvd_cve"),
        "advisories": _count(session, "distro_advisory"),
        "epss": _count(session, "epss_score"),
        "kev": _count(session, "kev"),
        "msrc": _count(session, "reference_msrc_fix"),
        "nuclei": count_templates(nuclei_templates_dir()),
    }


def loaded_releases(session: Session) -> list[dict]:
    rows = session.execute(
        select(DistroAdvisoryRow.family, DistroAdvisoryRow.release, func.count(),
               func.max(DistroAdvisoryRow.loaded_at))
        .group_by(DistroAdvisoryRow.family, DistroAdvisoryRow.release)).all()
    return [{"family": f, "release": r, "records": int(n),
             "loaded_at": t.isoformat() if t else None} for f, r, n, t in rows]


def missing_releases(session: Session, *, lookback: int = 200) -> list[dict]:
    """Выпуски ОС с хостов последних прогонов без бюллетеней (по warnings прогонов)."""
    have = {(r["family"], r["release"]) for r in loaded_releases(session)}
    out: dict[tuple[str, str], dict] = {}
    runs = session.scalars(select(ScanRun).where(ScanRun.status.in_(("done", "partial")))
                           .order_by(ScanRun.id.desc()).limit(lookback))
    for run in runs:
        for w in run.warnings or []:
            if w.get("kind") != "advisories_missing" or not w.get("release"):
                continue
            key = (w.get("family"), str(w.get("release")))
            if key in have:
                continue
            item = out.setdefault(key, {"family": key[0], "release": key[1],
                                        "os": w.get("os"), "hosts": [], "runs": []})
            for h in w.get("hosts") or [w.get("host")]:
                if h and h not in item["hosts"]:
                    item["hosts"].append(h)
            if run.id not in item["runs"]:
                item["runs"].append(run.id)
    return list(out.values())


def _aware(dt: datetime | None) -> datetime | None:
    if dt is None:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=UTC)


def progress_view(row: FeedSync, now: datetime | None = None) -> dict | None:
    """Процент, скорость и ETA текущей загрузки; None — загрузка не идёт."""
    from scanner.feeds.scheduler import STALE_AFTER
    now = now or datetime.now(UTC)
    since = _aware(row.running_since)
    if since is None or now - since >= STALE_AFTER:
        return None
    done, total = row.progress_done, row.progress_total
    elapsed = max((now - since).total_seconds(), 0.0)
    rate = (done / elapsed) if done and elapsed > 1 else None
    percent = (min(100.0, 100.0 * done / total) if total and done is not None else None)
    eta = (int((total - done) / rate) if rate and total and done is not None
           and total >= done else None)
    return {"stage": row.progress_stage, "done": done, "total": total,
            "percent": None if percent is None else round(percent, 1),
            "rate_per_sec": None if rate is None else round(rate, 1),
            "eta_seconds": eta, "elapsed_seconds": int(elapsed),
            "started_at": since.isoformat(),
            "updated_at": _aware(row.progress_at).isoformat() if row.progress_at else None}


def readiness(session: Session, sources: dict) -> dict:
    """Готовность всех источников для мастера настройки."""
    counts = record_counts(session)
    rows = {r.source: r for r in session.scalars(select(FeedSync))}
    now = datetime.now(UTC)
    items = []
    for sid, src in sources.items():
        row = rows.get(sid)
        n = counts.get(sid)
        prog = progress_view(row, now) if row is not None else None
        if prog is not None:
            state = RUNNING
        elif n:
            state = READY
            if row is not None and row.last_success_at and \
                    now - _aware(row.last_success_at) > timedelta(days=30):
                state = STALE
        elif row is not None and row.last_result == "error":
            state = ERROR
        else:
            state = MISSING
        purpose, required = PURPOSE.get(sid, (src.description, False))
        items.append({
            "source": sid, "title": src.title, "purpose": purpose, "required": required,
            "state": state, "records": n, "progress": prog,
            "auto_update": bool(row.enabled) if row else False,
            "last_success_at": (_aware(row.last_success_at).isoformat()
                                if row and row.last_success_at else None),
            "last_result": row.last_result if row else None,
            # во время новой попытки прошлое сообщение — история, не актуальная ошибка
            "message": row.message if row else None,
            "message_is_previous": prog is not None,
            "last_error_at": (_aware(row.last_error_at).isoformat()
                              if row and row.last_error_at else None),
            "hint": None if state in (READY, RUNNING) else HINTS.get(sid),
        })
    missing = missing_releases(session)
    ready = all(i["state"] in (READY, STALE) for i in items if i["required"]) and not missing
    return {"ready": ready, "sources": items, "releases": loaded_releases(session),
            "missing_releases": missing}
