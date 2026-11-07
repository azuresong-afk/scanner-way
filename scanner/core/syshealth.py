"""Состояние самого сканера (хелсчек): из чего он состоит и всё ли с этим в порядке.

В отличие от `/health/ready` (оркестратору нужно одно «да/нет»), здесь — разбор
по компонентам для людей и внешнего мониторинга:

* ``api`` — версия, время работы процесса;
* ``database`` — связь с PostgreSQL, задержка, версия схемы, размер базы;
* ``workers`` — фоновые потоки API (прогоны, расписания, справочники,
  уведомления, сам монитор состояния);
* ``runs`` — зависшие прогоны, давно ждущие в очереди, прерванные за сутки;
* ``engines`` — внешние движки (nmap, Nuclei, OpenSCAP, Lynis, SNMP) и их версии;
* ``feeds`` — справочники БДУ/NVD/бюллетени/Nuclei/EPSS/KEV/MSRC;
* ``disk`` — свободное место в каталогах данных;
* ``nodes`` — связь с сетевыми узлами-сканерами;
* ``notifications`` — неудачные доставки уведомлений за сутки.

Статус компонента: ``ok`` — в порядке, ``warn`` — работает, но стоит
посмотреть, ``error`` — функция сканера не работает. Общий статус — худший из
компонентов. Каждая проверка изолирована: сбой одной не роняет остальные.
Никаких секретов в ответе нет: только имена, версии, счётчики и подсказки.
"""
from __future__ import annotations

import logging
import os
import re
import shutil
import subprocess
import threading
import time
from collections.abc import Callable, Iterable, Mapping
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import func, select, text
from sqlalchemy.orm import Session, sessionmaker

log = logging.getLogger(__name__)

OK, WARN, ERROR, UNKNOWN = "ok", "warn", "error", "unknown"
_RANK = {OK: 0, UNKNOWN: 1, WARN: 2, ERROR: 3}
STATUS_TITLES = {OK: "в порядке", WARN: "требует внимания", ERROR: "не работает",
                 UNKNOWN: "не проверено"}

COMPONENT_TITLES = {
    "api": "Служба API",
    "database": "База данных",
    "workers": "Фоновые службы",
    "runs": "Прогоны",
    "engines": "Движки проверок",
    "feeds": "Справочники",
    "disk": "Место на диске",
    "nodes": "Узлы-сканеры",
    "notifications": "Уведомления",
}

# Движки: (назначение, обязателен ли, команда версии). nmap нужен любому
# прогону; без остальных выпадают отдельные проверки.
ENGINES: dict[str, tuple[str, bool, list[str]]] = {
    "nmap": ("обнаружение хостов и сервисов", True, ["nmap", "--version"]),
    "nuclei": ("сетевые проверки уязвимостей", False, ["nuclei", "-version"]),
    "oscap": ("аудит конфигураций (OpenSCAP)", False, ["oscap", "--version"]),
    "lynis": ("аудит конфигураций (Lynis)", False, ["lynis", "show", "version"]),
    "snmpget": ("аудит сетевых устройств по SNMP", False, ["snmpget", "-V"]),
}
ENGINE_CACHE_SECONDS = 600.0

WORKER_TITLES = {"runs": "исполнитель прогонов", "scheduler": "расписания",
                 "feeds": "обновление справочников", "notifications": "уведомления",
                 "health": "монитор состояния"}

# Диск: меньше этого — предупреждение / ошибка.
DISK_WARN_PERCENT, DISK_WARN_BYTES = 10.0, 5 * 1024 ** 3
DISK_ERROR_PERCENT, DISK_ERROR_BYTES = 3.0, 1024 ** 3

PENDING_TOO_LONG = timedelta(hours=1)
LOOKBACK = timedelta(hours=24)

_VERSION_RE = re.compile(r"(\d+\.\d+(?:\.\d+)*(?:[-.]?[A-Za-z][A-Za-z0-9]*)?)")
_STARTED = time.monotonic()
_STARTED_AT = datetime.now(UTC)


@dataclass(slots=True)
class Component:
    id: str
    status: str
    summary: str
    title: str = ""
    hint: str | None = None
    items: list[dict[str, Any]] = field(default_factory=list)
    details: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.title = self.title or COMPONENT_TITLES.get(self.id, self.id)


def worst(statuses: Iterable[str]) -> str:
    out = OK
    for s in statuses:
        if _RANK.get(s, 1) > _RANK[out]:
            out = s
    return out


def _aware(dt: datetime | None) -> datetime | None:
    if dt is None:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=UTC)


def _human_bytes(n: float) -> str:
    for unit in ("Б", "КБ", "МБ", "ГБ", "ТБ"):
        if abs(n) < 1024 or unit == "ТБ":
            return f"{n:.0f} {unit}" if unit in ("Б", "КБ") else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} ТБ"


def _plural(n: int, one: str, few: str, many: str) -> str:
    if n % 10 == 1 and n % 100 != 11:
        return one
    if 2 <= n % 10 <= 4 and not 12 <= n % 100 <= 14:
        return few
    return many


# ---------------- отдельные проверки ----------------
def check_api(*, in_api: bool = True) -> Component:
    from scanner import __version__
    if not in_api:
        return Component("api", OK, f"версия {__version__} (проверка из командной строки: "
                                    "работу самой службы API показывает /health/ready)",
                         details={"version": __version__})
    up = int(time.monotonic() - _STARTED)
    d, rem = divmod(up, 86400)
    h, rem = divmod(rem, 3600)
    m = rem // 60
    uptime = (f"{d} д {h} ч" if d else f"{h} ч {m} мин" if h else f"{m} мин")
    return Component("api", OK, f"версия {__version__}, работает {uptime}",
                     details={"version": __version__, "uptime_seconds": up,
                              "started_at": _STARTED_AT.isoformat(), "pid": os.getpid()})


def check_database_component(session: Session, *, check_migrations: bool = True) -> Component:
    from scanner.core.health import check_database
    t0 = time.monotonic()
    db = check_database(session.get_bind(), check_migrations=check_migrations)
    latency = round((time.monotonic() - t0) * 1000, 1)
    details: dict[str, Any] = {"latency_ms": latency, **db}
    if db.get("database") != "ok":
        return Component("database", ERROR, "нет связи с базой данных", details=details,
                         hint="Проверьте контейнер db: docker compose ps db, docker compose "
                              "logs db. Пока базы нет, прогоны и интерфейс не работают.")
    expected, current = db.get("expected"), db.get("migration")
    if check_migrations and expected is not None and current != expected:
        return Component("database", ERROR,
                         f"схема базы {current or 'не размечена'}, ожидается {expected}",
                         details=details,
                         hint="Примените миграции: docker compose exec app alembic upgrade "
                              "head (или перезапустите app — entrypoint применит их сам).")
    size = None
    if session.get_bind().dialect.name == "postgresql":
        try:
            size = int(session.execute(
                text("SELECT pg_database_size(current_database())")).scalar() or 0)
        except Exception:  # noqa: BLE001 — нет прав: размер просто не показываем
            session.rollback()
    details["size_bytes"] = size
    parts = [f"отвечает за {latency:g} мс"]
    if current:
        parts.append(f"схема {current}")
    if size:
        parts.append(f"размер {_human_bytes(size)}")
    status = WARN if latency > 1000 else OK
    return Component("database", status, ", ".join(parts), details=details,
                     hint="База отвечает медленно: проверьте нагрузку и диск сервера БД."
                     if status == WARN else None)


def check_workers(threads: Mapping[str, bool] | None) -> Component:
    if threads is None:
        return Component("workers", UNKNOWN, "проверяется только внутри службы API",
                         hint="Запустите проверку в контейнере app или откройте страницу "
                              "«Состояние» в интерфейсе.")
    items = [{"id": k, "title": WORKER_TITLES.get(k, k), "status": OK if v else ERROR}
             for k, v in threads.items()]
    dead = [i["title"] for i in items if i["status"] == ERROR]
    if dead:
        return Component("workers", ERROR, "остановлены: " + ", ".join(dead), items=items,
                         hint="Перезапустите службу: docker compose restart app. Причина — "
                              "в docker compose logs app.")
    return Component("workers", OK, f"работают все ({len(items)})", items=items)


def check_runs(session: Session, *, stale_seconds: float,
               now: datetime | None = None) -> Component:
    from scanner.core.db import ScanRun
    now = now or datetime.now(UTC)
    running = list(session.scalars(select(ScanRun).where(ScanRun.status == "running")))
    pending = list(session.scalars(select(ScanRun).where(ScanRun.status == "pending")))
    stale = timedelta(seconds=max(stale_seconds, 60) * 3)
    stuck = [r for r in running if r.node_id is None and _aware(r.heartbeat_at) is not None
             and now - _aware(r.heartbeat_at) > stale]
    waiting = [r for r in pending if r.node_id is None and _aware(r.created_at) is not None
               and now - _aware(r.created_at) > PENDING_TOO_LONG]
    since = now - LOOKBACK
    interrupted = int(session.scalar(select(func.count()).select_from(ScanRun).where(
        ScanRun.status == "interrupted", ScanRun.finished_at >= since)) or 0)
    failed = int(session.scalar(select(func.count()).select_from(ScanRun).where(
        ScanRun.status == "failed", ScanRun.finished_at >= since)) or 0)
    details = {"running": len(running), "pending": len(pending), "stuck": [r.id for r in stuck],
               "waiting_long": [r.id for r in waiting], "interrupted_24h": interrupted,
               "failed_24h": failed}
    summary = f"идёт {len(running)}, в очереди {len(pending)}"
    if failed:
        summary += f"; с ошибкой за сутки: {failed}"
    problems, hints = [], []
    if stuck:
        problems.append(f"не подают признаков жизни: №{', №'.join(str(r.id) for r in stuck)}")
        hints.append("Зависший прогон можно остановить на его странице; после перезапуска "
                     "службы он будет помечен «Прерван» и его можно повторить.")
    if waiting:
        problems.append(f"ждут в очереди больше часа: {len(waiting)}")
        hints.append("Все исполнители заняты или остановлены — проверьте «Фоновые службы» "
                     "и при необходимости увеличьте SCANNER_API_RUN_WORKERS.")
    if interrupted:
        problems.append(f"прервано перезапуском службы за сутки: {interrupted}")
        hints.append("Служба сканера перезапускалась во время прогонов — проверьте "
                     "docker compose logs app (нехватка памяти, падение).")
    if problems:
        return Component("runs", WARN, "; ".join(problems), details=details,
                         hint=" ".join(hints))
    return Component("runs", OK, summary, details=details)


_engine_cache: dict[str, tuple[float, dict]] = {}
_engine_lock = threading.Lock()


def _probe_engine(name: str, cmd: list[str],
                  which: Callable[[str], str | None] = shutil.which) -> dict:
    path = which(cmd[0])
    if not path:
        return {"installed": False, "version": None, "path": None}
    version = None
    try:
        p = subprocess.run([path, *cmd[1:]], capture_output=True, text=True, timeout=10,
                           check=False)
        out = (p.stdout or "") + "\n" + (p.stderr or "")
        for line in out.splitlines():
            if name == "nuclei" and "version" not in line.lower():
                continue
            m = _VERSION_RE.search(line)
            if m:
                version = m.group(1)
                break
    except (OSError, subprocess.SubprocessError) as e:
        log.debug("engine %s version probe failed: %s", name, e)
    return {"installed": True, "version": version, "path": path}


def engine_info(*, refresh: bool = False,
                probe: Callable[[str, list[str]], dict] | None = None) -> dict[str, dict]:
    """Установлен ли движок и какая версия (кэш на ENGINE_CACHE_SECONDS)."""
    probe = probe or _probe_engine
    now = time.monotonic()
    out = {}
    with _engine_lock:
        for name, (_purpose, _req, cmd) in ENGINES.items():
            cached = _engine_cache.get(name)
            if cached and not refresh and now - cached[0] < ENGINE_CACHE_SECONDS:
                out[name] = cached[1]
                continue
            info = probe(name, cmd)
            _engine_cache[name] = (now, info)
            out[name] = info
    return out


def check_engines(info: Mapping[str, dict]) -> Component:
    items, missing_req, missing_opt = [], [], []
    for name, (purpose, required, _cmd) in ENGINES.items():
        i = info.get(name) or {"installed": False}
        ok = bool(i.get("installed"))
        items.append({"id": name, "title": name, "purpose": purpose, "required": required,
                      "status": OK if ok else (ERROR if required else WARN),
                      "version": i.get("version")})
        if not ok:
            (missing_req if required else missing_opt).append(name)
    if missing_req:
        return Component("engines", ERROR, "нет обязательного движка: " + ", ".join(missing_req),
                         items=items,
                         hint="Без nmap прогоны не обнаружат ни одного хоста. Пересоберите "
                              "образ: docker compose up -d --build app.")
    if missing_opt:
        return Component("engines", WARN, "не установлены: " + ", ".join(missing_opt)
                         + " — эти проверки не выполнятся", items=items,
                         hint="В штатном образе движки есть; если вы собирали образ сами — "
                              "доустановите их или пересоберите образ.")
    versions = ", ".join(f"{i['id']} {i['version']}" if i["version"] else i["id"]
                         for i in items)
    return Component("engines", OK, versions, items=items)


def check_feeds(session: Session, sources: Mapping[str, Any]) -> Component:
    from scanner.feeds.readiness import ERROR as F_ERROR
    from scanner.feeds.readiness import MISSING, RUNNING, STALE, readiness
    r = readiness(session, dict(sources))
    items, bad_req, warn = [], [], []
    for s in r["sources"]:
        state = s["state"]
        if state in (F_ERROR, MISSING) and s["required"]:
            st = ERROR
            bad_req.append(s["title"])
        elif state in (F_ERROR, STALE) or (state == MISSING and not s["required"]):
            st = WARN if state != MISSING else OK
            if state != MISSING:
                warn.append(s["title"])
        else:
            st = OK
        items.append({"id": s["source"], "title": s["title"], "status": st, "state": state,
                      "required": s["required"], "records": s["records"],
                      "last_success_at": s["last_success_at"],
                      "message": None if state == RUNNING else s["message"]})
    missing_rel = r.get("missing_releases") or []
    details = {"missing_releases": [f"{m['family']} {m['release']}" for m in missing_rel]}
    hint = "Откройте «Справочники» — там причина и кнопка «Обновить сейчас»."
    if bad_req:
        return Component("feeds", ERROR, "нет данных или ошибка загрузки: " + ", ".join(bad_req),
                         items=items, details=details,
                         hint=hint + " Без них находки не привязываются к БДУ/CVE "
                                     "или отчёт будет неполным.")
    if warn or missing_rel:
        parts = []
        if warn:
            parts.append("устарели или не обновились: " + ", ".join(warn))
        if missing_rel:
            parts.append("нет бюллетеней для " + ", ".join(details["missing_releases"][:5]))
        return Component("feeds", WARN, "; ".join(parts), items=items, details=details,
                         hint=hint)
    loaded = sum(1 for i in items if i["records"])
    return Component("feeds", OK, f"загружено {loaded} из {len(items)}", items=items,
                     details=details)


def default_disk_paths() -> list[str]:
    from scanner.core.health import ROOT
    paths = [p for p in ("/data",) if os.path.isdir(p)]
    return paths or [str(ROOT)]


def check_disk(paths: Iterable[str],
               usage: Callable[[str], Any] = shutil.disk_usage) -> Component:
    items, seen = [], set()
    for p in paths:
        try:
            u = usage(p)
        except OSError as e:
            items.append({"id": p, "title": p, "status": UNKNOWN, "error": str(e)[:200]})
            continue
        key = (u.total, u.used)         # один и тот же раздел под разными путями
        if key in seen:
            continue
        seen.add(key)
        pct = 100.0 * u.free / u.total if u.total else 0.0
        if pct < DISK_ERROR_PERCENT or u.free < DISK_ERROR_BYTES:
            st = ERROR
        elif pct < DISK_WARN_PERCENT or u.free < DISK_WARN_BYTES:
            st = WARN
        else:
            st = OK
        items.append({"id": p, "title": p, "status": st, "free_bytes": u.free,
                      "total_bytes": u.total, "free_percent": round(pct, 1)})
    if not items:
        return Component("disk", UNKNOWN, "каталоги данных не найдены")
    status = worst(i["status"] for i in items)
    summary = "; ".join(f"{i['title']}: свободно {_human_bytes(i['free_bytes'])} "
                        f"({i['free_percent']:g}%)" if "free_bytes" in i
                        else f"{i['title']}: {i.get('error')}" for i in items)
    hint = None
    if status in (WARN, ERROR):
        hint = ("Освободите место: удалите старые отчёты и образы (docker system prune), "
                "перенесите резервные копии. Когда место кончится, PostgreSQL и загрузка "
                "справочников остановятся.")
    return Component("disk", status, summary, items=items, hint=hint)


def check_nodes(session: Session, now: datetime | None = None) -> Component:
    from scanner.core.db import ScanNode
    from scanner.nodes.store import (
        MODE_ONLINE,
        STATUS_NEVER,
        STATUS_OFFLINE,
        STATUS_ONLINE,
        node_status,
    )
    rows = list(session.scalars(select(ScanNode).order_by(ScanNode.name)))
    online_nodes = [n for n in rows if n.mode == MODE_ONLINE and n.enabled]
    if not online_nodes:
        return Component("nodes", OK, "сетевых узлов нет" if not rows
                         else f"сетевых узлов нет (всего узлов: {len(rows)})")
    items = []
    for n in online_nodes:
        st = node_status(n, now)
        items.append({"id": n.id, "title": n.name, "node_status": st,
                      "status": OK if st == STATUS_ONLINE else WARN if st == STATUS_OFFLINE
                      else UNKNOWN,
                      "last_seen_at": _aware(n.last_seen_at).isoformat()
                      if n.last_seen_at else None, "version": n.version})
    off = [i["title"] for i in items if i["node_status"] == STATUS_OFFLINE]
    never = [i["title"] for i in items if i["node_status"] == STATUS_NEVER]
    on = sum(1 for i in items if i["node_status"] == STATUS_ONLINE)
    summary = f"на связи {on} из {len(items)}"
    if never:
        summary += f"; ещё не подключались: {', '.join(never)}"
    if off:
        return Component("nodes", WARN, f"нет связи: {', '.join(off)}; " + summary,
                         items=items,
                         hint="На машине узла посмотрите журнал (docker compose -f "
                              "docker-compose.node.yml logs node) и проверьте связь (… run "
                              "--rm node check). Прогоны на этих узлах ждут, пока узел "
                              "снова выйдет на связь.")
    return Component("nodes", OK, summary, items=items)


def check_notifications(session: Session, now: datetime | None = None) -> Component:
    from scanner.core.db import IntegrationChannelRow, NotificationLogRow
    now = now or datetime.now(UTC)
    channels = list(session.scalars(select(IntegrationChannelRow)))
    enabled = [c for c in channels if c.enabled]
    if not enabled:
        return Component("notifications", OK,
                         "каналы не настроены" if not channels else "все каналы выключены")
    since = now - LOOKBACK
    failed = list(session.execute(
        select(NotificationLogRow.channel_id, func.count()).where(
            NotificationLogRow.status == "failed",
            NotificationLogRow.created_at >= since)
        .group_by(NotificationLogRow.channel_id)).all())
    retry = int(session.scalar(select(func.count()).select_from(NotificationLogRow).where(
        NotificationLogRow.status == "retry")) or 0)
    by_id = {c.id: c for c in channels}
    items = [{"id": c.id, "title": c.name, "kind": c.type,
              "status": OK if c.id not in dict(failed) else WARN,
              "failed_24h": int(dict(failed).get(c.id, 0))} for c in enabled]
    total_failed = sum(int(n) for _cid, n in failed)
    summary = f"каналов включено: {len(enabled)}"
    if retry:
        summary += f"; ждут повтора: {retry}"
    if total_failed:
        names = ", ".join(by_id[cid].name for cid, _n in failed if cid in by_id)
        return Component("notifications", WARN,
                         f"не доставлено за сутки: {total_failed} ({names}); " + summary,
                         items=items, details={"retry": retry, "failed_24h": total_failed},
                         hint="Откройте «Уведомления» → журнал доставки: там причина и "
                              "кнопка «Повторить».")
    return Component("notifications", OK, summary, items=items,
                     details={"retry": retry, "failed_24h": 0})


# ---------------- сборка ----------------
@dataclass(slots=True)
class HealthContext:
    sessions: sessionmaker[Session]
    feed_sources: Mapping[str, Any] = field(default_factory=dict)
    threads: Callable[[], Mapping[str, bool]] | None = None
    disk_paths: list[str] = field(default_factory=default_disk_paths)
    check_migrations: bool = True
    run_stale_seconds: float = 180.0
    engines: Callable[..., dict[str, dict]] = engine_info


def _guard(cid: str, fn: Callable[[], Component]) -> Component:
    try:
        return fn()
    except Exception as e:
        log.exception("health check %s failed", cid)
        return Component(cid, UNKNOWN, f"проверка не выполнена: {type(e).__name__}",
                         details={"error": str(e).splitlines()[0][:200] if str(e) else ""})


def collect(ctx: HealthContext, *, refresh: bool = False) -> dict[str, Any]:
    """Полный отчёт о состоянии: {"status", "checked_at", "components": [...]}"""
    comps: list[Component] = [_guard("api", lambda: check_api(
        in_api=ctx.threads is not None))]
    session = ctx.sessions()
    try:
        db = _guard("database", lambda: check_database_component(
            session, check_migrations=ctx.check_migrations))
        comps.append(db)
        comps.append(_guard("workers", lambda: check_workers(
            ctx.threads() if ctx.threads else None)))
        db_ok = db.status in (OK, WARN)

        def with_db(cid: str, fn: Callable[[], Component]) -> Component:
            if not db_ok:
                return Component(cid, UNKNOWN, "не проверено: база данных недоступна "
                                           "или её схема устарела")
            try:
                return _guard(cid, fn)
            finally:
                session.rollback()

        comps.append(with_db("runs", lambda: check_runs(
            session, stale_seconds=ctx.run_stale_seconds)))
        comps.append(_guard("engines", lambda: check_engines(ctx.engines(refresh=refresh))))
        comps.append(with_db("feeds", lambda: check_feeds(session, ctx.feed_sources)))
        comps.append(_guard("disk", lambda: check_disk(ctx.disk_paths)))
        comps.append(with_db("nodes", lambda: check_nodes(session)))
        comps.append(with_db("notifications", lambda: check_notifications(session)))
    finally:
        session.close()
    status = worst(c.status for c in comps)
    return {"status": status, "status_title": STATUS_TITLES[status],
            "checked_at": datetime.now(UTC).isoformat(),
            "components": [asdict(c) for c in comps]}


def brief(report: Mapping[str, Any]) -> dict[str, Any]:
    """Только статусы — для внешнего мониторинга без входа (без подробностей)."""
    return {"status": report["status"], "checked_at": report["checked_at"],
            "components": {c["id"]: c["status"] for c in report["components"]}}


# ---------------- монитор: уведомления о сменах состояния ----------------
class HealthMonitor:
    """Раз в tick_seconds собирает состояние и сообщает о переходах компонентов.

    Уведомление уходит, когда компонент переходит в warn/error (или сразу после
    старта, если он уже не в порядке) и когда он возвращается в ok.
    ``unknown`` уведомлений не вызывает. Последний отчёт кэшируется — страница
    «Состояние» и шапка интерфейса не запускают проверки чаще, чем нужно.
    """

    CACHE_SECONDS = 15.0

    def __init__(self, ctx: HealthContext, *, tick_seconds: float = 300.0,
                 notify: Callable[[str, str, str, str, str | None], None] | None = None):
        self.ctx = ctx
        self.tick_seconds = tick_seconds
        self.notify = notify
        self._prev: dict[str, str] = {}
        self._last: tuple[float, dict] | None = None
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        if self.tick_seconds <= 0 or self._thread is not None:
            return
        self._thread = threading.Thread(target=self._loop, name="health-monitor", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=5)
            self._thread = None

    def _loop(self) -> None:
        # первая проверка — не сразу: даём службам API подняться
        while not self._stop.wait(min(self.tick_seconds, 60.0) if not self._prev
                                  else self.tick_seconds):
            try:
                self.tick()
            except Exception:
                log.exception("health monitor tick failed")

    def report(self, *, refresh: bool = False) -> dict:
        with self._lock:
            if not refresh and self._last and \
                    time.monotonic() - self._last[0] < self.CACHE_SECONDS:
                return self._last[1]
        rep = collect(self.ctx, refresh=refresh)
        with self._lock:
            self._last = (time.monotonic(), rep)
        return rep

    def tick(self) -> list[tuple[str, str, str]]:
        """Одна проверка; возвращает переходы (компонент, было, стало)."""
        rep = self.report(refresh=True)
        changes: list[tuple[str, str, str]] = []
        for c in rep["components"]:
            cur, prev = c["status"], self._prev.get(c["id"])
            if cur == UNKNOWN:
                continue
            self._prev[c["id"]] = cur
            if prev == cur or (prev is None and cur == OK):
                continue
            if prev is None or prev == UNKNOWN:
                prev = OK
            if prev == cur:
                continue
            changes.append((c["id"], prev, cur))
            if cur == OK:
                log.info("health: %s recovered", c["id"])
            else:
                log.warning("health: %s is %s: %s", c["id"], cur, c["summary"])
            if self.notify is not None:
                try:
                    self.notify(c["id"], c["title"], cur, c["summary"], c.get("hint"))
                except Exception:
                    log.exception("health notification failed")
        return changes
