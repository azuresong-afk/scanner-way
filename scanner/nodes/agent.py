"""Узел-сканер: исполнение задания и цикл агента (`scanner node run`).

Узел — вторая линия allowlist: цели задания пересекаются с локальным
allowlist узла (SCANNER_NODE_ALLOWLIST), который задаётся при установке на
самом узле и центром не меняется. Адрес вне него узел не трогает, даже если
центр выдал его в задании (центр скомпрометирован, ошибка администратора).

Цикл агента: регистрация (hello) -> опрос заданий раз в poll_seconds -> прогон
тем же оркестратором, что и в центре (модули, лимиты скорости, покрытие) ->
результат в центр. Пока прогон идёт, отдельный поток раз в heartbeat_seconds
отправляет отметку «жив» и ход прогона и узнаёт об остановке оператором.
Аудит действий узла буферизуется и уходит в журнал аудита центра; копия — в
журнал контейнера узла. Результат перед отправкой кладётся в каталог очереди
(SCANNER_NODE_SPOOL) и удаляется после приёма центром: обрыв связи или
перезапуск узла его не теряет.
"""
from __future__ import annotations

import gzip
import json
import logging
import os
import platform
import shutil
import socket
import tarfile
import threading
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from scanner.core import run_events as ev
from scanner.core.allowlist import AllowlistGate
from scanner.core.orchestrator import (
    ModuleFactory,
    Orchestrator,
    RunOutcome,
    default_module_registry,
)
from scanner.core.ratelimit import get_profile
from scanner.nodes.codec import NodeJob, decode_job, encode_outcome
from scanner.nodes.store import intersect_networks, scope_networks

log = logging.getLogger("scanner.node")

POLL_SECONDS = 5.0
HEARTBEAT_SECONDS = 10.0
AUDIT_FLUSH_RECORDS = 200
TEMPLATES_EVERY = 24 * 3600.0
TOOLS = ("nmap", "nuclei", "oscap", "lynis", "snmpget")


class NodeConfigError(ValueError):
    """Узел настроен неверно — агент не стартует."""


# ---------- модули узла ----------
def node_registry(reference_store: object | None, advisory_store: object | None = None,
                  msrc_store: object | None = None) -> dict[str, ModuleFactory]:
    """Реестр модулей узла над переданными справочниками.

    Сетевой режим — справочники центра через RPC (scanner.nodes.remote),
    автономный — локальная копия из комплекта данных. Подгрузка бюллетеней из
    интернета на узле выключена: справочники обновляются там, где они хранятся."""
    matcher = None
    if reference_store is not None:
        from scanner.feeds.matcher import VulnMatcher
        matcher = VulnMatcher(reference_store)  # type: ignore[arg-type]
    reg = dict(default_module_registry(matcher=matcher))

    def auth_inventory():
        from scanner.core.sshexec import options_from_env
        from scanner.modules.auth_inventory import (
            AuthInventoryModule,
            AuthInventoryOptions,
        )
        return AuthInventoryModule(AuthInventoryOptions(ssh=options_from_env()),
                                   matcher=matcher, advisories=advisory_store,
                                   fetch_advisories=None)

    def win_inventory():
        from scanner.core.winexec import options_from_env
        from scanner.modules.win_inventory import (
            WinInventoryModule,
            WinInventoryOptions,
        )
        return WinInventoryModule(WinInventoryOptions(winrm=options_from_env()),
                                  matcher=matcher, msrc_store=msrc_store)

    def db_audit():
        from scanner.core.dbexec import options_from_env
        from scanner.modules.db_audit import DbAuditModule, DbAuditOptions
        return DbAuditModule(DbAuditOptions(db=options_from_env()), matcher=matcher,
                             msrc_store=msrc_store)

    reg.update({"auth_inventory": auth_inventory, "win_inventory": win_inventory,
                "db_audit": db_audit})
    return reg


def local_gate(job: NodeJob, local_allowlist: list[str]) -> AllowlistGate:
    """allowlist задания ∩ локальный allowlist узла."""
    return AllowlistGate(intersect_networks(job.allowlist, scope_networks(local_allowlist)))


def execute_job(job: NodeJob, registry: Mapping[str, ModuleFactory], *, audit: Any,
                local_allowlist: list[str],
                progress: Callable[[dict], None] | None = None,
                should_stop: Callable[[], bool] | None = None,
                events: Callable[[ev.Event], None] | None = None) -> RunOutcome:
    """Исполняет задание на узле. Цели вне локального allowlist узла
    отбрасываются (и попадают в аудит как отказ). ValueError — узел не может
    исполнить задание (нет модуля в этой версии узла)."""
    missing = [m for m in job.modules if m not in registry]
    if missing:
        raise ValueError(f"узел не поддерживает модули: {', '.join(missing)} — "
                         "обновите образ узла до версии центра")
    gate = local_gate(job, local_allowlist)
    orch = Orchestrator(gate, audit, should_stop=should_stop, events=events)
    return orch.run_detailed(
        engagement_id=job.engagement_id, scan_run_id=job.scan_run_id,
        requested_targets=list(job.targets), modules=[registry[m]() for m in job.modules],
        rate=get_profile(job.rate_profile), credentials=list(job.credentials),
        cred_candidates=list(job.cred_candidates), options=dict(job.options),
        progress=progress, progress_history=dict(job.progress_history))


# ---------- аудит узла ----------
def _jsonable(v: Any) -> Any:
    try:
        return json.loads(json.dumps(v, ensure_ascii=False, default=str))
    except (TypeError, ValueError):
        return str(v)


class BufferedAudit:
    """Аудит действий узла: копия в журнал контейнера + буфер для центра."""

    def __init__(self, flush: Callable[[list[dict]], None], *,
                 max_records: int = AUDIT_FLUSH_RECORDS):
        self._flush = flush
        self._buf: list[dict] = []
        self._lock = threading.Lock()
        self.max_records = max_records

    def record(self, *, subject: str, action: str, target: str, result: str,
               details: Any = None) -> None:
        rec = {"ts": time.time(), "subject": subject, "action": action,
               "target": str(target)[:500], "result": str(result)[:100],
               "details": _jsonable(details)}
        log.info("AUDIT action=%s target=%s result=%s", action, rec["target"], result)
        with self._lock:
            self._buf.append(rec)
            full = len(self._buf) >= self.max_records
        if full:
            self.flush()

    def flush(self) -> None:
        with self._lock:
            batch, self._buf = self._buf, []
        if not batch:
            return
        try:
            self._flush(batch)
        except Exception:   # центр недоступен — вернуть в буфер, отправим позже
            log.warning("audit upload failed, %d records kept", len(batch), exc_info=True)
            with self._lock:
                self._buf = batch + self._buf


# ---------- конфигурация ----------
@dataclass(slots=True)
class NodeConfig:
    server: str
    token: str
    allowlist: list[str]
    ca: str | None = None
    client_cert: str | None = None
    client_key: str | None = None
    poll_seconds: float = POLL_SECONDS
    heartbeat_seconds: float = HEARTBEAT_SECONDS
    spool: Path | None = None
    sync_templates: bool = True
    allow_http: bool = False
    name: str | None = None
    extra: dict = field(default_factory=dict)


def _split(v: str | None) -> list[str]:
    return [x.strip() for x in (v or "").replace(";", ",").replace("\n", ",").split(",")
            if x.strip()]


def config_from_env(env: Mapping[str, str] | None = None) -> NodeConfig:
    e = os.environ if env is None else env
    allow = _split(e.get("SCANNER_NODE_ALLOWLIST"))
    if not allow:
        raise NodeConfigError(
            "не задан локальный allowlist узла SCANNER_NODE_ALLOWLIST (сети сегмента, "
            "которые этому узлу разрешено проверять) — узел без него не стартует")
    from scanner.nodes.store import NodeError, clean_scope
    try:
        allow = clean_scope(allow)
    except NodeError as err:
        raise NodeConfigError(f"SCANNER_NODE_ALLOWLIST: {err}") from err
    token = (e.get("SCANNER_NODE_TOKEN") or "").strip()
    token_file = e.get("SCANNER_NODE_TOKEN_FILE")
    if not token and token_file:
        token = Path(token_file).read_text(encoding="utf-8").strip()
    spool = e.get("SCANNER_NODE_SPOOL", "/var/lib/scanner-node/spool")
    return NodeConfig(server=(e.get("SCANNER_NODE_SERVER") or "").strip(), token=token,
                      allowlist=allow, ca=e.get("SCANNER_NODE_CA") or None,
                      client_cert=e.get("SCANNER_NODE_CLIENT_CERT") or None,
                      client_key=e.get("SCANNER_NODE_CLIENT_KEY") or None,
                      poll_seconds=float(e.get("SCANNER_NODE_POLL_SECONDS") or POLL_SECONDS),
                      heartbeat_seconds=float(e.get("SCANNER_NODE_HEARTBEAT_SECONDS")
                                              or HEARTBEAT_SECONDS),
                      spool=Path(spool) if spool else None,
                      sync_templates=(e.get("SCANNER_NODE_TEMPLATES_FROM_CENTER", "1")
                                      not in ("0", "false", "no", "off")),
                      allow_http=e.get("SCANNER_NODE_ALLOW_HTTP", "0") in ("1", "true", "yes"))


def node_info(cfg: NodeConfig) -> dict:
    from scanner import __version__ as version
    return {"hostname": socket.gethostname(), "version": version,
            "allowlist": cfg.allowlist, "platform": platform.platform(),
            "python": platform.python_version(),
            "tools": {t: bool(shutil.which(t)) for t in TOOLS}}


# ---------- агент ----------
class NodeAgent:
    def __init__(self, client: Any, cfg: NodeConfig, *,
                 registry: Mapping[str, ModuleFactory] | None = None,
                 sleep: Callable[[float], None] = time.sleep):
        self.client = client
        self.cfg = cfg
        self._registry = registry
        self._sleep = sleep
        self.node: dict = {}

    @property
    def registry(self) -> Mapping[str, ModuleFactory]:
        if self._registry is None:
            from scanner.nodes.remote import (
                RemoteAdvisoryStore,
                RemoteMsrcStore,
                RemoteReferenceStore,
            )
            self._registry = node_registry(RemoteReferenceStore(self.client),
                                           RemoteAdvisoryStore(self.client),
                                           RemoteMsrcStore(self.client))
        return self._registry

    def sync_templates(self) -> int | None:
        """Шаблоны Nuclei из центра (если изменились). -> число файлов; None — без
        изменений или центр их не раздаёт. Ошибка не мешает работе узла."""
        from scanner.feeds.sources import nuclei_templates_dir
        from scanner.nodes.remote import NodeApiError
        from scanner.nodes.templates import install_archive
        target = nuclei_templates_dir()
        marker = target.parent / ".scanner-node-templates-etag"
        etag = marker.read_text().strip() if marker.is_file() else None
        tmp = target.parent / ".nuclei-templates-download.tar.gz"
        try:
            target.parent.mkdir(parents=True, exist_ok=True)
            new = self.client.download_templates(tmp, etag)
            if new is None:
                return None
            n = install_archive(tmp, target)
            marker.write_text(new)
            log.info("шаблоны Nuclei обновлены из центра: %d файлов", n)
            return n
        except NodeApiError as e:
            if e.status != 404:
                log.warning("шаблоны Nuclei не получены из центра: %s", e)
            return None
        except (OSError, tarfile.TarError):
            log.warning("шаблоны Nuclei из центра не распакованы", exc_info=True)
            return None
        finally:
            tmp.unlink(missing_ok=True)

    def hello(self) -> dict:
        res = self.client.hello(node_info(self.cfg))
        self.node = dict(res.get("node") or {})
        outside = res.get("outside_local_allowlist") or []
        log.info("connected to %s as node «%s»", self.cfg.server, self.node.get("name"))
        if outside:
            log.warning("сети узла в центре вне локального allowlist (не будут "
                        "проверяться): %s", ", ".join(outside))
        return res

    # --- очередь результатов ---
    def _spool_path(self, run_id: int) -> Path | None:
        if self.cfg.spool is None:
            return None
        return self.cfg.spool / f"result-{int(run_id)}.json.gz"

    def _spool(self, run_id: int, payload: dict) -> None:
        p = self._spool_path(run_id)
        if p is None:
            return
        try:
            p.parent.mkdir(parents=True, exist_ok=True)
            tmp = p.with_suffix(".tmp")
            tmp.write_bytes(gzip.compress(json.dumps(payload, ensure_ascii=False).encode()))
            os.chmod(tmp, 0o600)
            tmp.replace(p)
        except OSError:
            log.warning("cannot spool result of run %s", run_id, exc_info=True)

    def _unspool(self, run_id: int) -> None:
        p = self._spool_path(run_id)
        if p is not None:
            p.unlink(missing_ok=True)

    def resend_spooled(self) -> int:
        if self.cfg.spool is None or not self.cfg.spool.is_dir():
            return 0
        sent = 0
        for p in sorted(self.cfg.spool.glob("result-*.json.gz")):
            try:
                run_id = int(p.name.split("-")[1].split(".")[0])
                payload = json.loads(gzip.decompress(p.read_bytes()))
            except (ValueError, OSError):
                log.warning("broken spooled result %s — removed", p)
                p.unlink(missing_ok=True)
                continue
            if self._upload(run_id, payload, attempts=1):
                sent += 1
        return sent

    def _upload(self, run_id: int, payload: dict, *, attempts: int = 8) -> bool:
        from scanner.nodes.remote import NodeApiError
        delay = 2.0
        for i in range(attempts):
            try:
                res = self.client.result(run_id, payload)
                log.info("run %s: result accepted, status %s", run_id,
                         (res or {}).get("status"))
                self._unspool(run_id)
                return True
            except NodeApiError as e:
                if e.status is not None and 400 <= e.status < 500:
                    # центр отказал окончательно (прогон чужой/уже завершён)
                    log.error("run %s: result rejected: %s", run_id, e)
                    self._unspool(run_id)
                    return False
                log.warning("run %s: result upload failed (%s), retry %d", run_id, e, i + 1)
                if i + 1 < attempts:
                    self._sleep(delay)
                    delay = min(delay * 2, 120.0)
        return False

    # --- задание ---
    def run_once(self) -> bool:
        """Забрать и исполнить одно задание. -> было ли задание."""
        data = self.client.next_job()
        if not data:
            return False
        self.handle_job(data)
        return True

    def handle_job(self, data: Mapping) -> str:
        from scanner.nodes.remote import NodeApiError
        job = decode_job(data)
        run_id = job.scan_run_id
        log.info("run %s: job received, %d targets, modules %s", run_id, len(job.targets),
                 ",".join(job.modules))
        audit = BufferedAudit(lambda recs: self.client.audit(run_id, recs))
        stop = threading.Event()
        latest: dict = {"progress": None}
        done = threading.Event()

        def beat() -> None:
            while not done.wait(self.cfg.heartbeat_seconds):
                try:
                    res = self.client.heartbeat(run_id, latest["progress"]) or {}
                    if res.get("stop"):
                        stop.set()
                except NodeApiError as e:
                    if e.status in (404, 409):
                        stop.set()      # прогон снят в центре
                    log.warning("run %s: heartbeat failed: %s", run_id, e)
                audit.flush()

        def send_event(e: ev.Event) -> None:
            try:
                self.client.events(run_id, [{"kind": e.kind, "subject": e.subject,
                                             "message": e.message, "host": e.host,
                                             "severity": e.severity,
                                             "details": _jsonable(e.details)}])
            except Exception:  # лента вторична
                log.debug("event upload failed", exc_info=True)

        def on_progress(snap: dict) -> None:
            latest["progress"] = snap

        hb = threading.Thread(target=beat, name=f"node-heartbeat-{run_id}", daemon=True)
        hb.start()
        try:
            try:
                out = execute_job(job, self.registry, audit=audit,
                                  local_allowlist=self.cfg.allowlist,
                                  progress=on_progress, should_stop=stop.is_set,
                                  events=send_event)
            except Exception as e:
                log.exception("run %s: execution failed", run_id)
                audit.flush()
                try:
                    self.client.fail(run_id, f"{type(e).__name__}: {e}")
                except NodeApiError:
                    log.warning("run %s: cannot report failure", run_id)
                return "failed"
            finally:
                job.credentials, job.cred_candidates = [], []   # секреты больше не нужны
            audit.flush()
            payload = encode_outcome(out, scan_run_id=run_id)
            self._spool(run_id, payload)
            ok = self._upload(run_id, payload)
            audit.flush()
            return "sent" if ok else "spooled"
        finally:
            done.set()
            hb.join(timeout=5)

    def run_forever(self, stop: threading.Event | None = None) -> None:
        from scanner.nodes.remote import NodeApiError
        stop = stop or threading.Event()
        connected = False
        delay = self.cfg.poll_seconds
        next_templates = 0.0
        while not stop.is_set():
            try:
                if not connected:
                    self.hello()
                    connected = True
                    self.resend_spooled()
                if self.cfg.sync_templates and time.monotonic() >= next_templates:
                    self.sync_templates()
                    next_templates = time.monotonic() + TEMPLATES_EVERY
                if not self.run_once():
                    stop.wait(self.cfg.poll_seconds)
                delay = self.cfg.poll_seconds
            except NodeApiError as e:
                connected = False
                if e.status == 401:
                    log.error("центр отклонил токен узла (неверный, перевыпущен или "
                              "узел отключён) — проверьте SCANNER_NODE_TOKEN")
                else:
                    log.warning("нет связи с центром: %s", e)
                stop.wait(delay)
                delay = min(delay * 2, 300.0)
