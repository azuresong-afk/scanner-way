"""Узлы-сканеры (распределённое сканирование).

Две части:

* «Сканеры» для людей (/nodes): список и статус узлов — право run_scan или
  view_engagements (выбор узла при запуске); заведение, изменение,
  перевыпуск токена и удаление — manage_nodes (администратор). Токен узла
  отдаётся только в ответе на заведение/перевыпуск, в БД — его хэш.
* Протокол узла (/node/v1/*): узел сам выходит на центр с токеном узла
  (Authorization: Bearer snode_…), забирает задания своих прогонов, шлёт
  отметку «жив», ход, ленту, аудит и результат, читает справочники
  (только чтение, белый список методов). Пользовательский токен здесь не
  действует, токен узла не действует в остальном API.

Опционально mTLS: обратный прокси центра проверяет сертификат узла и передаёт
результат заголовками (SCANNER_NODE_MTLS_VERIFY_HEADER / ..._FINGERPRINT_HEADER);
отпечаток сертификата закрепляется за узлом при первом подключении.
"""
from __future__ import annotations

import json
import os
import zlib
from datetime import datetime
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from scanner.api.deps import AuditDep, Principal, SessionDep, deny
from scanner.api.deps import current_user as _current_user
from scanner.api.rbac import Perm
from scanner.core import run_events as ev
from scanner.core.audit import AuditSink
from scanner.core.db import ScanNode, ScanRun, session_scope
from scanner.core.orchestrator import RunService
from scanner.nodes import store as nodes
from scanner.nodes.codec import CodecError, decode_outcome

router = APIRouter(tags=["nodes"])
_bearer = HTTPBearer(auto_error=False)

MAX_BODY = int(os.environ.get("SCANNER_NODE_MAX_RESULT_MB", "256")) * 1024 * 1024
POLL_SECONDS = 5


# ---------------- схемы ----------------
class NodeIn(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    description: str | None = Field(default=None, max_length=500)
    mode: str = Field(default=nodes.MODE_ONLINE, pattern="^(online|offline)$")
    scope: list[str] = Field(min_length=1, max_length=nodes.MAX_SCOPE)
    allow_credentials: bool = True


class NodeUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=100)
    description: str | None = Field(default=None, max_length=500)
    scope: list[str] | None = Field(default=None, min_length=1, max_length=nodes.MAX_SCOPE)
    allow_credentials: bool | None = None
    enabled: bool | None = None


class NodeOut(BaseModel):
    id: int
    name: str
    description: str | None = None
    mode: str
    status: str                 # online | offline | never | disabled | autonomous
    scope: list[str]
    allow_credentials: bool
    enabled: bool
    token_prefix: str | None = None
    hostname: str | None = None
    version: str | None = None
    local_allowlist: list[str] = Field(default_factory=list)
    outside_local_allowlist: list[str] = Field(default_factory=list)
    tools: dict[str, bool] = Field(default_factory=dict)
    created_at: datetime | None = None
    registered_at: datetime | None = None
    last_seen_at: datetime | None = None
    active_runs: list[int] = Field(default_factory=list)
    queued_runs: int = 0
    has_public_key: bool = False


class NodeCreated(NodeOut):
    token: str | None = None     # показывается один раз


def _outside(node: ScanNode) -> list[str]:
    """Сети узла из центра, которых нет в локальном allowlist узла."""
    local = (node.info or {}).get("allowlist") or []
    if not local:
        return []
    local_nets = nodes.scope_networks(local)
    out = []
    for spec in node.scope or []:
        nets = nodes.scope_networks([spec])
        covered = nodes.intersect_networks(nets, local_nets)
        if sorted(covered) != sorted(nets):
            out.append(spec)
    return out


def node_out(session: Session, node: ScanNode, **extra: Any) -> dict:
    runs = nodes.active_runs(session, node.id)
    info = node.info or {}
    return dict(id=node.id, name=node.name, description=node.description, mode=node.mode,
                status=nodes.node_status(node), scope=list(node.scope or []),
                allow_credentials=node.allow_credentials, enabled=node.enabled,
                token_prefix=node.token_prefix, hostname=node.hostname,
                version=node.version, local_allowlist=list(info.get("allowlist") or []),
                outside_local_allowlist=_outside(node),
                tools={str(k): bool(v) for k, v in (info.get("tools") or {}).items()},
                created_at=node.created_at, registered_at=node.registered_at,
                last_seen_at=node.last_seen_at,
                active_runs=[r.id for r in runs if r.status == "running"],
                queued_runs=sum(1 for r in runs if r.status == "pending"),
                has_public_key=bool(node.public_key), **extra)


# ---------------- права людей ----------------
def _viewer(request: Request, user: Annotated[Principal, Depends(_current_user)],
            audit: AuditDep) -> Principal:
    if not (user.has(Perm.RUN_SCAN) or user.has(Perm.VIEW_ENGAGEMENTS)):
        deny(audit, user, request, [str(Perm.VIEW_ENGAGEMENTS)])
    return user


def _manager(request: Request, user: Annotated[Principal, Depends(_current_user)],
             audit: AuditDep) -> Principal:
    if not user.has(Perm.MANAGE_NODES):
        deny(audit, user, request, [str(Perm.MANAGE_NODES)])
    return user


Viewer = Annotated[Principal, Depends(_viewer)]
Manager = Annotated[Principal, Depends(_manager)]


def _get(session: Session, node_id: int) -> ScanNode:
    node = nodes.get_node(session, node_id)
    if node is None:
        raise HTTPException(404, "узел не найден")
    return node


@router.get("/nodes", response_model=list[NodeOut])
def list_nodes(_: Viewer, session: SessionDep) -> list[dict]:
    return [node_out(session, n) for n in nodes.list_nodes(session)]


@router.get("/nodes/{node_id}", response_model=NodeOut)
def get_node(node_id: int, _: Viewer, session: SessionDep) -> dict:
    return node_out(session, _get(session, node_id))


@router.post("/nodes", response_model=NodeCreated, status_code=201)
def create_node(body: NodeIn, user: Manager, session: SessionDep, audit: AuditDep) -> dict:
    try:
        node, token = nodes.create_node(session, name=body.name, scope=body.scope,
                                        description=body.description, mode=body.mode,
                                        allow_credentials=body.allow_credentials,
                                        created_by=user.id)
    except nodes.NodeError as e:
        raise HTTPException(422, str(e)) from e
    audit.record(subject=user.subject, action="node_create", target=f"node:{node.id}",
                 result="ok", details={"name": node.name, "mode": node.mode,
                                       "scope": node.scope,
                                       "allow_credentials": node.allow_credentials,
                                       "token_prefix": node.token_prefix})
    return node_out(session, node, token=token)


@router.patch("/nodes/{node_id}", response_model=NodeOut)
def update_node(node_id: int, body: NodeUpdate, user: Manager, session: SessionDep,
                audit: AuditDep) -> dict:
    node = _get(session, node_id)
    before = {"name": node.name, "scope": list(node.scope or []),
              "allow_credentials": node.allow_credentials, "enabled": node.enabled}
    try:
        nodes.update_node(session, node, **body.model_dump(exclude_unset=True))
    except nodes.NodeError as e:
        raise HTTPException(422, str(e)) from e
    audit.record(subject=user.subject, action="node_update", target=f"node:{node.id}",
                 result="ok", details={"before": before,
                                       "changes": body.model_dump(exclude_unset=True)})
    return node_out(session, node)


@router.post("/nodes/{node_id}/token", response_model=NodeCreated)
def rotate_token(node_id: int, user: Manager, session: SessionDep, audit: AuditDep) -> dict:
    node = _get(session, node_id)
    try:
        token = nodes.rotate_token(session, node)
    except nodes.NodeError as e:
        raise HTTPException(422, str(e)) from e
    # закреплённый сертификат сбрасывается вместе с токеном (переустановка узла)
    info = dict(node.info or {})
    info.pop("cert_fingerprint", None)
    node.info = info
    audit.record(subject=user.subject, action="node_token_rotate", target=f"node:{node.id}",
                 result="ok", details={"name": node.name, "token_prefix": node.token_prefix})
    return node_out(session, node, token=token)


@router.delete("/nodes/{node_id}", status_code=204)
def delete_node(node_id: int, user: Manager, session: SessionDep, audit: AuditDep) -> Response:
    node = _get(session, node_id)
    active = nodes.active_runs(session, node.id)
    if active:
        raise HTTPException(409, "у узла есть прогоны в очереди или в работе: "
                                 "остановите их или дождитесь завершения")
    name = node.name
    session.delete(node)
    audit.record(subject=user.subject, action="node_delete", target=f"node:{node_id}",
                 result="ok", details={"name": name})
    return Response(status_code=204)


# ---------------- протокол узла ----------------
def _runs(request: Request) -> RunService:
    return request.app.state.runs


def _mtls_check(request: Request, node: ScanNode) -> None:
    verify_h = os.environ.get("SCANNER_NODE_MTLS_VERIFY_HEADER")
    if not verify_h:
        return
    if request.headers.get(verify_h, "") != "SUCCESS":
        raise HTTPException(401, "нужен клиентский сертификат узла (mTLS)")
    fp_h = os.environ.get("SCANNER_NODE_MTLS_FINGERPRINT_HEADER")
    fp = (request.headers.get(fp_h, "") if fp_h else "").strip().lower()
    if not fp:
        return
    info = dict(node.info or {})
    pinned = info.get("cert_fingerprint")
    if pinned and pinned != fp:
        raise HTTPException(401, "сертификат узла не совпадает с закреплённым "
                                 "(перевыпустите токен, чтобы закрепить новый)")
    if not pinned:
        info["cert_fingerprint"] = fp
        node.info = info


class NodeCtx:
    def __init__(self, node: ScanNode, session: Session):
        self.node = node
        self.session = session


def current_node(request: Request,
                 creds: Annotated[HTTPAuthorizationCredentials | None, Depends(_bearer)],
                 session: SessionDep, audit: AuditDep) -> NodeCtx:
    token = creds.credentials if creds is not None else None
    node = nodes.authenticate(session, token)
    if node is None:
        audit.record(subject="node:unknown", action="node_auth", target=request.url.path,
                     result="denied",
                     details={"token_prefix": (token or "")[:len(nodes.TOKEN_PREFIX) + 4]
                              or None,
                              "ip": request.client.host if request.client else None})
        session.commit()
        raise HTTPException(401, "неверный токен узла", headers={"WWW-Authenticate": "Bearer"})
    _mtls_check(request, node)
    nodes.touch(node)
    return NodeCtx(node, session)


NodeDep = Annotated[NodeCtx, Depends(current_node)]
RunsDep = Annotated[RunService, Depends(_runs)]


def _subject(node: ScanNode) -> str:
    return f"node:{node.name}"


class HelloIn(BaseModel):
    hostname: str | None = Field(default=None, max_length=255)
    version: str | None = Field(default=None, max_length=64)
    allowlist: list[str] = Field(default_factory=list, max_length=nodes.MAX_SCOPE)
    platform: str | None = Field(default=None, max_length=300)
    python: str | None = Field(default=None, max_length=32)
    tools: dict[str, bool] = Field(default_factory=dict)


@router.post("/node/v1/hello")
def node_hello(body: HelloIn, ctx: NodeDep, audit: AuditDep, request: Request) -> dict:
    node = ctx.node
    try:
        local = nodes.clean_scope(body.allowlist)
    except nodes.NodeError as e:
        raise HTTPException(422, f"локальный allowlist узла: {e}") from e
    first = node.registered_at is None
    info = dict(node.info or {})
    info.update({"allowlist": local, "platform": body.platform, "python": body.python,
                 "tools": {str(k)[:32]: bool(v) for k, v in list(body.tools.items())[:20]},
                 "ip": request.client.host if request.client else None})
    nodes.touch(node, hostname=body.hostname, version=body.version, info=info,
                registered=first)
    audit.record(subject=_subject(node), action="node_register" if first else "node_hello",
                 target=f"node:{node.id}", result="ok",
                 details={"hostname": body.hostname, "version": body.version,
                          "local_allowlist": local, "ip": info.get("ip")})
    return {"node": {"id": node.id, "name": node.name, "scope": list(node.scope or []),
                     "allow_credentials": node.allow_credentials},
            "outside_local_allowlist": _outside(node), "poll_seconds": POLL_SECONDS}


@router.post("/node/v1/jobs/next")
def node_next_job(ctx: NodeDep, runs: RunsDep) -> dict:
    node = ctx.node
    run_id = nodes.next_pending_run(ctx.session, node.id)
    ctx.session.commit()        # отметка «на связи» и отпустить транзакцию
    if run_id is None:
        return {"job": None}
    job = runs.claim_for_node(run_id, node)
    return {"job": job}


def _node_run(session: Session, node: ScanNode, run_id: int) -> ScanRun:
    run = session.get(ScanRun, run_id)
    if run is None or run.node_id != node.id:
        raise HTTPException(404, "прогон не найден или назначен другому узлу")
    return run


class HeartbeatIn(BaseModel):
    progress: dict | None = None


@router.post("/node/v1/jobs/{run_id}/heartbeat")
def node_heartbeat(run_id: int, body: HeartbeatIn, ctx: NodeDep, runs: RunsDep) -> dict:
    _node_run(ctx.session, ctx.node, run_id)
    ctx.session.commit()
    progress = body.progress if body.progress is None or len(json.dumps(body.progress)) < 20000 \
        else None
    st = runs.node_heartbeat(run_id, ctx.node.id, progress)
    if st is None:
        raise HTTPException(404, "прогон не найден")
    if st not in ("running", "stopped"):
        raise HTTPException(409, f"прогон уже не выполняется (статус {st})")
    return {"status": st, "stop": st == "stopped"}


class EventsIn(BaseModel):
    events: list[dict] = Field(default_factory=list, max_length=500)


@router.post("/node/v1/jobs/{run_id}/events", status_code=204)
def node_events(run_id: int, body: EventsIn, ctx: NodeDep, request: Request) -> Response:
    _node_run(ctx.session, ctx.node, run_id)
    ctx.session.commit()
    out = []
    for e in body.events:
        try:
            out.append(ev.Event(kind=str(e["kind"])[:64], subject=str(e["subject"])[:200],
                                message=str(e["message"])[:1000],
                                host=(str(e["host"])[:64] if e.get("host") else None),
                                severity=(str(e["severity"])[:16] if e.get("severity")
                                          else None),
                                details=e.get("details") if isinstance(e.get("details"), dict)
                                else None))
        except (KeyError, TypeError):
            continue
    ev.safe_add(request.app.state.sessions, run_id, out)
    return Response(status_code=204)


async def _json_body(request: Request) -> Any:
    """Тело запроса (gzip допускается) с ограничением размера."""
    raw = bytearray()
    async for chunk in request.stream():
        raw.extend(chunk)
        if len(raw) > MAX_BODY:
            raise HTTPException(413, "результат больше допустимого "
                                     "(SCANNER_NODE_MAX_RESULT_MB)")
    data = bytes(raw)
    if request.headers.get("content-encoding", "").lower() == "gzip":
        d = zlib.decompressobj(16 + zlib.MAX_WBITS)
        try:
            data = d.decompress(data, MAX_BODY + 1)
        except zlib.error as e:
            raise HTTPException(400, "повреждённое сжатие gzip") from e
        if len(data) > MAX_BODY or d.unconsumed_tail:
            raise HTTPException(413, "результат больше допустимого после распаковки")
    try:
        return json.loads(data)
    except ValueError as e:
        raise HTTPException(400, "тело запроса — не JSON") from e


def _node_from_request(request: Request) -> ScanNode:
    """Аутентификация узла для async-обработчиков (своя короткая сессия)."""
    auth = request.headers.get("authorization", "")
    token = auth[7:].strip() if auth.lower().startswith("bearer ") else None
    with session_scope(request.app.state.sessions) as s:
        node = nodes.authenticate(s, token)
        if node is None:
            request.app.state.audit.record(subject="node:unknown", action="node_auth",
                                           target=request.url.path, result="denied")
            raise HTTPException(401, "неверный токен узла",
                                headers={"WWW-Authenticate": "Bearer"})
        _mtls_check(request, node)
        nodes.touch(node)
        s.flush()
        s.expunge(node)
    return node


@router.post("/node/v1/jobs/{run_id}/audit", status_code=204)
async def node_audit(run_id: int, request: Request) -> Response:
    node = _node_from_request(request)
    body = await _json_body(request)
    records = (body or {}).get("records") or []
    if not isinstance(records, list) or len(records) > 5000:
        raise HTTPException(422, "records: список до 5000 записей")
    with session_scope(request.app.state.sessions) as s:
        _node_run(s, node, run_id)
    sink: AuditSink = request.app.state.audit
    subj = _subject(node)
    for r in records:
        if not isinstance(r, dict):
            continue
        details = r.get("details")
        details = details if isinstance(details, dict) else (
            {"message": str(details)[:2000]} if details is not None else {})
        details = {**details, "node_id": node.id, "node_ts": r.get("ts")}
        orig = str(r.get("subject") or "scanner")[:100]
        sink.record(subject=subj if orig == "scanner" else f"{subj}:{orig}",
                    action=str(r.get("action") or "unknown")[:100],
                    target=str(r.get("target") or "")[:500],
                    result=str(r.get("result") or "")[:100], details=details)
    return Response(status_code=204)


class FailIn(BaseModel):
    error: str = Field(max_length=1000)


@router.post("/node/v1/jobs/{run_id}/fail")
def node_fail(run_id: int, body: FailIn, ctx: NodeDep, audit: AuditDep,
              request: Request, runs: RunsDep) -> dict:
    run = _node_run(ctx.session, ctx.node, run_id)
    if run.status not in ("running", "stopped"):
        raise HTTPException(409, f"прогон уже завершён (статус {run.status})")
    msg = f"Узел «{ctx.node.name}» не смог выполнить прогон: {body.error}"[:1000]
    from scanner.core import repository as repo
    repo.set_scan_run_status(ctx.session, run_id, "failed", error_message=msg)
    audit.record(subject=_subject(ctx.node), action="scan_finish",
                 target=f"scan_run:{run_id}", result="failed",
                 details={"error": body.error, "node_id": ctx.node.id})
    ctx.session.commit()
    ev.safe_add(request.app.state.sessions, run_id, [ev.run_finish("failed", message=msg)])
    runs._notify(run_id)
    return {"status": "failed"}


def filter_outcome(out: Any, allowed_nets: list[str]) -> dict[str, int]:
    """Убирает из результата узла данные по хостам вне allowlist договора ∩
    сетей узла: узел не может «дописать» в договор чужие адреса.
    -> {что: сколько отброшено}."""
    from scanner.core import coverage as cv
    from scanner.core.allowlist import AllowlistGate
    gate = AllowlistGate(allowed_nets)
    ok = gate.is_allowed
    dropped: dict[str, int] = {}

    def keep(name: str, items: list, host_of) -> list:
        kept = [x for x in items if ok(str(host_of(x)))]
        if len(kept) != len(items):
            dropped[name] = len(items) - len(kept)
        return kept

    out.findings = keep("findings", out.findings, lambda f: f.host)
    out.services = keep("services", out.services, lambda s: s.host)
    out.hosts = keep("hosts", out.hosts, lambda h: h.host)
    out.inventory = keep("inventory", out.inventory, lambda i: i.host)
    out.allowed = keep("allowed", out.allowed, lambda a: a)
    entries = keep("coverage", out.coverage.entries(), lambda e: e.host)
    out.coverage = cv.Coverage(entries)
    facts = {h: v for h, v in out.compliance_facts.items() if ok(h)}
    if len(facts) != len(out.compliance_facts):
        dropped["compliance_facts"] = len(out.compliance_facts) - len(facts)
    out.compliance_facts = facts
    out.warnings = [w for w in out.warnings if not w.get("host") or ok(str(w["host"]))]
    return dropped


@router.post("/node/v1/jobs/{run_id}/result")
async def node_result(run_id: int, request: Request) -> dict:
    node = _node_from_request(request)
    body = await _json_body(request)
    try:
        rid, out = decode_outcome(body)
    except CodecError as e:
        raise HTTPException(422, f"результат узла не разобран: {e}") from e
    if rid != run_id:
        raise HTTPException(422, "номер прогона в результате не совпадает с адресом")
    runs: RunService = request.app.state.runs
    audit: AuditSink = request.app.state.audit
    from scanner.core import repository as repo
    from scanner.nodes.jobs import node_gate
    with session_scope(request.app.state.sessions) as s:
        run = _node_run(s, node, run_id)
        # interrupted — центр не слышал узел дольше порога, но результат дошёл:
        # сохраняем, данные дороже статуса
        if run.status not in ("running", "stopped", "interrupted"):
            raise HTTPException(409, f"прогон уже завершён (статус {run.status})")
        if run.status == "interrupted":
            repo.set_scan_run_status(s, run_id, "running")
        contract = repo.load_allowlist_gate(s, run.engagement_id).networks
        scope = list(s.get(ScanNode, node.id).scope or [])
    _, nets = node_gate(contract, scope)
    dropped = filter_outcome(out, nets)
    if dropped:
        audit.record(subject=_subject(node), action="node_result_filtered",
                     target=f"scan_run:{run_id}", result="dropped",
                     details={"dropped": dropped, "node_id": node.id})
    audit.record(subject=_subject(node), action="node_result", target=f"scan_run:{run_id}",
                 result="received",
                 details={"node_id": node.id, "findings": len(out.findings),
                          "hosts": len(out.allowed)})
    import anyio
    final = await anyio.to_thread.run_sync(runs.persist_outcome, run_id, out)
    return {"status": final}


@router.get("/node/v1/nuclei-templates")
def node_templates(ctx: NodeDep, request: Request) -> Response:
    """Шаблоны Nuclei центра одним архивом (ETag — отпечаток каталога)."""
    from fastapi.responses import FileResponse

    from scanner.feeds.sources import nuclei_templates_dir
    from scanner.nodes.templates import build_archive
    ctx.session.commit()
    built = build_archive(nuclei_templates_dir())
    if built is None:
        raise HTTPException(404, "в центре нет шаблонов Nuclei")
    path, etag = built
    if request.headers.get("if-none-match", "").strip('"') == etag:
        return Response(status_code=304, headers={"ETag": f'"{etag}"'})
    return FileResponse(path, media_type="application/gzip", headers={"ETag": f'"{etag}"'},
                        filename="nuclei-templates.tar.gz")


class ReferenceIn(BaseModel):
    store: str = Field(max_length=32)
    method: str = Field(max_length=64)
    args: list[Any] = Field(default_factory=list, max_length=4)


@router.post("/node/v1/reference")
def node_reference(body: ReferenceIn, ctx: NodeDep, request: Request) -> dict:
    from scanner.nodes.reference import ReferenceError, ReferenceService
    ctx.session.commit()
    svc = getattr(request.app.state, "node_reference", None)
    if svc is None:
        engine = request.app.state.sessions.kw.get("bind")
        svc = request.app.state.node_reference = ReferenceService(engine)
    try:
        return {"result": svc.call(body.store, body.method, body.args)}
    except ReferenceError as e:
        raise HTTPException(422, str(e)) from e

