"""Автономный режим узлов-сканеров: ключ центра, ключ узла, задание и результат.

    GET  /offline/center-key              открытый ключ центра (center.pub)
    GET  /nodes/{id}/public-key           ключ автономного узла и его отпечаток
    PUT  /nodes/{id}/public-key           загрузить node.pub с узла
    GET  /nodes/{id}/offline-jobs         задания узла
    GET  /runs/{id}/offline               задание прогона (статус)
    POST /runs/{id}/offline/export        «Выгрузить задание» -> файл .scnjob
    GET  /runs/{id}/offline/job           скачать выгруженное задание ещё раз
    POST /runs/{id}/offline/cancel        отменить задание (прогон -> остановлен)
    POST /offline/results/preview         заголовок файла результата (без загрузки)
    POST /offline/results                 «Загрузить результат» (тело — файл .scnres)
"""
from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from pydantic import BaseModel, Field
from sqlalchemy import select

from scanner.api.deps import AuditDep, Principal, SessionDep, deny, require
from scanner.api.rbac import MODULE_PERMISSIONS, Perm
from scanner.api.settings import ApiSettings
from scanner.core import repository as repo
from scanner.core.db import OfflineJobRow, ScanNode
from scanner.nodes import offline_center as oc
from scanner.nodes import offline_files as of

router = APIRouter(tags=["offline"])

# Право на управление узлами: то же, что у раздела «Сканеры».
NODE_ADMIN = Perm.MANAGE_ENGAGEMENTS


class NodeKeyIn(BaseModel):
    public_key: str = Field(min_length=10, max_length=4096)


def _keys(request: Request):
    keys = getattr(request.app.state, "offline_keys", None)
    if keys is not None:
        return keys
    try:
        keys = oc.center_keys(oc.center_material(ApiSettings()))
    except oc.OfflineError as e:
        raise HTTPException(409, {"code": e.code, "message": str(e)}) from e
    request.app.state.offline_keys = keys
    return keys


def _fail(e: oc.OfflineError) -> HTTPException:
    return HTTPException(e.status, {"code": e.code, "message": str(e)})


def _node(session, node_id: int) -> ScanNode:
    node = session.get(ScanNode, node_id)
    if node is None:
        raise HTTPException(404, "node not found")
    return node


def _download(name: str, data: bytes) -> Response:
    from urllib.parse import quote
    ascii_name = name.encode("ascii", "replace").decode().replace("?", "_")
    return Response(content=data, media_type="application/octet-stream", headers={
        "Content-Disposition": f"attachment; filename=\"{ascii_name}\"; "
                               f"filename*=UTF-8''{quote(name)}",
        "Cache-Control": "no-store"})


@router.get("/offline/center-key")
def center_key(request: Request,
               _: Annotated[Principal, Depends(require(Perm.VIEW_ENGAGEMENTS))],
               format: Annotated[str, Query(pattern="^(json|file)$")] = "json"):
    """Открытый ключ центра: ставится на автономный узел при установке
    (`scanner node init --center-key center.pub`). Отпечаток сверяют на узле."""
    pub = _keys(request).public
    if format == "file":
        text = (f"# Открытый ключ центра сканера. Отпечаток: {pub.fingerprint}\n"
                f"{pub.export()}\n")
        return _download("center.pub", text.encode("utf-8"))
    return {"public_key": pub.export(), "fingerprint": pub.fingerprint}


@router.get("/nodes/{node_id}/public-key")
def read_node_key(node_id: int, session: SessionDep,
                  _: Annotated[Principal, Depends(require(Perm.VIEW_ENGAGEMENTS))]) -> dict:
    node = _node(session, node_id)
    if not node.public_key:
        return {"public_key": None, "fingerprint": None}
    try:
        pub = oc.node_public(node)
    except oc.OfflineError as e:
        raise _fail(e) from e
    return {"public_key": pub.export(), "fingerprint": pub.fingerprint}


@router.put("/nodes/{node_id}/public-key")
def set_node_key(node_id: int, body: NodeKeyIn, session: SessionDep, audit: AuditDep,
                 user: Annotated[Principal, Depends(require(NODE_ADMIN))]) -> dict:
    node = _node(session, node_id)
    before = node.public_key
    try:
        pub = oc.set_node_key(session, node, body.public_key)
    except oc.OfflineError as e:
        raise _fail(e) from e
    session.commit()
    audit.record(subject=user.subject, action="node_key_set", target=f"node:{node_id}",
                 result="ok", details={"node": node.name, "fingerprint": pub.fingerprint,
                                       "replaced": bool(before)})
    return {"public_key": pub.export(), "fingerprint": pub.fingerprint}


@router.get("/nodes/{node_id}/offline-jobs")
def node_jobs(node_id: int, session: SessionDep,
              _: Annotated[Principal, Depends(require(Perm.VIEW_REPORT))],
              limit: Annotated[int, Query(ge=1, le=200)] = 50) -> list[dict]:
    node = _node(session, node_id)
    rows = session.scalars(select(OfflineJobRow).where(OfflineJobRow.node_id == node_id)
                           .order_by(OfflineJobRow.exported_at.desc()).limit(limit)).all()
    return [oc.job_out(r, node.name) for r in rows]


@router.get("/runs/{run_id}/offline")
def run_job(run_id: int, session: SessionDep,
            _: Annotated[Principal, Depends(require(Perm.VIEW_REPORT))]) -> dict:
    row = session.scalar(select(OfflineJobRow).where(OfflineJobRow.run_id == run_id))
    if row is None:
        raise HTTPException(404, "offline job not found")
    node = session.get(ScanNode, row.node_id) if row.node_id else None
    return oc.job_out(row, node.name if node else None)


def _check_run_rights(session, run_id: int, user: Principal, request: Request,
                      audit) -> None:
    """Задание несёт учётки и наборы проверки — те же права, что и на запуск."""
    run = repo.get_scan_run(session, run_id)
    if run is None:
        raise HTTPException(404, "scan run not found")
    need = {MODULE_PERMISSIONS[m] for m in run.modules or [] if m in MODULE_PERMISSIONS}
    if run.credential_ids:
        need.add(Perm.HOST_CREDENTIALS)
    if run.cred_set_ids:
        need.add(Perm.CRED_AUDIT)
    missing = [p.value for p in sorted(need) if not user.has(p)]
    if missing:
        deny(audit, user, request, missing)


@router.post("/runs/{run_id}/offline/export")
def export_job(run_id: int, request: Request, session: SessionDep, audit: AuditDep,
               user: Annotated[Principal, Depends(require(Perm.RUN_SCAN))],
               valid_days: Annotated[int, Query(ge=1, le=oc.MAX_VALID_DAYS)]
               = oc.DEFAULT_VALID_DAYS) -> Response:
    """«Выгрузить задание»: прогон в очереди на автономном узле -> подписанный
    файл задания (учётки зашифрованы на ключ узла). Прогон переходит в
    «Выполняется» и ждёт загрузки результата."""
    _check_run_rights(session, run_id, user, request, audit)
    keys = _keys(request)
    session.commit()
    try:
        job = oc.export_job(request.app.state.sessions, request.app.state.runs, audit,
                            run_id=run_id, actor=user.subject, keys=keys,
                            valid_days=valid_days)
    except oc.OfflineError as e:
        raise _fail(e) from e
    return _download(job.filename, job.data)


@router.get("/runs/{run_id}/offline/job")
def download_job(run_id: int, request: Request, session: SessionDep, audit: AuditDep,
                 user: Annotated[Principal, Depends(require(Perm.RUN_SCAN))]) -> Response:
    _check_run_rights(session, run_id, user, request, audit)
    try:
        name, data = oc.job_file(session, run_id)
    except oc.OfflineError as e:
        raise _fail(e) from e
    audit.record(subject=user.subject, action="offline_job_download",
                 target=f"scan_run:{run_id}", result="ok")
    return _download(name, data)


@router.post("/runs/{run_id}/offline/cancel")
def cancel_job(run_id: int, request: Request, session: SessionDep, audit: AuditDep,
               user: Annotated[Principal, Depends(require(Perm.RUN_SCAN))]) -> dict:
    """Задание потеряно или больше не нужно: результат по нему не примется."""
    if repo.get_scan_run(session, run_id) is None:
        raise HTTPException(404, "scan run not found")
    session.commit()
    try:
        oc.cancel_job(request.app.state.sessions, request.app.state.runs, audit,
                      run_id=run_id, actor=user.subject)
    except oc.OfflineError as e:
        raise _fail(e) from e
    return {"run_id": run_id, "status": oc.STATUS_CANCELLED}


async def _body(request: Request) -> bytes:
    chunks, size = [], 0
    async for chunk in request.stream():
        size += len(chunk)
        if size > of.MAX_FILE_BYTES:
            raise HTTPException(413, f"файл больше {of.MAX_FILE_BYTES // (1024 * 1024)} МБ")
        chunks.append(chunk)
    if not size:
        raise HTTPException(422, "пустой файл")
    return b"".join(chunks)


@router.post("/offline/results/preview")
async def preview_result(request: Request,
                         _: Annotated[Principal, Depends(require(Perm.RUN_SCAN))]) -> dict:
    """Открытый заголовок файла результата — что за прогон и узел, до загрузки."""
    try:
        return oc.inspect_result(await _body(request))
    except oc.OfflineError as e:
        raise _fail(e) from e


@router.post("/offline/results")
async def import_result(request: Request, session: SessionDep, audit: AuditDep,
                        user: Annotated[Principal, Depends(require(Perm.RUN_SCAN))]) -> dict:
    """«Загрузить результат»: тело — файл .scnres с автономного узла
    (application/octet-stream). Подпись узла, привязка к заданию и allowlist
    договора проверяются до сохранения; затем — как у обычного прогона:
    находки, сравнение с прошлым прогоном, «Активы», уведомления."""
    data = await _body(request)
    keys = _keys(request)
    session.commit()
    try:
        return oc.import_result(request.app.state.sessions, request.app.state.runs, audit,
                                data=data, actor=user.subject, keys=keys)
    except oc.OfflineError as e:
        raise _fail(e) from e
