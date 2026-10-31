"""Каналы уведомлений (почта, Telegram, syslog/CEF, Jira) и журнал доставки.

Просмотр — право view_engagements; создание, изменение, удаление, проверочная
отправка и повтор — manage_engagements. Секреты каналов принимаются на вход и сразу
шифруются; ни один ответ API, ни запись аудита, ни журнал доставки их не содержат.
"""
from __future__ import annotations

from datetime import datetime
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response, status
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select

from scanner.api.deps import AuditDep, Principal, SessionDep, require
from scanner.api.rbac import Perm
from scanner.core.db import IntegrationChannelRow, NotificationLogRow
from scanner.integrations.base import ChannelConfigError
from scanner.integrations.channels import CHANNELS
from scanner.integrations.dispatcher import Dispatcher
from scanner.integrations.events import EVENTS, PRIORITIES, SEVERITIES, Filters

router = APIRouter(prefix="/integrations", tags=["integrations"])

Viewer = Annotated[Principal, Depends(require(Perm.VIEW_ENGAGEMENTS))]
Manager = Annotated[Principal, Depends(require(Perm.MANAGE_ENGAGEMENTS))]


def _dispatcher(request: Request) -> Dispatcher:
    return request.app.state.notifier


Notifier = Annotated[Dispatcher, Depends(_dispatcher)]


class FiltersIO(BaseModel):
    min_severity: str | None = None
    min_priority: str | None = None
    groups: list[str] = Field(default_factory=list, max_length=50)
    owners: list[str] = Field(default_factory=list, max_length=50)
    engagements: list[int] = Field(default_factory=list, max_length=50)


class ChannelIn(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    type: str
    enabled: bool = True
    config: dict[str, Any] = Field(default_factory=dict)
    secrets: dict[str, str] = Field(default_factory=dict)
    events: list[str] = Field(default_factory=lambda: list(EVENTS))
    filters: FiltersIO = Field(default_factory=FiltersIO)


class ChannelUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=100)
    enabled: bool | None = None
    config: dict[str, Any] | None = None
    secrets: dict[str, str] | None = None      # заданные ключи заменяют, прочие остаются
    events: list[str] | None = None
    filters: FiltersIO | None = None


class ChannelOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    name: str
    type: str
    enabled: bool
    config: dict[str, Any]
    events: list[str]
    filters: FiltersIO
    has_secret: bool
    created_at: datetime
    updated_at: datetime


class ChannelTypeOut(BaseModel):
    type: str
    title: str
    events: list[str]
    secret_fields: list[str]


class LogOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    channel_id: int
    channel_name: str | None = None
    event: str
    status: str
    attempts: int
    next_attempt_at: datetime | None
    last_error: str | None
    engagement_id: int | None
    scan_run_id: int | None
    external_ref: str | None
    summary: str = ""
    created_at: datetime
    sent_at: datetime | None


def _out(row: IntegrationChannelRow) -> ChannelOut:
    return ChannelOut(
        id=row.id, name=row.name, type=row.type, enabled=row.enabled,
        config=dict(row.config or {}), events=list(row.events or []),
        filters=FiltersIO(**Filters.from_dict(row.filters).to_dict()),
        has_secret=bool(row.secret_enc), created_at=row.created_at,
        updated_at=row.updated_at)


def _log_out(row: NotificationLogRow, names: dict[int, str]) -> LogOut:
    p = row.payload or {}
    n = len(p.get("items") or []) + int(p.get("items_omitted") or 0)
    summary = p.get("title") or ""
    if row.event == "new_critical":
        summary = f"{summary}: находок {n}" if summary else f"находок: {n}"
    return LogOut(
        id=row.id, channel_id=row.channel_id, channel_name=names.get(row.channel_id),
        event=row.event, status=row.status, attempts=row.attempts,
        next_attempt_at=row.next_attempt_at, last_error=row.last_error,
        engagement_id=row.engagement_id, scan_run_id=row.scan_run_id,
        external_ref=row.external_ref, summary=summary[:200],
        created_at=row.created_at, sent_at=row.sent_at)


def _filters(f: FiltersIO) -> dict[str, Any]:
    if f.min_severity and f.min_severity not in SEVERITIES:
        raise HTTPException(422, f"min_severity: одно из {', '.join(SEVERITIES)}")
    if f.min_priority and f.min_priority not in PRIORITIES:
        raise HTTPException(422, f"min_priority: одно из {', '.join(PRIORITIES)}")
    clean = Filters(min_severity=f.min_severity or None, min_priority=f.min_priority or None,
                    groups=sorted({g.strip() for g in f.groups if g.strip()}),
                    owners=sorted({o.strip() for o in f.owners if o.strip()}),
                    engagements=sorted(set(f.engagements)))
    return clean.to_dict()


def _events(kind: str, events: list[str]) -> list[str]:
    impl = CHANNELS[kind]
    bad = [e for e in events if e not in EVENTS]
    if bad:
        raise HTTPException(422, f"неизвестные события: {', '.join(bad)}")
    unsupported = [e for e in events if e not in impl.supported_events]
    if unsupported:
        raise HTTPException(422, f"канал «{impl.title}» не поддерживает события: "
                                 f"{', '.join(unsupported)}")
    return sorted(set(events), key=EVENTS.index)


def _vault(request: Request):
    vault = request.app.state.runs.vault
    if vault is None:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, {
            "code": "credentials_key_missing",
            "message": "не задан ключ шифрования секретов: "
                       "SCANNER_CREDENTIALS_KEY (или SCANNER_API_SECRET) в .env"})
    return vault


def _names(session) -> dict[int, str]:
    return {i: n for i, n in session.execute(
        select(IntegrationChannelRow.id, IntegrationChannelRow.name))}


def _get(session, channel_id: int) -> IntegrationChannelRow:
    row = session.get(IntegrationChannelRow, channel_id)
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "channel not found")
    return row


def _audit_details(row: IntegrationChannelRow) -> dict[str, Any]:
    return {"channel_id": row.id, "name": row.name, "type": row.type,
            "enabled": row.enabled, "events": list(row.events or []),
            "filters": row.filters, "has_secret": bool(row.secret_enc)}


@router.get("/types", response_model=list[ChannelTypeOut])
def channel_types(_: Viewer) -> list[ChannelTypeOut]:
    return [ChannelTypeOut(type=c.type, title=c.title,
                           events=[e for e in EVENTS if e in c.supported_events],
                           secret_fields=list(c.secret_fields))
            for c in CHANNELS.values()]


@router.get("/channels", response_model=list[ChannelOut])
def list_channels(_: Viewer, session: SessionDep) -> list[ChannelOut]:
    return [_out(r) for r in session.scalars(
        select(IntegrationChannelRow).order_by(IntegrationChannelRow.id))]


@router.post("/channels", response_model=ChannelOut, status_code=201)
def create_channel(body: ChannelIn, request: Request, user: Manager, session: SessionDep,
                   audit: AuditDep) -> ChannelOut:
    impl = CHANNELS.get(body.type)
    if impl is None:
        raise HTTPException(422, f"неизвестный тип канала: {body.type}")
    secrets = {k: v for k, v in body.secrets.items() if k in impl.secret_fields and v}
    try:
        config = impl.validate(body.config)
        impl.validate_secrets(secrets, config)
    except ChannelConfigError as e:
        audit.record(subject=user.subject, action="channel_create", target="integrations",
                     result="rejected",
                     details={"name": body.name, "type": body.type, "reason": str(e)[:300]})
        raise HTTPException(422, str(e)) from e
    row = IntegrationChannelRow(
        name=body.name.strip(), type=body.type, enabled=body.enabled, config=config,
        secret_enc=_vault(request).encrypt(secrets) if secrets else None,
        events=_events(body.type, body.events), filters=_filters(body.filters),
        created_by=user.id)
    session.add(row)
    session.commit()
    audit.record(subject=user.subject, action="channel_create",
                 target=f"channel:{row.id}", result="ok", details=_audit_details(row))
    return _out(row)


@router.patch("/channels/{channel_id}", response_model=ChannelOut)
def update_channel(channel_id: int, body: ChannelUpdate, request: Request, user: Manager,
                   session: SessionDep, audit: AuditDep) -> ChannelOut:
    row = _get(session, channel_id)
    impl = CHANNELS[row.type]
    try:
        config = impl.validate(body.config) if body.config is not None else dict(row.config)
        new_secrets = {k: v for k, v in (body.secrets or {}).items()
                       if k in impl.secret_fields and v}
        if new_secrets or body.config is not None:
            vault = _vault(request)
            current = vault.decrypt(row.secret_enc) if row.secret_enc else {}
            merged = {**current, **new_secrets}
            impl.validate_secrets(merged, config)
            if new_secrets:
                row.secret_enc = vault.encrypt(merged)
            del current, merged
    except ChannelConfigError as e:
        audit.record(subject=user.subject, action="channel_update",
                     target=f"channel:{channel_id}", result="rejected",
                     details={"reason": str(e)[:300]})
        raise HTTPException(422, str(e)) from e
    row.config = config
    if body.name is not None:
        row.name = body.name.strip()
    if body.enabled is not None:
        row.enabled = body.enabled
    if body.events is not None:
        row.events = _events(row.type, body.events)
    if body.filters is not None:
        row.filters = _filters(body.filters)
    row.updated_at = datetime.now(row.created_at.tzinfo) if row.created_at else datetime.now()
    session.commit()
    audit.record(subject=user.subject, action="channel_update",
                 target=f"channel:{row.id}", result="ok",
                 details={**_audit_details(row), "secrets_replaced": bool(body.secrets)})
    return _out(row)


@router.delete("/channels/{channel_id}", status_code=204)
def delete_channel(channel_id: int, user: Manager, session: SessionDep,
                   audit: AuditDep) -> Response:
    row = _get(session, channel_id)
    details = _audit_details(row)
    session.delete(row)
    session.commit()
    audit.record(subject=user.subject, action="channel_delete",
                 target=f"channel:{channel_id}", result="ok", details=details)
    return Response(status_code=204)


@router.post("/channels/{channel_id}/test", response_model=LogOut)
def test_channel(channel_id: int, user: Manager, session: SessionDep, notifier: Notifier,
                 audit: AuditDep) -> LogOut:
    row = _get(session, channel_id)
    name = row.name
    log = notifier.send_test(channel_id, user.subject)
    audit.record(subject=user.subject, action="channel_test",
                 target=f"channel:{channel_id}", result=log.status,
                 details={"name": name, "log_id": log.id, "error": log.last_error})
    return _log_out(log, {channel_id: name})


@router.get("/log", response_model=list[LogOut])
def delivery_log(_: Viewer, session: SessionDep,
                 channel_id: int | None = None,
                 status_: Annotated[str | None, Query(alias="status")] = None,
                 limit: Annotated[int, Query(ge=1, le=500)] = 100) -> list[LogOut]:
    q = select(NotificationLogRow).order_by(NotificationLogRow.id.desc()).limit(limit)
    if channel_id is not None:
        q = q.where(NotificationLogRow.channel_id == channel_id)
    if status_:
        q = q.where(NotificationLogRow.status == status_)
    rows = list(session.scalars(q))
    names = _names(session)
    return [_log_out(r, names) for r in rows]


@router.post("/log/{log_id}/retry", response_model=LogOut)
def retry_delivery(log_id: int, user: Manager, session: SessionDep, notifier: Notifier,
                   audit: AuditDep) -> LogOut:
    try:
        notifier.retry(log_id)
    except LookupError:
        raise HTTPException(status.HTTP_404_NOT_FOUND,
                            "delivery not found or not in failed state") from None
    session.expire_all()
    row = session.get(NotificationLogRow, log_id)
    audit.record(subject=user.subject, action="notification_retry",
                 target=f"channel:{row.channel_id}", result=row.status,
                 details={"log_id": log_id})
    names = _names(session)
    return _log_out(row, names)
