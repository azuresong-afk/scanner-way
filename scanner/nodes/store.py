"""Узлы-сканеры в БД центра: заведение, токены, статус «на связи».

Токен узла показывается один раз при заведении (или перевыпуске); в БД
хранится только его SHA-256 и первые символы — по ним администратор опознаёт
токен в списке. Узел предъявляет токен в заголовке Authorization: Bearer.
"""
from __future__ import annotations

import hashlib
import ipaddress
import secrets
from collections.abc import Iterable
from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from scanner.core.db import ScanNode, ScanRun
from scanner.core.targetspec import parse_target

MODE_ONLINE = "online"
MODE_OFFLINE = "offline"
MODES = (MODE_ONLINE, MODE_OFFLINE)
TOKEN_PREFIX = "snode_"
# Узел опрашивает центр каждые несколько секунд; дольше этого молчит — «нет связи».
ONLINE_SECONDS = 90
MAX_SCOPE = 256

STATUS_ONLINE = "online"        # на связи
STATUS_OFFLINE = "offline"      # не выходил на связь дольше ONLINE_SECONDS
STATUS_NEVER = "never"          # ещё ни разу не подключался
STATUS_DISABLED = "disabled"    # отключён администратором
STATUS_AUTONOMOUS = "autonomous"  # автономный узел: обмен файлами


class NodeError(ValueError):
    """Понятная администратору причина отказа (API отдаёт её как 422)."""


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def new_token() -> str:
    return TOKEN_PREFIX + secrets.token_urlsafe(32)


def clean_scope(specs: Iterable[str]) -> list[str]:
    """Сети узла: адреса, подсети и диапазоны (как в allowlist). Пустой список
    не допускается — узел без сетей не смог бы проверить ни одного адреса."""
    out: list[str] = []
    for raw in specs or []:
        spec = str(raw).strip()
        if not spec:
            continue
        try:
            t = parse_target(spec)
        except ValueError as e:
            raise NodeError(f"сеть узла «{spec}»: {e}") from e
        if t.text not in out:
            out.append(t.text)
    if not out:
        raise NodeError("укажите хотя бы одну сеть сегмента, где стоит узел")
    if len(out) > MAX_SCOPE:
        raise NodeError(f"слишком много сетей узла (больше {MAX_SCOPE})")
    return out


def scope_networks(scope: Iterable[str]) -> list[str]:
    """Сети узла в виде CIDR (диапазоны раскладываются в подсети)."""
    nets: list[str] = []
    for spec in scope or []:
        try:
            nets.extend(str(n) for n in parse_target(spec).networks)
        except ValueError:
            continue
    return nets


def intersect_networks(a: Iterable[str], b: Iterable[str]) -> list[str]:
    """Пересечение двух наборов подсетей: подсети либо вложены, либо не
    пересекаются, поэтому пересечение пары — меньшая из двух."""
    left = [ipaddress.ip_network(x, strict=False) for x in a]
    right = [ipaddress.ip_network(x, strict=False) for x in b]
    out: list[str] = []
    for x in left:
        for y in right:
            if x.version != y.version or not x.overlaps(y):
                continue
            n = str(x if x.prefixlen >= y.prefixlen else y)
            if n not in out:
                out.append(n)
    return out


def node_status(node: ScanNode, now: datetime | None = None) -> str:
    if not node.enabled:
        return STATUS_DISABLED
    if node.mode == MODE_OFFLINE:
        return STATUS_AUTONOMOUS
    if node.last_seen_at is None:
        return STATUS_NEVER
    now = now or datetime.now(UTC)
    seen = node.last_seen_at if node.last_seen_at.tzinfo else \
        node.last_seen_at.replace(tzinfo=UTC)
    return STATUS_ONLINE if now - seen <= timedelta(seconds=ONLINE_SECONDS) else \
        STATUS_OFFLINE


def _clean_name(name: str) -> str:
    name = " ".join(str(name or "").split())
    if not name:
        raise NodeError("укажите имя узла")
    if len(name) > 100:
        raise NodeError("имя узла длиннее 100 символов")
    return name


def create_node(session: Session, *, name: str, scope: Iterable[str],
                description: str | None = None, mode: str = MODE_ONLINE,
                allow_credentials: bool = True,
                created_by: int | None = None) -> tuple[ScanNode, str | None]:
    """Завести узел. -> (узел, токен). Токен — только у сетевого узла и
    только здесь: в БД остаётся его хэш."""
    if mode not in MODES:
        raise NodeError(f"неизвестный режим узла: {mode}")
    name = _clean_name(name)
    if session.scalar(select(ScanNode.id).where(ScanNode.name == name)) is not None:
        raise NodeError(f"узел «{name}» уже есть")
    token = new_token() if mode == MODE_ONLINE else None
    node = ScanNode(name=name, description=(description or "").strip()[:500] or None,
                    mode=mode, scope=clean_scope(scope),
                    allow_credentials=bool(allow_credentials), enabled=True,
                    token_hash=hash_token(token) if token else None,
                    token_prefix=token[:len(TOKEN_PREFIX) + 4] if token else None,
                    info={}, created_by=created_by)
    session.add(node)
    session.flush()
    return node, token


def update_node(session: Session, node: ScanNode, *, name: str | None = None,
                description: str | None = None, scope: Iterable[str] | None = None,
                allow_credentials: bool | None = None,
                enabled: bool | None = None) -> ScanNode:
    if name is not None:
        name = _clean_name(name)
        other = session.scalar(select(ScanNode.id).where(ScanNode.name == name,
                                                         ScanNode.id != node.id))
        if other is not None:
            raise NodeError(f"узел «{name}» уже есть")
        node.name = name
    if description is not None:
        node.description = description.strip()[:500] or None
    if scope is not None:
        node.scope = clean_scope(scope)
    if allow_credentials is not None:
        node.allow_credentials = bool(allow_credentials)
    if enabled is not None:
        node.enabled = bool(enabled)
    session.flush()
    return node


def rotate_token(session: Session, node: ScanNode) -> str:
    """Новый токен; прежний перестаёт действовать сразу."""
    if node.mode != MODE_ONLINE:
        raise NodeError("у автономного узла нет токена: он обменивается файлами")
    token = new_token()
    node.token_hash = hash_token(token)
    node.token_prefix = token[:len(TOKEN_PREFIX) + 4]
    session.flush()
    return token


def authenticate(session: Session, token: str | None) -> ScanNode | None:
    """Сетевой включённый узел по токену; иначе None."""
    if not token or not token.startswith(TOKEN_PREFIX) or len(token) > 200:
        return None
    node = session.scalar(select(ScanNode).where(ScanNode.token_hash == hash_token(token)))
    if node is None or not node.enabled or node.mode != MODE_ONLINE:
        return None
    # хэш уже совпал по индексу; сравнение постоянного времени — от утечек по времени
    if not secrets.compare_digest(node.token_hash or "", hash_token(token)):
        return None
    return node


def touch(node: ScanNode, *, hostname: str | None = None, version: str | None = None,
          info: dict | None = None, registered: bool = False) -> None:
    now = datetime.now(UTC)
    node.last_seen_at = now
    if registered:
        node.registered_at = now
    if hostname is not None:
        node.hostname = str(hostname)[:255]
    if version is not None:
        node.version = str(version)[:64]
    if info is not None:
        node.info = info


def get_node(session: Session, node_id: int) -> ScanNode | None:
    return session.get(ScanNode, node_id)


def list_nodes(session: Session) -> list[ScanNode]:
    return list(session.scalars(select(ScanNode).order_by(ScanNode.name)))


def active_runs(session: Session, node_id: int) -> list[ScanRun]:
    return list(session.scalars(
        select(ScanRun).where(ScanRun.node_id == node_id,
                              ScanRun.status.in_(("pending", "running")))
        .order_by(ScanRun.id)))


def next_pending_run(session: Session, node_id: int) -> int | None:
    return session.scalar(
        select(ScanRun.id).where(ScanRun.node_id == node_id, ScanRun.status == "pending")
        .order_by(ScanRun.id).limit(1))


def node_worker_id(node_id: int, boot: str) -> str:
    """worker_id прогона на узле: «node-<id>:0:<метка>» — сторож центра судит
    о нём только по давности отметки «жив» (хост не совпадает с центром)."""
    return f"node-{node_id}:0:{boot}"
