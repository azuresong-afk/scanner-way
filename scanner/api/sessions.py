"""Сеансы входа (таблица auth_sessions, миграция 0030).

Каждый вход создаёт сеанс; токен доступа несёт его id (sid). API принимает
токен, только пока сеанс жив:

* не отозван — выход (POST /auth/logout), «завершить сеанс» в профиле,
  администратор заблокировал пользователя, сменил ему пароль, сбросил 2FA;
* не истёк предельный срок сеанса (SCANNER_API_SESSION_MAX_HOURS).

Продление (POST /auth/refresh): по ещё действующему токену выдаётся новый
токен того же сеанса на SCANNER_API_TOKEN_TTL_MINUTES, но не дальше
предельного срока. Интерфейс продлевает токен, только пока пользователь
что-то делает, поэтому срок токена — это и время бездействия до выхода.
"""
from __future__ import annotations

import secrets
from datetime import UTC, datetime, timedelta

from sqlalchemy import delete, or_, select, update
from sqlalchemy.orm import Session

from scanner.core.db import AuthSessionRow

# Отозванные и истёкшие сеансы хранятся столько дней (видно в профиле и для
# разборов), потом удаляются при очередном входе.
KEEP_DAYS = 30
_UA_MAX = 300


def _now() -> datetime:
    return datetime.now(UTC)


def _aware(ts: datetime | None) -> datetime | None:
    # SQLite (тесты) возвращает наивное время — считаем его UTC.
    if ts is not None and ts.tzinfo is None:
        return ts.replace(tzinfo=UTC)
    return ts


def create(db: Session, user_id: int, *, max_hours: int, method: str | None,
           client: str | None, user_agent: str | None) -> AuthSessionRow:
    now = _now()
    row = AuthSessionRow(
        id=secrets.token_urlsafe(18), user_id=user_id, created_at=now, last_seen_at=now,
        expires_at=now + timedelta(hours=max_hours) if max_hours > 0 else None,
        method=method, client=client,
        user_agent=(user_agent or "")[:_UA_MAX] or None)
    db.add(row)
    _cleanup(db, now)
    db.flush()
    return row


def _cleanup(db: Session, now: datetime) -> None:
    edge = now - timedelta(days=KEEP_DAYS)
    db.execute(delete(AuthSessionRow).where(or_(
        AuthSessionRow.revoked_at < edge, AuthSessionRow.expires_at < edge,
        AuthSessionRow.last_seen_at < edge)))


def alive(row: AuthSessionRow | None, user_id: int, now: datetime | None = None) -> bool:
    if row is None or row.user_id != user_id or row.revoked_at is not None:
        return False
    exp = _aware(row.expires_at)
    return exp is None or exp > (now or _now())


def get_alive(db: Session, sid: str | None, user_id: int) -> AuthSessionRow | None:
    if not sid:
        return None
    row = db.get(AuthSessionRow, sid)
    return row if alive(row, user_id) else None


def not_after(row: AuthSessionRow) -> int | None:
    """Предельный срок сеанса как unix-время (для TokenSigner.issue)."""
    exp = _aware(row.expires_at)
    return int(exp.timestamp()) if exp is not None else None


def touch(row: AuthSessionRow) -> None:
    row.last_seen_at = _now()


def revoke(db: Session, row: AuthSessionRow, reason: str) -> None:
    if row.revoked_at is None:
        row.revoked_at = _now()
        row.revoked_reason = reason


def revoke_user(db: Session, user_id: int, reason: str, *,
                keep: str | None = None) -> int:
    """Отозвать все живые сеансы пользователя (кроме keep). Возвращает число."""
    q = (update(AuthSessionRow)
         .where(AuthSessionRow.user_id == user_id, AuthSessionRow.revoked_at.is_(None))
         .values(revoked_at=_now(), revoked_reason=reason))
    if keep is not None:
        q = q.where(AuthSessionRow.id != keep)
    return db.execute(q).rowcount or 0


def list_active(db: Session, user_id: int, idle_seconds: int) -> list[AuthSessionRow]:
    """Живые сеансы: не отозваны, не истекли и продлевались не раньше, чем срок
    токена назад (иначе последний токен уже истёк и сеанс фактически закрыт)."""
    now = _now()
    rows = db.scalars(select(AuthSessionRow)
                      .where(AuthSessionRow.user_id == user_id,
                             AuthSessionRow.revoked_at.is_(None))
                      .order_by(AuthSessionRow.last_seen_at.desc())).all()
    edge = now - timedelta(seconds=idle_seconds)
    return [r for r in rows if alive(r, user_id, now) and _aware(r.last_seen_at) >= edge]
