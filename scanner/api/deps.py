"""Зависимости FastAPI: сессия БД, текущий пользователь, проверка прав."""
from __future__ import annotations

from collections.abc import Callable, Iterator
from dataclasses import dataclass
from typing import Annotated

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from scanner.api.rbac import Perm, user_permissions
from scanner.core.audit import AuditSink
from scanner.core.db import User, session_scope

_bearer = HTTPBearer(auto_error=False)


@dataclass(frozen=True, slots=True)
class Principal:
    id: int
    username: str
    permissions: frozenset[str]

    @property
    def subject(self) -> str:
        """Субъект для журнала аудита."""
        return f"user:{self.username}"

    def has(self, perm: Perm | str) -> bool:
        return str(perm) in self.permissions


def get_session(request: Request) -> Iterator[Session]:
    with session_scope(request.app.state.sessions) as s:
        yield s


def get_audit(request: Request) -> AuditSink:
    return request.app.state.audit


SessionDep = Annotated[Session, Depends(get_session)]
AuditDep = Annotated[AuditSink, Depends(get_audit)]


def current_user(request: Request,
                 creds: Annotated[HTTPAuthorizationCredentials | None, Depends(_bearer)],
                 session: SessionDep) -> Principal:
    unauthorized = HTTPException(status.HTTP_401_UNAUTHORIZED, "not authenticated",
                                 headers={"WWW-Authenticate": "Bearer"})
    if creds is None:
        raise unauthorized
    uid = request.app.state.signer.verify(creds.credentials)
    user = session.get(User, uid) if uid is not None else None
    if user is None or not user.is_active:
        raise unauthorized
    return Principal(user.id, user.username, frozenset(user_permissions(session, user.id)))


CurrentUser = Annotated[Principal, Depends(current_user)]


def require(*perms: Perm) -> Callable[..., Principal]:
    """Зависимость: пользователь обязан иметь все перечисленные права.

    Отказ фиксируется в журнале аудита до ответа 403.
    """
    def dep(request: Request, user: CurrentUser, audit: AuditDep) -> Principal:
        missing = [str(p) for p in perms if not user.has(p)]
        if missing:
            deny(audit, user, request, missing)
        return user
    return dep


def deny(audit: AuditSink, user: Principal, request: Request, missing: list[str]):
    audit.record(subject=user.subject, action="access_denied",
                 target=f"{request.method} {request.url.path}", result="forbidden",
                 details={"missing_permissions": missing})
    raise HTTPException(status.HTTP_403_FORBIDDEN,
                        f"missing permission: {', '.join(missing)}")
