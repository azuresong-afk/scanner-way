"""Вход, текущий пользователь, управление пользователями и ролями."""
from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from scanner.api.deps import AuditDep, CurrentUser, Principal, SessionDep, require
from scanner.api.ldap_auth import LdapAuthenticator, LdapDenied, LdapUnavailable
from scanner.api.rbac import (
    Perm,
    active_admin_ids,
    set_user_roles,
    user_role_names,
)
from scanner.api.schemas import (
    AuthConfigOut,
    LoginIn,
    MeOut,
    RolesIn,
    TokenOut,
    UserCreate,
    UserOut,
    UserUpdate,
)
from scanner.api.security import (
    DUMMY_HASH,
    MFA_PENDING,
    NO_PASSWORD,
    hash_password,
    verify_password,
)
from scanner.api.settings import ApiSettings
from scanner.core.audit import AuditSink
from scanner.core.db import User

router = APIRouter()


def _user_out(session: Session, u: User) -> UserOut:
    return UserOut(id=u.id, username=u.username, display_name=u.display_name,
                   is_active=u.is_active, roles=user_role_names(session, u.id),
                   auth_source=u.auth_source or "local", mfa_enabled=bool(u.mfa_enabled))


MFA_TOKEN_TTL = 300   # секунд между вводом пароля и кодом 2FA


def mfa_required_for(settings: ApiSettings, u: User) -> bool:
    """Нужна ли 2FA при входе этого пользователя."""
    if settings.mfa == "off":
        return False
    if u.mfa_enabled:
        return True
    return settings.mfa == "required" and u.username.lower() not in settings.mfa_exempt


def issue_access(request: Request, user: User) -> TokenOut:
    signer = request.app.state.signer
    return TokenOut(access_token=signer.issue(user.id), expires_in=signer.ttl)


def finish_login(request: Request, audit: AuditSink, user: User, *, method: str,
                 client: str | None) -> TokenOut:
    """После проверки пароля: токен доступа или второй шаг (2FA)."""
    settings: ApiSettings = request.app.state.settings
    if mfa_required_for(settings, user):
        enroll = not user.mfa_enabled
        audit.record(subject=f"user:{user.username}", action="login", target=client,
                     result="mfa_pending", details={"method": method, "enroll": enroll})
        token = request.app.state.signer.issue(user.id, typ=MFA_PENDING, ttl=MFA_TOKEN_TTL)
        return TokenOut(mfa_required=True, mfa_enroll=enroll, mfa_token=token)
    audit.record(subject=f"user:{user.username}", action="login", target=client,
                 result="ok", details={"method": method})
    return issue_access(request, user)


def _ldap_login(request: Request, session: Session, audit: AuditSink, body: LoginIn,
                client: str | None) -> User | None:
    """Вход учётной записью домена. None — не вышло (аудит уже записан)."""
    auth: LdapAuthenticator = request.app.state.ldap
    try:
        ident = auth.authenticate(body.username, body.password)
    except LdapUnavailable as e:
        audit.record(subject=f"user:{body.username}", action="login", target=client,
                     result="ldap_unavailable", details={"method": "ldap", "error": str(e)})
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE,
                            "directory (LDAP) is unavailable, try later") from None
    except LdapDenied as e:
        audit.record(subject=f"user:{body.username}", action="login", target=client,
                     result="failure", details={"method": "ldap", "reason": e.reason})
        return None
    user = session.scalar(select(User).where(User.username == ident.username,
                                             User.auth_source == "ldap"))
    clash = session.scalar(select(User.id).where(func.lower(User.username) == ident.username,
                                                 User.auth_source != "ldap"))
    if clash is not None:
        # Локальная учётка с тем же именем не «перехватывается» доменом.
        audit.record(subject=f"user:{ident.username}", action="login", target=client,
                     result="failure", details={"method": "ldap", "reason": "local_conflict"})
        return None
    roles = sorted(ident.roles)
    if user is None:
        user = User(username=ident.username, display_name=ident.display_name,
                    password_hash=NO_PASSWORD, is_active=True, auth_source="ldap",
                    external_dn=ident.dn)
        session.add(user)
        session.flush()
        set_user_roles(session, user.id, roles)
        session.commit()
        audit.record(subject="ldap", action="user_create", target=f"user:{user.username}",
                     result="ok", details={"user_id": user.id, "roles": roles,
                                           "groups": list(ident.groups), "source": "ldap"})
        return user
    before = user_role_names(session, user.id)
    user.external_dn = ident.dn
    if ident.display_name:
        user.display_name = ident.display_name
    if before != roles:
        set_user_roles(session, user.id, roles)
        audit.record(subject="ldap", action="user_roles", target=f"user:{user.username}",
                     result="ok", details={"before": before, "after": roles,
                                           "groups": list(ident.groups), "source": "ldap"})
    session.commit()
    return user


@router.get("/auth/config", response_model=AuthConfigOut, tags=["auth"])
def auth_config(request: Request) -> AuthConfigOut:
    """Способы входа для страницы входа (без авторизации, без подробностей)."""
    return AuthConfigOut(ldap=request.app.state.ldap is not None,
                         mfa=request.app.state.settings.mfa)


@router.post("/auth/token", response_model=TokenOut, response_model_exclude_none=True,
             tags=["auth"])
def login(body: LoginIn, request: Request, session: SessionDep,
          audit: AuditDep) -> TokenOut:
    throttle = request.app.state.throttle
    client = request.client.host if request.client else None
    # «CORP\\ivanov» и «ivanov» — одна учётка и один счётчик неудачных попыток
    key = body.username.rsplit("\\", 1)[-1].strip().lower()
    if throttle.locked(key):
        audit.record(subject=f"user:{body.username}", action="login", target=client,
                     result="locked")
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS,
                            "too many failed attempts, try later")
    user = session.scalar(select(User).where(User.username == body.username))
    method = "local"
    if user is not None and user.auth_source == "local":
        ok = verify_password(body.password, user.password_hash)
    elif request.app.state.ldap is not None and (user is None or user.auth_source == "ldap"):
        method = "ldap"
        user = _ldap_login(request, session, audit, body, client)
        ok = user is not None
    else:
        verify_password(body.password, DUMMY_HASH)     # то же время ответа
        ok = False
    if not (ok and user is not None and user.is_active):
        throttle.failure(key)
        if method == "local" or (user is not None and not user.is_active):
            audit.record(subject=f"user:{body.username}", action="login", target=client,
                         result="failure", details={"method": method})
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid credentials")
    throttle.success(key)
    return finish_login(request, audit, user, method=method, client=client)


@router.get("/me", response_model=MeOut, tags=["auth"])
def me(user: CurrentUser,
       session: SessionDep) -> MeOut:
    u = session.get(User, user.id)
    return MeOut(**_user_out(session, u).model_dump(),
                 permissions=sorted(user.permissions))


@router.get("/users", response_model=list[UserOut], tags=["users"])
def list_users(_: Annotated[Principal, Depends(require(Perm.MANAGE_USERS))],
               session: SessionDep) -> list[UserOut]:
    return [_user_out(session, u) for u in session.scalars(select(User).order_by(User.id))]


@router.post("/users", response_model=UserOut, status_code=201, tags=["users"])
def create_user(body: UserCreate, user: Annotated[Principal, Depends(require(Perm.MANAGE_USERS))],
                session: SessionDep,
                audit: AuditDep) -> UserOut:
    if session.scalar(select(User.id).where(User.username == body.username)):
        raise HTTPException(status.HTTP_409_CONFLICT, "username already exists")
    u = User(username=body.username, display_name=body.display_name,
             password_hash=hash_password(body.password), is_active=True)
    session.add(u)
    session.flush()
    try:
        set_user_roles(session, u.id, body.roles)
    except ValueError as e:
        raise HTTPException(422, str(e)) from e
    session.commit()
    audit.record(subject=user.subject, action="user_create", target=f"user:{u.username}",
                 result="ok", details={"user_id": u.id, "roles": sorted(body.roles)})
    return _user_out(session, u)


def _get_user(session: Session, user_id: int) -> User:
    u = session.get(User, user_id)
    if u is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "user not found")
    return u


def _guard_last_admin(session: Session, target: User, *, removing: bool) -> None:
    if removing and active_admin_ids(session) == {target.id}:
        raise HTTPException(status.HTTP_409_CONFLICT,
                            "cannot remove or disable the last active admin")


@router.patch("/users/{user_id}", response_model=UserOut, tags=["users"])
def update_user(user_id: int, body: UserUpdate,
                user: Annotated[Principal, Depends(require(Perm.MANAGE_USERS))],
                session: SessionDep,
                audit: AuditDep) -> UserOut:
    u = _get_user(session, user_id)
    changed = body.model_dump(exclude_unset=True)
    if changed.get("is_active") is False:
        _guard_last_admin(session, u, removing=True)
    if "display_name" in changed:
        u.display_name = body.display_name
    if body.is_active is not None:
        u.is_active = body.is_active
    if body.password is not None:
        if u.auth_source != "local":
            raise HTTPException(status.HTTP_409_CONFLICT,
                                "password of a directory (LDAP) user is managed in the directory")
        u.password_hash = hash_password(body.password)
    session.commit()
    audit.record(subject=user.subject, action="user_update", target=f"user:{u.username}",
                 result="ok", details={"fields": sorted(changed)})   # без пароля
    return _user_out(session, u)


@router.put("/users/{user_id}/roles", response_model=UserOut, tags=["users"])
def put_roles(user_id: int, body: RolesIn,
              user: Annotated[Principal, Depends(require(Perm.MANAGE_USERS))],
              session: SessionDep,
              audit: AuditDep) -> UserOut:
    u = _get_user(session, user_id)
    if u.auth_source == "ldap":
        raise HTTPException(status.HTTP_409_CONFLICT,
                            "roles of a directory (LDAP) user come from directory groups")
    before = user_role_names(session, u.id)
    _guard_last_admin(session, u, removing="admin" in before and "admin" not in body.roles)
    try:
        set_user_roles(session, u.id, body.roles)
    except ValueError as e:
        raise HTTPException(422, str(e)) from e
    session.commit()
    audit.record(subject=user.subject, action="user_roles", target=f"user:{u.username}",
                 result="ok", details={"before": before, "after": sorted(set(body.roles))})
    return _user_out(session, u)
