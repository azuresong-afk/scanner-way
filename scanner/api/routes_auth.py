"""Вход, текущий пользователь, управление пользователями и ролями."""
from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from scanner.api.deps import AuditDep, CurrentUser, Principal, SessionDep, require
from scanner.api.rbac import (
    Perm,
    active_admin_ids,
    set_user_roles,
    user_role_names,
)
from scanner.api.schemas import (
    LoginIn,
    MeOut,
    RolesIn,
    TokenOut,
    UserCreate,
    UserOut,
    UserUpdate,
)
from scanner.api.security import DUMMY_HASH, hash_password, verify_password
from scanner.core.db import User

router = APIRouter()


def _user_out(session: Session, u: User) -> UserOut:
    return UserOut(id=u.id, username=u.username, display_name=u.display_name,
                   is_active=u.is_active, roles=user_role_names(session, u.id))


@router.post("/auth/token", response_model=TokenOut, tags=["auth"])
def login(body: LoginIn, request: Request, session: SessionDep,
          audit: AuditDep) -> TokenOut:
    throttle = request.app.state.throttle
    client = request.client.host if request.client else None
    if throttle.locked(body.username):
        audit.record(subject=f"user:{body.username}", action="login", target=client,
                     result="locked")
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS,
                            "too many failed attempts, try later")
    user = session.scalar(select(User).where(User.username == body.username))
    ok = verify_password(body.password, user.password_hash if user else DUMMY_HASH)
    if not (ok and user is not None and user.is_active):
        throttle.failure(body.username)
        audit.record(subject=f"user:{body.username}", action="login", target=client,
                     result="failure")
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid credentials")
    throttle.success(body.username)
    audit.record(subject=f"user:{user.username}", action="login", target=client,
                 result="ok")
    signer = request.app.state.signer
    return TokenOut(access_token=signer.issue(user.id), expires_in=signer.ttl)


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
