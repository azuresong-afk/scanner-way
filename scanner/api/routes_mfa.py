"""Двухфакторный вход (TOTP): второй шаг входа, настройка в профиле, сброс.

Режим задаёт администратор стенда в окружении (`SCANNER_API_MFA`):
off — 2FA нет; optional — каждый включает себе сам; required — обязательна
всем, кроме сервисных учёток из `SCANNER_API_MFA_EXEMPT_USERS`.

Второй шаг входа: POST /auth/token отдаёт mfa_token (5 минут), он вместе с
кодом из приложения меняется на токен доступа в POST /auth/mfa. Если 2FA
обязательна, а пользователь её ещё не настроил, — тот же mfa_token даёт
настроить её прямо при входе (POST /auth/mfa/enroll → …/enroll/confirm).

Неверные коды считаются тем же ограничителем перебора, что и пароли
(`login_max_failures` подряд → пауза), отдельно по каждому пользователю.
"""
from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from scanner.api import mfa, sessions
from scanner.api.deps import AuditDep, CurrentUser, Principal, SessionDep, require
from scanner.api.rbac import Perm
from scanner.api.routes_auth import _user_out, issue_access
from scanner.api.schemas import (
    MfaCodeIn,
    MfaSetupOut,
    MfaStatusOut,
    MfaTokenIn,
    MfaVerifyIn,
    RecoveryCodesOut,
    TokenOut,
    UserOut,
)
from scanner.api.security import MFA_PENDING
from scanner.api.settings import ApiSettings
from scanner.core.audit import AuditSink
from scanner.core.credentials import CredentialVault, VaultUnavailable
from scanner.core.db import User

router = APIRouter(tags=["auth"])


def _settings(request: Request) -> ApiSettings:
    return request.app.state.settings


def _vault(request: Request) -> CredentialVault:
    vault = request.app.state.vault
    if vault is None:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE,
                            "2FA is unavailable: SCANNER_API_SECRET (encryption key) is not set")
    return vault


def _mode_on(request: Request) -> None:
    if _settings(request).mfa == "off":
        raise HTTPException(status.HTTP_409_CONFLICT, "2FA is turned off on this server")


def _client(request: Request) -> str | None:
    return request.client.host if request.client else None


def _pending_user(request: Request, session: Session, token: str) -> User:
    uid = request.app.state.signer.verify(token, typ=MFA_PENDING)
    user = session.get(User, uid) if uid is not None else None
    if user is None or not user.is_active:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED,
                            "sign-in session expired, enter the password again")
    return user


def _secret(request: Request, user: User) -> str | None:
    if not user.mfa_secret:
        return None
    try:
        return _vault(request).decrypt(user.mfa_secret).get("totp")
    except VaultUnavailable:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE,
                            "cannot decrypt the 2FA secret: was the encryption key "
                            "changed? An administrator can reset 2FA") from None


def _check_code(request: Request, session: Session, audit: AuditSink, user: User,
                code: str, *, allow_recovery: bool) -> str:
    """Проверяет код и «тратит» его. Возвращает 'totp' | 'recovery'; иначе 400/429."""
    throttle = request.app.state.throttle
    key = f"mfa:{user.id}"
    if throttle.locked(key):
        audit.record(subject=f"user:{user.username}", action="login", target=_client(request),
                     result="locked", details={"step": "mfa"})
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS,
                            "too many failed attempts, try later")
    secret = _secret(request, user)
    used = None
    if secret:
        step = mfa.verify_code(secret, code, last_step=user.mfa_last_step)
        if step is not None:
            user.mfa_last_step = step
            used = "totp"
    if used is None and allow_recovery and user.mfa_enabled:
        left = mfa.use_recovery(code, user.mfa_recovery)
        if left is not None:
            user.mfa_recovery = left
            used = "recovery"
    if used is None:
        throttle.failure(key)
        audit.record(subject=f"user:{user.username}", action="login", target=_client(request),
                     result="mfa_failure")
        # 400, а не 401: неверный код в профиле не должен «разлогинивать».
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "invalid code")
    throttle.success(key)
    session.flush()
    return used


def _new_setup(request: Request, session: Session, user: User) -> MfaSetupOut:
    vault = _vault(request)
    secret = mfa.new_secret()
    user.mfa_secret = vault.encrypt({"totp": secret})
    user.mfa_enabled = False
    user.mfa_last_step = None
    user.mfa_recovery = None
    session.commit()
    uri = mfa.otpauth_uri(secret, account=user.username, issuer=_settings(request).mfa_issuer)
    return MfaSetupOut(secret=secret, otpauth_uri=uri, qr_svg=mfa.qr_svg(uri))


def _enable(session: Session, user: User) -> list[str]:
    codes = mfa.new_recovery_codes()
    user.mfa_enabled = True
    user.mfa_recovery = [mfa.hash_recovery(c) for c in codes]
    session.commit()
    return codes


# ---------- второй шаг входа ----------

@router.post("/auth/mfa", response_model=TokenOut, response_model_exclude_none=True)
def verify(body: MfaVerifyIn, request: Request, session: SessionDep,
           audit: AuditDep) -> TokenOut:
    user = _pending_user(request, session, body.mfa_token)
    if not user.mfa_enabled:
        raise HTTPException(status.HTTP_409_CONFLICT, "2FA is not set up for this user")
    used = _check_code(request, session, audit, user, body.code, allow_recovery=True)
    session.commit()
    audit.record(subject=f"user:{user.username}", action="login", target=_client(request),
                 result="ok", details={"mfa": used,
                                       "recovery_codes_left": len(user.mfa_recovery or [])})
    return issue_access(request, session, user)


@router.post("/auth/mfa/enroll", response_model=MfaSetupOut)
def enroll_start(body: MfaTokenIn, request: Request, session: SessionDep) -> MfaSetupOut:
    _mode_on(request)
    user = _pending_user(request, session, body.mfa_token)
    if user.mfa_enabled:
        raise HTTPException(status.HTTP_409_CONFLICT, "2FA is already set up")
    return _new_setup(request, session, user)


@router.post("/auth/mfa/enroll/confirm", response_model=TokenOut,
             response_model_exclude_none=True)
def enroll_confirm(body: MfaVerifyIn, request: Request, session: SessionDep,
                   audit: AuditDep) -> TokenOut:
    _mode_on(request)
    user = _pending_user(request, session, body.mfa_token)
    if user.mfa_enabled:
        raise HTTPException(status.HTTP_409_CONFLICT, "2FA is already set up")
    if not user.mfa_secret:
        raise HTTPException(status.HTTP_409_CONFLICT, "start 2FA setup first")
    _check_code(request, session, audit, user, body.code, allow_recovery=False)
    codes = _enable(session, user)
    audit.record(subject=f"user:{user.username}", action="mfa_enable",
                 target=f"user:{user.username}", result="ok", details={"at_login": True})
    audit.record(subject=f"user:{user.username}", action="login", target=_client(request),
                 result="ok", details={"mfa": "totp"})
    out = issue_access(request, session, user)
    out.recovery_codes = codes
    return out


# ---------- профиль: своя 2FA ----------

def _me(session: Session, principal: Principal) -> User:
    return session.get(User, principal.id)


def _status(settings: ApiSettings, user: User) -> MfaStatusOut:
    required = (settings.mfa == "required"
                and user.username.lower() not in settings.mfa_exempt)
    return MfaStatusOut(mode=settings.mfa, enabled=bool(user.mfa_enabled), required=required,
                        recovery_codes_left=len(user.mfa_recovery or []))


@router.get("/me/mfa", response_model=MfaStatusOut)
def my_status(principal: CurrentUser, request: Request, session: SessionDep) -> MfaStatusOut:
    return _status(_settings(request), _me(session, principal))


@router.post("/me/mfa/setup", response_model=MfaSetupOut)
def my_setup(principal: CurrentUser, request: Request, session: SessionDep) -> MfaSetupOut:
    _mode_on(request)
    user = _me(session, principal)
    if user.mfa_enabled:
        raise HTTPException(status.HTTP_409_CONFLICT,
                            "2FA is already on: turn it off first to re-link the app")
    return _new_setup(request, session, user)


@router.post("/me/mfa/confirm", response_model=RecoveryCodesOut)
def my_confirm(body: MfaCodeIn, principal: CurrentUser, request: Request,
               session: SessionDep, audit: AuditDep) -> RecoveryCodesOut:
    _mode_on(request)
    user = _me(session, principal)
    if user.mfa_enabled:
        raise HTTPException(status.HTTP_409_CONFLICT, "2FA is already set up")
    if not user.mfa_secret:
        raise HTTPException(status.HTTP_409_CONFLICT, "start 2FA setup first")
    _check_code(request, session, audit, user, body.code, allow_recovery=False)
    codes = _enable(session, user)
    audit.record(subject=principal.subject, action="mfa_enable",
                 target=f"user:{user.username}", result="ok")
    return RecoveryCodesOut(recovery_codes=codes)


@router.post("/me/mfa/recovery-codes", response_model=RecoveryCodesOut)
def my_new_recovery(body: MfaCodeIn, principal: CurrentUser, request: Request,
                    session: SessionDep, audit: AuditDep) -> RecoveryCodesOut:
    """Новые коды восстановления (старые перестают действовать). Нужен код из приложения."""
    _mode_on(request)
    user = _me(session, principal)
    if not user.mfa_enabled:
        raise HTTPException(status.HTTP_409_CONFLICT, "2FA is not set up")
    _check_code(request, session, audit, user, body.code, allow_recovery=False)
    codes = mfa.new_recovery_codes()
    user.mfa_recovery = [mfa.hash_recovery(c) for c in codes]
    session.commit()
    audit.record(subject=principal.subject, action="mfa_recovery_codes",
                 target=f"user:{user.username}", result="ok")
    return RecoveryCodesOut(recovery_codes=codes)


@router.post("/me/mfa/disable", response_model=MfaStatusOut)
def my_disable(body: MfaCodeIn, principal: CurrentUser, request: Request,
               session: SessionDep, audit: AuditDep) -> MfaStatusOut:
    settings = _settings(request)
    user = _me(session, principal)
    if not user.mfa_enabled:
        raise HTTPException(status.HTTP_409_CONFLICT, "2FA is not set up")
    if _status(settings, user).required:
        raise HTTPException(status.HTTP_409_CONFLICT,
                            "2FA is required on this server and cannot be turned off")
    _check_code(request, session, audit, user, body.code, allow_recovery=True)
    _clear(user)
    sessions.revoke_user(session, user.id, "mfa_disabled", keep=principal.session_id)
    session.commit()
    audit.record(subject=principal.subject, action="mfa_disable",
                 target=f"user:{user.username}", result="ok")
    return _status(settings, user)


def _clear(user: User) -> None:
    user.mfa_secret = None
    user.mfa_enabled = False
    user.mfa_last_step = None
    user.mfa_recovery = None


# ---------- администратор: сброс 2FA (потерян телефон и коды) ----------

@router.delete("/users/{user_id}/mfa", response_model=UserOut, tags=["users"])
def reset_mfa(user_id: int,
              principal: Annotated[Principal, Depends(require(Perm.MANAGE_USERS))],
              session: SessionDep, audit: AuditDep) -> UserOut:
    user = session.get(User, user_id)
    if user is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "user not found")
    was = bool(user.mfa_enabled)
    _clear(user)
    # Потерян телефон — открытые входы этого пользователя закрываются тоже.
    revoked = sessions.revoke_user(session, user.id, "mfa_reset")
    session.commit()
    audit.record(subject=principal.subject, action="mfa_reset",
                 target=f"user:{user.username}", result="ok", details={"was_enabled": was,
                                                        "sessions_revoked": revoked})
    return _user_out(session, user)
