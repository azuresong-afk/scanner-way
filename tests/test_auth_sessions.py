"""Сеансы входа (миграция 0030): отзыв токена при выходе и продление входа."""
from __future__ import annotations

import time
from datetime import UTC, datetime, timedelta

from fastapi.testclient import TestClient
from sqlalchemy import select

from scanner.api import mfa
from scanner.api.main import create_app
from scanner.api.settings import ApiSettings
from scanner.core.db import AuditLogRow, AuthSessionRow, User
from scanner.reporting.remediation import RemediationResolver

SECRET = "s" * 40
PASSWORD = "correct-horse-battery"
OTHER_PW = "another-long-password"


def _settings(**kw) -> ApiSettings:
    base = {"secret": SECRET, "bootstrap_admin": "root", "bootstrap_password": PASSWORD}
    base.update(kw)
    return ApiSettings(**base)


def _client(sqlite_factory, settings=None):
    app = create_app(session_factory=sqlite_factory, settings=settings or _settings(),
                     registry={}, resolver_factory=lambda f: RemediationResolver())
    return TestClient(app)


def _login(c, username="root", password=PASSWORD):
    r = c.post("/auth/token", json={"username": username, "password": password})
    assert r.status_code == 200, r.text
    return r.json()


def _h(token):
    return {"Authorization": f"Bearer {token}"}


def _actions(sqlite_factory):
    with sqlite_factory() as s:
        return [(r.action, r.result, r.details) for r in
                s.scalars(select(AuditLogRow).order_by(AuditLogRow.id))]


def _make_user(c, admin_h, name="ivan", roles=("operator",)):
    r = c.post("/users", headers=admin_h,
               json={"username": name, "password": OTHER_PW, "roles": list(roles)})
    assert r.status_code == 201, r.text
    return r.json()["id"]


# ---------- выход ----------

def test_logout_revokes_token_immediately(sqlite_factory):
    with _client(sqlite_factory) as c:
        t = _login(c)
        assert t["expires_in"] == 3600
        assert t["session_expires_at"]          # по умолчанию предел 12 часов
        tok = t["access_token"]
        assert c.get("/me", headers=_h(tok)).status_code == 200
        assert c.post("/auth/logout", headers=_h(tok)).status_code == 204
        # срок токена не вышел, но сеанс закрыт — токен больше не принимается
        assert c.get("/me", headers=_h(tok)).status_code == 401
        assert c.post("/auth/refresh", headers=_h(tok)).status_code == 401
        assert c.post("/auth/logout", headers=_h(tok)).status_code == 401
    with sqlite_factory() as s:
        row = s.scalar(select(AuthSessionRow))
        assert row.revoked_reason == "logout" and row.revoked_at is not None
    assert ("logout", "ok", None) in [(a, r, d) for a, r, d in _actions(sqlite_factory)]


def test_logout_closes_only_its_own_session(sqlite_factory):
    with _client(sqlite_factory) as c:
        a = _login(c)["access_token"]
        b = _login(c)["access_token"]
        c.post("/auth/logout", headers=_h(a))
        assert c.get("/me", headers=_h(a)).status_code == 401
        assert c.get("/me", headers=_h(b)).status_code == 200


def test_token_without_session_is_rejected(sqlite_factory):
    """Токены, выпущенные до миграции 0030 (без sid), и подделанный sid — 401."""
    with _client(sqlite_factory) as c:
        _login(c)
        signer = c.app.state.signer
        with sqlite_factory() as s:
            uid = s.scalar(select(User.id).where(User.username == "root"))
        assert c.get("/me", headers=_h(signer.issue(uid))).status_code == 401
        assert c.get("/me", headers=_h(signer.issue(uid, sid="nope"))).status_code == 401
        # sid чужого пользователя к своему uid не подходит
        admin_h = _h(_login(c)["access_token"])
        other = _make_user(c, admin_h)
        with sqlite_factory() as s:
            sid = s.scalar(select(AuthSessionRow.id).where(AuthSessionRow.user_id == uid))
        assert c.get("/me", headers=_h(signer.issue(other, sid=sid))).status_code == 401


# ---------- продление ----------

def test_refresh_extends_same_session(sqlite_factory):
    with _client(sqlite_factory) as c:
        signer = c.app.state.signer
        t0 = time.time()
        signer._clock = lambda: t0
        first = _login(c)
        tok = first["access_token"]
        # через 50 минут работы токен продлевается ещё на час от «сейчас»
        signer._clock = lambda: t0 + 3000
        r = c.post("/auth/refresh", headers=_h(tok))
        assert r.status_code == 200
        new = r.json()["access_token"]
        assert new != tok and r.json()["expires_in"] == 3600
        assert signer.claims(new)[1] == signer.claims(tok)[1]       # тот же сеанс
        signer._clock = lambda: t0 + 3700                            # старый истёк
        assert c.get("/me", headers=_h(tok)).status_code == 401
        assert c.get("/me", headers=_h(new)).status_code == 200
        # бездействие дольше срока токена — нужен новый вход
        signer._clock = lambda: t0 + 3000 + 3601
        assert c.post("/auth/refresh", headers=_h(new)).status_code == 401
    with sqlite_factory() as s:
        assert s.query(AuthSessionRow).count() == 1


def test_refresh_stops_at_session_max(sqlite_factory):
    with _client(sqlite_factory, _settings(session_max_hours=2)) as c:
        signer = c.app.state.signer
        tok = _login(c)["access_token"]
        with sqlite_factory() as s:
            row = s.scalar(select(AuthSessionRow))
            # до предельного срока сеанса осталось 10 минут
            row.expires_at = datetime.now(UTC) + timedelta(minutes=10)
            s.commit()
        r = c.post("/auth/refresh", headers=_h(tok)).json()
        assert 0 < r["expires_in"] <= 600              # не дальше предела сеанса
        # предел прошёл — даже свежий по подписи токен не принимается
        with sqlite_factory() as s:
            row = s.scalar(select(AuthSessionRow))
            row.expires_at = datetime.now(UTC) - timedelta(seconds=1)
            s.commit()
        assert c.get("/me", headers=_h(r["access_token"])).status_code == 401
        assert signer.claims(r["access_token"]) is not None


def test_no_session_max(sqlite_factory):
    with _client(sqlite_factory, _settings(session_max_hours=0)) as c:
        t = _login(c)
        assert "session_expires_at" not in t
        assert c.post("/auth/refresh", headers=_h(t["access_token"])).status_code == 200


# ---------- список сеансов и завершение ----------

def test_my_sessions_list_and_revoke(sqlite_factory):
    with _client(sqlite_factory) as c:
        a = _login(c)["access_token"]
        b = _login(c)["access_token"]
        cc = _login(c)["access_token"]
        lst = c.get("/me/sessions", headers=_h(a)).json()
        assert len(lst) == 3 and sum(x["current"] for x in lst) == 1
        assert all(x["method"] == "local" for x in lst)
        b_sid = c.app.state.signer.claims(b)[1]
        assert c.delete(f"/me/sessions/{b_sid}", headers=_h(a)).status_code == 204
        assert c.get("/me", headers=_h(b)).status_code == 401
        assert c.delete(f"/me/sessions/{b_sid}", headers=_h(a)).status_code == 404
        r = c.post("/me/sessions/revoke-others", headers=_h(a)).json()
        assert r == {"revoked": 1}
        assert c.get("/me", headers=_h(cc)).status_code == 401
        assert c.get("/me", headers=_h(a)).status_code == 200
        assert len(c.get("/me/sessions", headers=_h(a)).json()) == 1


def test_cannot_revoke_someone_elses_session(sqlite_factory):
    with _client(sqlite_factory) as c:
        admin = _login(c)["access_token"]
        _make_user(c, _h(admin))
        ivan = _login(c, "ivan", OTHER_PW)["access_token"]
        admin_sid = c.app.state.signer.claims(admin)[1]
        assert c.delete(f"/me/sessions/{admin_sid}", headers=_h(ivan)).status_code == 404
        assert c.get("/me", headers=_h(admin)).status_code == 200


# ---------- действия администратора закрывают сеансы ----------

def test_admin_disable_password_and_revoke_all(sqlite_factory):
    with _client(sqlite_factory) as c:
        admin = _h(_login(c)["access_token"])
        uid = _make_user(c, admin)
        ivan = _login(c, "ivan", OTHER_PW)["access_token"]

        # смена пароля закрывает входы со старым паролем
        assert c.patch(f"/users/{uid}", headers=admin,
                       json={"password": "brand-new-password"}).status_code == 200
        assert c.get("/me", headers=_h(ivan)).status_code == 401
        ivan = _login(c, "ivan", "brand-new-password")["access_token"]

        # «Завершить сеансы» администратором
        assert c.delete(f"/users/{uid}/sessions", headers=admin).json() == {"revoked": 1}
        assert c.get("/me", headers=_h(ivan)).status_code == 401
        ivan = _login(c, "ivan", "brand-new-password")["access_token"]

        # блокировка
        assert c.patch(f"/users/{uid}", headers=admin,
                       json={"is_active": False}).status_code == 200
        c.patch(f"/users/{uid}", headers=admin, json={"is_active": True})
        assert c.get("/me", headers=_h(ivan)).status_code == 401   # и после разблокировки

        # оператор не может закрывать чужие сеансы
        ivan = _login(c, "ivan", "brand-new-password")["access_token"]
        assert c.delete("/users/1/sessions", headers=_h(ivan)).status_code == 403
    reasons = set()
    with sqlite_factory() as s:
        reasons = {r.revoked_reason for r in s.scalars(select(AuthSessionRow))}
    assert {"password_changed", "admin", "user_disabled"} <= reasons


def test_admin_changing_own_password_keeps_current_session(sqlite_factory):
    with _client(sqlite_factory) as c:
        a = _login(c)["access_token"]
        b = _login(c)["access_token"]
        assert c.patch("/users/1", headers=_h(a),
                       json={"password": "root-new-password"}).status_code == 200
        assert c.get("/me", headers=_h(a)).status_code == 200
        assert c.get("/me", headers=_h(b)).status_code == 401


# ---------- 2FA ----------

def _code(secret, shift=0):
    return mfa.code_at(secret, mfa.current_step() + shift)


def test_mfa_login_creates_session_and_reset_revokes(sqlite_factory):
    with _client(sqlite_factory, _settings(mfa="optional")) as c:
        admin = _h(_login(c)["access_token"])
        uid = _make_user(c, admin)
        ivan = _h(_login(c, "ivan", OTHER_PW)["access_token"])
        secret = c.post("/me/mfa/setup", headers=ivan).json()["secret"]
        c.post("/me/mfa/confirm", headers=ivan, json={"code": _code(secret)})

        pending = _login(c, "ivan", OTHER_PW)
        # промежуточный токен 2FA — не сеанс: ни продлить, ни выйти им нельзя
        assert c.post("/auth/refresh", headers=_h(pending["mfa_token"])).status_code == 401
        r = c.post("/auth/mfa", json={"mfa_token": pending["mfa_token"],
                                      "code": _code(secret, 1)}).json()
        tok = r["access_token"]
        assert r["session_expires_at"]
        assert c.post("/auth/refresh", headers=_h(tok)).status_code == 200
        assert len(c.get("/me/sessions", headers=_h(tok)).json()) == 2

        # администратор сбросил 2FA (потерян телефон) — все входы закрыты
        c.delete(f"/users/{uid}/mfa", headers=admin)
        assert c.get("/me", headers=_h(tok)).status_code == 401
        assert c.get("/me", headers=ivan).status_code == 401
    details = [d for a, _, d in _actions(sqlite_factory) if a == "mfa_reset"]
    assert details and details[0]["sessions_revoked"] == 2


def test_mfa_disable_closes_other_sessions(sqlite_factory):
    with _client(sqlite_factory, _settings(mfa="optional")) as c:
        a = _h(_login(c)["access_token"])
        secret = c.post("/me/mfa/setup", headers=a).json()["secret"]
        codes = c.post("/me/mfa/confirm", headers=a,
                       json={"code": _code(secret)}).json()["recovery_codes"]
        pending = _login(c)["mfa_token"]
        b = c.post("/auth/mfa", json={"mfa_token": pending, "code": codes[0]}
                   ).json()["access_token"]
        assert c.post("/me/mfa/disable", headers=a, json={"code": codes[1]}).status_code == 200
        assert c.get("/me", headers=a).status_code == 200
        assert c.get("/me", headers=_h(b)).status_code == 401


def test_old_sessions_cleaned_up_on_login(sqlite_factory):
    with _client(sqlite_factory) as c:
        tok = _login(c)["access_token"]
        c.post("/auth/logout", headers=_h(tok))
        with sqlite_factory() as s:
            row = s.scalar(select(AuthSessionRow))
            row.revoked_at = datetime.now(UTC) - timedelta(days=31)
            s.commit()
        _login(c)
    with sqlite_factory() as s:
        assert s.query(AuthSessionRow).count() == 1
