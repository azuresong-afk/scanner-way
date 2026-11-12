"""Вход через LDAP/AD и двухфакторный вход (TOTP) — миграция 0027.

Каталог — заглушка ldap3 MOCK_SYNC (общий DIT у соединений одного Server):
настоящая привязка (bind) с проверкой пароля и поиск по фильтру.
"""
from __future__ import annotations

import base64

import pytest
from fastapi.testclient import TestClient
from ldap3 import MOCK_SYNC, Connection, Server
from ldap3.core.exceptions import LDAPSocketOpenError
from sqlalchemy import select

from scanner.api import mfa
from scanner.api.ldap_auth import (
    LdapAuthenticator,
    LdapConfig,
    LdapConfigError,
    LdapDenied,
    parse_group_roles,
)
from scanner.api.main import create_app
from scanner.api.settings import ApiSettings
from scanner.core.db import AuditLogRow, User
from scanner.reporting.remediation import RemediationResolver

SECRET = "x" * 40
PASSWORD = "correct-horse-battery"
BASE = "dc=corp,dc=local"
ADMINS = "CN=Scanner-Admins,OU=Groups,DC=corp,DC=local"
OPS = "CN=Scanner-Operators,OU=Groups,DC=corp,DC=local"
SVC_DN, SVC_PW = "cn=svc-scanner,ou=svc,dc=corp,dc=local", "svc-secret"
IVANOV_DN = "cn=Иванов Иван,ou=users,dc=corp,dc=local"


class Directory:
    """Заглушка AD: пользователи с паролями и memberOf."""

    def __init__(self):
        self.server = Server("fake-dc")
        self.down = False
        self._admin = Connection(self.server, user=SVC_DN, password=SVC_PW,
                                 client_strategy=MOCK_SYNC)
        self.add(SVC_DN, SVC_PW, sam="svc-scanner")

    def add(self, dn, password, *, sam, groups=(), display=None, upn=None):
        attrs = {"objectClass": ["top", "person", "user"], "userPassword": password,
                 "sAMAccountName": sam, "memberOf": list(groups)}
        if display:
            attrs["displayName"] = display
        if upn:
            attrs["userPrincipalName"] = upn
        self._admin.strategy.add_entry(dn, attrs)

    def set_groups(self, dn, groups):
        # MOCK хранит DIT в объекте Server, значения атрибутов — байтами
        for key, entry in self.server.dit.items():
            if key.lower() == dn.lower():
                entry["memberOf"] = [g.encode() for g in groups]

    def connect(self, user, password):
        if self.down:
            raise LDAPSocketOpenError("unable to open socket")
        return Connection(self.server, user=user, password=password,
                          client_strategy=MOCK_SYNC)


def _settings(**kw) -> ApiSettings:
    base = dict(secret=SECRET, bootstrap_admin="root", bootstrap_password=PASSWORD,
                login_max_failures=3)
    base.update(kw)
    return ApiSettings(**base)


def _ldap_kw(**kw):
    base = dict(ldap_url="ldaps://dc1.corp.local", ldap_bind_dn=SVC_DN,
                ldap_bind_password=SVC_PW, ldap_user_base=BASE,
                ldap_group_roles=f"{ADMINS}=>admin;{OPS}=>operator,host_credentials")
    base.update(kw)
    return base


@pytest.fixture
def directory():
    d = Directory()
    d.add(IVANOV_DN, "Ad-Passw0rd!", sam="Ivanov", groups=[OPS],
          display="Иванов И. И.", upn="ivanov@corp.local")
    d.add("cn=Petrov,ou=users,dc=corp,dc=local", "Petrov-pw-123", sam="petrov",
          groups=["CN=Accounting,OU=Groups,DC=corp,DC=local"])
    return d


def _client(sqlite_factory, settings, directory=None):
    app = create_app(session_factory=sqlite_factory, settings=settings,
                     registry={}, resolver_factory=lambda f: RemediationResolver(),
                     ldap_connect=directory.connect if directory else None)
    return TestClient(app)


def _login(c, username, password=PASSWORD):
    return c.post("/auth/token", json={"username": username, "password": password})


def _bearer(token):
    return {"Authorization": f"Bearer {token}"}


def _audit(sqlite_factory):
    with sqlite_factory() as s:
        return [(r.subject, r.action, r.result, r.details) for r in
                s.scalars(select(AuditLogRow).order_by(AuditLogRow.id))]


# ---------- по умолчанию всё выключено ----------

def test_defaults_off_local_login_unchanged(sqlite_factory):
    with _client(sqlite_factory, _settings()) as c:
        assert c.get("/auth/config").json() == {"ldap": False, "mfa": "off"}
        r = _login(c, "root")
        assert r.status_code == 200
        body = r.json()
        # ответ как раньше: никаких полей 2FA
        assert set(body) == {"access_token", "token_type", "expires_in",
                             "session_expires_at"}
        me = c.get("/me", headers=_bearer(body["access_token"])).json()
        assert me["auth_source"] == "local" and me["mfa_enabled"] is False
        assert c.post("/me/mfa/setup", headers=_bearer(body["access_token"])).status_code == 409
        assert _login(c, "ivanov", "x").status_code == 401


# ---------- LDAP ----------

def test_ldap_login_creates_user_with_group_roles(sqlite_factory, directory):
    with _client(sqlite_factory, _settings(**_ldap_kw()), directory) as c:
        assert c.get("/auth/config").json()["ldap"] is True
        r = _login(c, "ivanov", "Ad-Passw0rd!")
        assert r.status_code == 200, r.text
        me = c.get("/me", headers=_bearer(r.json()["access_token"])).json()
        assert me["username"] == "ivanov"
        assert me["display_name"] == "Иванов И. И."
        assert me["auth_source"] == "ldap"
        assert me["roles"] == ["host_credentials", "operator"]
        assert "run_scan" in me["permissions"]
        # тот же пользователь: «CORP\\Ivanov» и UPN
        assert _login(c, "CORP\\Ivanov", "Ad-Passw0rd!").status_code == 200
        assert _login(c, "ivanov@corp.local", "Ad-Passw0rd!").status_code == 200
    with sqlite_factory() as s:
        users = s.scalars(select(User).where(User.auth_source == "ldap")).all()
        assert [u.username for u in users] == ["ivanov"]
        assert users[0].external_dn == IVANOV_DN
        assert users[0].password_hash.startswith("!")
    log = _audit(sqlite_factory)
    assert any(a == "user_create" and s == "ldap" for s, a, _, _ in log)
    assert any(a == "login" and r == "ok" and d == {"method": "ldap"} for _, a, r, d in log)


def test_ldap_roles_follow_groups_on_each_login(sqlite_factory, directory):
    with _client(sqlite_factory, _settings(**_ldap_kw()), directory) as c:
        assert _login(c, "ivanov", "Ad-Passw0rd!").status_code == 200
        directory.set_groups(IVANOV_DN, [ADMINS])
        r = _login(c, "ivanov", "Ad-Passw0rd!")
        me = c.get("/me", headers=_bearer(r.json()["access_token"])).json()
        assert me["roles"] == ["admin"]
        # группу убрали совсем — входа нет
        directory.set_groups(IVANOV_DN, [])
        assert _login(c, "ivanov", "Ad-Passw0rd!").status_code == 401
    log = _audit(sqlite_factory)
    assert any(a == "user_roles" and s == "ldap" and d["after"] == ["admin"]
               for s, a, _, d in log)
    assert any(a == "login" and d and d.get("reason") == "no_group" for _, a, _, d in log)


def test_ldap_rejects_bad_password_unmapped_and_injection(sqlite_factory, directory):
    with _client(sqlite_factory, _settings(**_ldap_kw()), directory) as c:
        assert _login(c, "ivanov", "wrong").status_code == 401
        assert _login(c, "petrov", "Petrov-pw-123").status_code == 401   # нет группы
        assert _login(c, "*", "Ad-Passw0rd!").status_code == 401         # фильтр экранирован
        assert _login(c, "iv*", "Ad-Passw0rd!").status_code == 401
    reasons = [d.get("reason") for _, a, r, d in _audit(sqlite_factory)
               if a == "login" and r == "failure" and d]
    assert reasons[:4] == ["bad_credentials", "no_group", "not_found", "not_found"]
    with sqlite_factory() as s:
        assert s.scalar(select(User).where(User.username == "petrov")) is None


def test_empty_password_never_reaches_directory(directory):
    calls = []

    def connect(u, p):
        calls.append(u)
        return directory.connect(u, p)

    cfg = LdapConfig.from_settings(_settings(**_ldap_kw()))
    auth = LdapAuthenticator(cfg, connect)
    with pytest.raises(LdapDenied) as e:
        auth.authenticate("ivanov", "")
    assert e.value.reason == "bad_credentials" and calls == []


def test_local_user_wins_and_is_not_taken_over(sqlite_factory, directory):
    directory.add("cn=root,ou=users,dc=corp,dc=local", "domain-root-pw", sam="root",
                  groups=[ADMINS])
    with _client(sqlite_factory, _settings(**_ldap_kw()), directory) as c:
        # локальный root входит своим паролем, пароль домена не подходит
        assert _login(c, "root").status_code == 200
        assert _login(c, "root", "domain-root-pw").status_code == 401
        assert _login(c, "ROOT", "domain-root-pw").status_code == 401   # local_conflict
    assert any(d and d.get("reason") == "local_conflict" for *_, d in _audit(sqlite_factory))


def test_ldap_user_roles_and_password_not_editable(sqlite_factory, directory):
    with _client(sqlite_factory, _settings(**_ldap_kw()), directory) as c:
        _login(c, "ivanov", "Ad-Passw0rd!")
        admin = _bearer(_login(c, "root").json()["access_token"])
        users = {u["username"]: u for u in c.get("/users", headers=admin).json()}
        uid = users["ivanov"]["id"]
        assert users["ivanov"]["auth_source"] == "ldap"
        assert c.put(f"/users/{uid}/roles", headers=admin,
                     json={"roles": ["admin"]}).status_code == 409
        assert c.patch(f"/users/{uid}", headers=admin,
                       json={"password": "another-long-password"}).status_code == 409
        # а отключить можно — и тогда пароль домена не поможет
        assert c.patch(f"/users/{uid}", headers=admin,
                       json={"is_active": False}).status_code == 200
        assert _login(c, "ivanov", "Ad-Passw0rd!").status_code == 401


def test_ldap_down_local_still_works(sqlite_factory, directory):
    directory.down = True
    with _client(sqlite_factory, _settings(**_ldap_kw()), directory) as c:
        r = _login(c, "ivanov", "Ad-Passw0rd!")
        assert r.status_code == 503
        assert _login(c, "root").status_code == 200
    assert any(r == "ldap_unavailable" for _, _, r, _ in _audit(sqlite_factory))


def test_ldap_config_validation():
    with pytest.raises(LdapConfigError, match="открытым текстом"):
        LdapConfig.from_settings(_settings(**_ldap_kw(ldap_url="ldap://dc1")))
    assert LdapConfig.from_settings(_settings(**_ldap_kw(ldap_url="ldap://dc1",
                                                         ldap_start_tls=True)))
    with pytest.raises(LdapConfigError, match="неизвестные роли"):
        parse_group_roles(f"{ADMINS}=>superuser")
    with pytest.raises(LdapConfigError, match="GROUP_ROLES"):
        LdapConfig.from_settings(_settings(**_ldap_kw(ldap_group_roles="")))
    with pytest.raises(LdapConfigError, match="USER_BASE"):
        LdapConfig.from_settings(_settings(**_ldap_kw(ldap_user_base="")))
    with pytest.raises(LdapConfigError):   # API не стартует с ошибкой в настройках
        create_app(settings=_settings(**_ldap_kw(ldap_group_roles="CN=x=>root")),
                   session_factory=object())  # type: ignore[arg-type]
    groups = parse_group_roles(f" {ADMINS} => admin ;\n{OPS}=>operator, host_credentials")
    assert groups["cn=scanner-admins,ou=groups,dc=corp,dc=local"] == {"admin"}
    assert groups["cn=scanner-operators,ou=groups,dc=corp,dc=local"] == {
        "operator", "host_credentials"}
    assert LdapConfig.from_settings(_settings()) is None


# ---------- TOTP ----------

def test_totp_rfc6238_vector_and_window():
    secret = base64.b32encode(b"12345678901234567890").decode()
    assert mfa.code_at(secret, 59 // 30) == "287082"            # RFC 6238, T=59
    assert mfa.code_at(secret, 1111111109 // 30) == "081804"    # T=1111111109
    now = 1111111109.0
    code = mfa.code_at(secret, mfa.current_step(now))
    assert mfa.verify_code(secret, code, last_step=None, now=now) == mfa.current_step(now)
    assert mfa.verify_code(secret, code, last_step=None, now=now + 30) is not None  # часы
    assert mfa.verify_code(secret, code, last_step=None, now=now + 90) is None
    assert mfa.verify_code(secret, code, last_step=mfa.current_step(now), now=now) is None
    assert mfa.verify_code(secret, "12345", last_step=None, now=now) is None
    assert mfa.verify_code(secret, code[:3] + " " + code[3:], last_step=None, now=now)


def test_recovery_codes_single_use():
    codes = mfa.new_recovery_codes()
    hashes = [mfa.hash_recovery(c) for c in codes]
    assert len(set(codes)) == 10
    left = mfa.use_recovery(codes[3].upper(), hashes)
    assert left is not None and len(left) == 9
    assert mfa.use_recovery(codes[3], left) is None


def _code(secret: str, shift: int = 0) -> str:
    return mfa.code_at(secret, mfa.current_step() + shift)


def test_mfa_optional_enable_login_recovery_disable(sqlite_factory):
    with _client(sqlite_factory, _settings(mfa="optional")) as c:
        assert c.get("/auth/config").json()["mfa"] == "optional"
        tok = _login(c, "root").json()["access_token"]   # 2FA ещё не включена
        h = _bearer(tok)
        assert c.get("/me/mfa", headers=h).json() == {
            "mode": "optional", "enabled": False, "required": False,
            "recovery_codes_left": 0}
        setup = c.post("/me/mfa/setup", headers=h).json()
        assert setup["otpauth_uri"].startswith("otpauth://totp/Scanner:root?")
        assert setup["qr_svg"].startswith("<svg")
        secret = setup["secret"]
        assert c.post("/me/mfa/confirm", headers=h, json={"code": "000000"}).status_code == 400
        r = c.post("/me/mfa/confirm", headers=h, json={"code": _code(secret)})
        assert r.status_code == 200
        recovery = r.json()["recovery_codes"]
        assert len(recovery) == 10
        with sqlite_factory() as s:
            u = s.scalar(select(User).where(User.username == "root"))
            assert u.mfa_enabled and secret not in (u.mfa_secret or "")

        # теперь пароль — только первый шаг
        r = _login(c, "root").json()
        assert r["mfa_required"] is True and r["mfa_enroll"] is False
        assert "access_token" not in r
        pending = r["mfa_token"]
        # промежуточный токен — не токен доступа
        assert c.get("/me", headers=_bearer(pending)).status_code == 401
        # и токен доступа — не промежуточный
        assert c.post("/auth/mfa", json={"mfa_token": tok, "code": _code(secret, 1)}
                      ).status_code == 401
        # код, уже принятый при подтверждении, повторно не проходит
        assert c.post("/auth/mfa", json={"mfa_token": pending, "code": _code(secret)}
                      ).status_code == 400
        r = c.post("/auth/mfa", json={"mfa_token": pending, "code": _code(secret, 1)})
        assert r.status_code == 200 and r.json()["access_token"]

        # код восстановления — один раз
        pending = _login(c, "root").json()["mfa_token"]
        r = c.post("/auth/mfa", json={"mfa_token": pending, "code": recovery[0]})
        assert r.status_code == 200
        h = _bearer(r.json()["access_token"])
        assert c.get("/me/mfa", headers=h).json()["recovery_codes_left"] == 9
        pending = _login(c, "root").json()["mfa_token"]
        assert c.post("/auth/mfa", json={"mfa_token": pending, "code": recovery[0]}
                      ).status_code == 400

        # выключить — по коду восстановления (телефона нет)
        r = c.post("/me/mfa/disable", headers=h, json={"code": recovery[1]})
        assert r.status_code == 200 and r.json()["enabled"] is False
        assert "access_token" in _login(c, "root").json()
    actions = [a for _, a, _, _ in _audit(sqlite_factory)]
    assert "mfa_enable" in actions and "mfa_disable" in actions
    assert any(r == "mfa_pending" for _, _, r, _ in _audit(sqlite_factory))


def test_mfa_required_enroll_at_login_and_exempt(sqlite_factory):
    s = _settings(mfa="required", mfa_exempt_users="svc-vm")
    with _client(sqlite_factory, s) as c:
        r = _login(c, "root").json()
        assert r["mfa_required"] and r["mfa_enroll"]
        pending = r["mfa_token"]
        # без настройки 2FA обычный второй шаг невозможен
        assert c.post("/auth/mfa", json={"mfa_token": pending, "code": "123456"}
                      ).status_code == 409
        setup = c.post("/auth/mfa/enroll", json={"mfa_token": pending}).json()
        r = c.post("/auth/mfa/enroll/confirm",
                   json={"mfa_token": pending, "code": _code(setup["secret"])})
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["access_token"] and len(body["recovery_codes"]) == 10
        admin = _bearer(body["access_token"])
        # отключить обязательную 2FA нельзя
        assert c.post("/me/mfa/disable", headers=admin,
                      json={"code": _code(setup["secret"], 1)}).status_code == 409
        assert c.get("/me/mfa", headers=admin).json()["required"] is True
        r = c.post("/users", headers=admin, json={"username": "svc-vm", "password": PASSWORD,
                                                  "roles": ["auditor"]})
        assert r.status_code == 201
        assert "access_token" in _login(c, "svc-vm").json()
        assert _login(c, "SVC-VM").status_code == 401       # имя учётки — точное
        # администратор сбрасывает 2FA (потерян телефон) — снова настройка при входе
        uid = next(u["id"] for u in c.get("/users", headers=admin).json()
                   if u["username"] == "root")
        r = c.delete(f"/users/{uid}/mfa", headers=admin)
        assert r.status_code == 200 and r.json()["mfa_enabled"] is False
        assert _login(c, "root").json()["mfa_enroll"] is True
    assert any(a == "mfa_reset" for _, a, _, _ in _audit(sqlite_factory))


def test_mfa_with_ldap_user(sqlite_factory, directory):
    with _client(sqlite_factory, _settings(mfa="required", **_ldap_kw()), directory) as c:
        r = _login(c, "ivanov", "Ad-Passw0rd!").json()
        assert r["mfa_enroll"] is True
        setup = c.post("/auth/mfa/enroll", json={"mfa_token": r["mfa_token"]}).json()
        r = c.post("/auth/mfa/enroll/confirm",
                   json={"mfa_token": r["mfa_token"], "code": _code(setup["secret"])})
        assert r.status_code == 200
        r = _login(c, "ivanov", "Ad-Passw0rd!").json()
        assert r["mfa_required"] and not r["mfa_enroll"]


def test_mfa_code_bruteforce_throttled(sqlite_factory):
    with _client(sqlite_factory, _settings(mfa="optional")) as c:
        h = _bearer(_login(c, "root").json()["access_token"])
        secret = c.post("/me/mfa/setup", headers=h).json()["secret"]
        c.post("/me/mfa/confirm", headers=h, json={"code": _code(secret)})
        pending = _login(c, "root").json()["mfa_token"]
        for _ in range(3):
            assert c.post("/auth/mfa", json={"mfa_token": pending, "code": "000000"}
                          ).status_code == 400
        r = c.post("/auth/mfa", json={"mfa_token": pending, "code": _code(secret, 1)})
        assert r.status_code == 429


def test_invalid_mfa_mode_fails_fast():
    with pytest.raises(ValueError):
        ApiSettings(mfa="requred")


def test_cli_ldap_check(monkeypatch, capsys):
    from scanner.cli import main
    monkeypatch.delenv("SCANNER_API_LDAP_URL", raising=False)
    assert main(["auth", "ldap-check"]) == 0
    assert "LDAP выключен" in capsys.readouterr().out
    monkeypatch.setenv("SCANNER_API_LDAP_URL", "ldap://dc1")
    assert main(["auth", "ldap-check"]) == 2
    assert "открытым текстом" in capsys.readouterr().err
