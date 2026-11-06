"""Вход через LDAP / Active Directory (опционально, по умолчанию выключен).

Как проходит вход:

1. служебной учётной записью (только чтение каталога) ищем пользователя по
   фильтру `ldap_user_filter` — введённый логин экранируется (RFC 4515), так
   что подставить свой фильтр через поле «Имя пользователя» нельзя;
2. проверяем пароль привязкой (bind) к каталогу от имени найденного DN.
   Пустой пароль отклоняется до обращения к каталогу: в LDAP привязка с
   пустым паролем — «анонимная» и успешна для любого DN;
3. роли — из групп пользователя по таблице «группа → роли»
   (`ldap_group_roles`). Нет ни одной подходящей группы — входа нет.

Пароль домена в «Сканере» не хранится. Права в «Сканере» по-прежнему
считаются из ролей в БД на каждый запрос: при каждом входе роли пользователя
из каталога перезаписываются по его текущим группам.

Модуль не знает о БД и FastAPI: принимает настройки, возвращает
`LdapIdentity` или исключение — его удобно проверять на заглушке каталога
(ldap3 MOCK_SYNC) и из CLI (`scanner auth ldap-check`).
"""
from __future__ import annotations

import contextlib
import re
import ssl
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field

from scanner.api.rbac import ROLE_PERMISSIONS

MAX_LOGIN_LEN = 256
MAX_PASSWORD_LEN = 1024
# Правило AD «членство по цепочке» (вложенные группы).
_IN_CHAIN = "1.2.840.113556.1.4.1941"
_CTRL = re.compile(r"[\x00-\x1f\x7f]")


class LdapConfigError(ValueError):
    """Настройки LDAP заданы неверно (видно при старте API и в ldap-check)."""


class LdapUnavailable(RuntimeError):
    """Каталог недоступен (сеть, TLS, таймаут, служебная учётка не входит)."""


class LdapDenied(Exception):
    """Вход отклонён. reason: bad_credentials | not_found | ambiguous | no_group."""

    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


def normalize_dn(dn: str) -> str:
    """DN для сравнения: без пробелов вокруг «,» и «=», в нижнем регистре."""
    return re.sub(r"\s*([,=+])\s*", r"\1", dn.strip()).lower()


def parse_group_roles(text: str) -> dict[str, frozenset[str]]:
    """«DN=>роль,роль; DN2=>роль» -> {нормализованный DN: роли}."""
    out: dict[str, frozenset[str]] = {}
    for raw in re.split(r"[;\n]", text):
        item = raw.strip()
        if not item:
            continue
        if "=>" not in item:
            raise LdapConfigError(f"группа без ролей (нужно «DN=>роль»): {item!r}")
        dn, _, roles_text = item.rpartition("=>")
        dn = normalize_dn(dn)
        roles = frozenset(r.strip() for r in roles_text.split(",") if r.strip())
        if not dn or "=" not in dn:
            raise LdapConfigError(f"не похоже на DN группы: {item!r}")
        unknown = sorted(roles - set(ROLE_PERMISSIONS))
        if unknown or not roles:
            raise LdapConfigError(
                f"неизвестные роли {unknown or '(пусто)'} у группы {dn!r}; "
                f"допустимые: {', '.join(sorted(ROLE_PERMISSIONS))}")
        out[dn] = out.get(dn, frozenset()) | roles
    return out


@dataclass(frozen=True)
class LdapConfig:
    urls: tuple[str, ...]
    user_base: str
    group_roles: dict[str, frozenset[str]]
    user_filter: str = ("(&(objectClass=user)(|(sAMAccountName={username})"
                        "(userPrincipalName={username})))")
    username_attr: str = "sAMAccountName"
    display_name_attr: str = "displayName"
    bind_dn: str = ""
    bind_password: str = field(default="", repr=False)
    start_tls: bool = False
    tls_verify: bool = True
    ca_file: str = ""
    nested_groups: bool = False
    timeout: float = 5.0

    @classmethod
    def from_settings(cls, s) -> LdapConfig | None:
        """None — LDAP выключен (пустой ldap_url). LdapConfigError — ошибка."""
        urls = tuple(u.strip() for u in s.ldap_url.split(",") if u.strip())
        if not urls:
            return None
        for u in urls:
            if not re.match(r"^ldaps?://[^/\s]+/?$", u, re.IGNORECASE):
                raise LdapConfigError(f"адрес каталога должен быть ldap(s)://хост[:порт]: {u!r}")
            if u.lower().startswith("ldap://") and not s.ldap_start_tls:
                raise LdapConfigError(
                    f"{u}: пароль пойдёт открытым текстом — используйте ldaps:// "
                    "или включите SCANNER_API_LDAP_START_TLS=true")
        if not s.ldap_user_base.strip():
            raise LdapConfigError("не задан SCANNER_API_LDAP_USER_BASE (где искать пользователей)")
        if "{username}" not in s.ldap_user_filter:
            raise LdapConfigError("в SCANNER_API_LDAP_USER_FILTER нет подстановки {username}")
        groups = parse_group_roles(s.ldap_group_roles)
        if not groups:
            raise LdapConfigError("не задан SCANNER_API_LDAP_GROUP_ROLES: без сопоставления "
                                  "групп и ролей никто из каталога не сможет войти")
        if bool(s.ldap_bind_dn) != bool(s.ldap_bind_password):
            raise LdapConfigError("служебная учётка задаётся парой "
                                  "SCANNER_API_LDAP_BIND_DN + SCANNER_API_LDAP_BIND_PASSWORD")
        return cls(urls=urls, user_base=s.ldap_user_base.strip(), group_roles=groups,
                   user_filter=s.ldap_user_filter, username_attr=s.ldap_username_attr,
                   display_name_attr=s.ldap_display_name_attr, bind_dn=s.ldap_bind_dn,
                   bind_password=s.ldap_bind_password, start_tls=s.ldap_start_tls,
                   tls_verify=s.ldap_tls_verify, ca_file=s.ldap_ca_file,
                   nested_groups=s.ldap_nested_groups,
                   timeout=float(s.ldap_timeout_seconds))


@dataclass(frozen=True)
class LdapIdentity:
    username: str            # логин в «Сканере» (атрибут username_attr, нижний регистр)
    dn: str
    display_name: str | None
    groups: tuple[str, ...]  # группы из таблицы сопоставления, в которых состоит
    roles: frozenset[str]


# (user | None, password | None) -> несвязанное соединение ldap3.
ConnectionFactory = Callable[[str | None, str | None], object]


def clean_login(login: str) -> str | None:
    """Логин без домена «CORP\\ivanov» -> «ivanov»; None — недопустимый."""
    login = login.strip()
    if "\\" in login:
        login = login.rsplit("\\", 1)[1]
    if not login or len(login) > MAX_LOGIN_LEN or _CTRL.search(login):
        return None
    return login


class LdapAuthenticator:
    def __init__(self, cfg: LdapConfig, connect: ConnectionFactory | None = None):
        self.cfg = cfg
        self._connect = connect or self._real_connection

    # ---------- соединение ----------
    def _real_connection(self, user: str | None, password: str | None):
        from ldap3 import FIRST, Connection, Server, ServerPool, Tls

        tls = Tls(validate=ssl.CERT_REQUIRED if self.cfg.tls_verify else ssl.CERT_NONE,
                  ca_certs_file=self.cfg.ca_file or None)   # контекст ssl по умолчанию
        servers = [Server(u, use_ssl=u.lower().startswith("ldaps://"), tls=tls,
                          connect_timeout=self.cfg.timeout, get_info="NO_INFO")
                   for u in self.cfg.urls]
        pool = ServerPool(servers, FIRST, active=1, exhaust=False)
        return Connection(pool, user=user, password=password, read_only=True,
                          receive_timeout=self.cfg.timeout, raise_exceptions=False,
                          auto_referrals=False)

    def _bind(self, user: str | None, password: str | None):
        """Связанное соединение или None (неверные учётные данные).

        LdapUnavailable — сеть / TLS / таймаут.
        """
        from ldap3.core.exceptions import LDAPException

        try:
            conn = self._connect(user, password)
            if self.cfg.start_tls:
                conn.open()
                if not conn.start_tls():
                    raise LdapUnavailable("STARTTLS не удался")
            if conn.bind():
                return conn
            code = (conn.result or {}).get("result")
        except LdapUnavailable:
            raise
        except LDAPException as e:
            raise LdapUnavailable(type(e).__name__) from None
        except (OSError, ssl.SSLError) as e:
            raise LdapUnavailable(type(e).__name__) from None
        if code == 49:                  # invalidCredentials
            return None
        raise LdapUnavailable(f"bind result {code}")

    # ---------- вход ----------
    def service_connection(self):
        conn = self._bind(self.cfg.bind_dn or None, self.cfg.bind_password or None)
        if conn is None:
            raise LdapUnavailable("служебная учётная запись LDAP не принята каталогом")
        return conn

    def find_user(self, conn, login: str) -> tuple[str, dict[str, list]]:
        from ldap3 import SUBTREE
        from ldap3.utils.conv import escape_filter_chars

        flt = self.cfg.user_filter.replace("{username}", escape_filter_chars(login))
        attrs = [self.cfg.username_attr, self.cfg.display_name_attr, "memberOf"]
        ok = conn.search(self.cfg.user_base, flt, SUBTREE, attributes=attrs, size_limit=2)
        code = (conn.result or {}).get("result")
        if not ok and code not in (0, 4, 32):     # 4 sizeLimitExceeded, 32 noSuchObject
            raise LdapUnavailable(f"search result {code}")
        entries = [e for e in conn.response or [] if e.get("type") == "searchResEntry"]
        if code == 4 or len(entries) > 1:
            raise LdapDenied("ambiguous")
        if not entries:
            raise LdapDenied("not_found")
        e = entries[0]
        return e["dn"], {k: _as_list(v) for k, v in (e.get("attributes") or {}).items()}

    def groups_of(self, conn, dn: str, member_of: Iterable[str]) -> tuple[str, ...]:
        direct = {normalize_dn(g) for g in member_of}
        found = [g for g in self.cfg.group_roles if g in direct]
        if self.cfg.nested_groups:
            from ldap3 import BASE
            from ldap3.utils.conv import escape_filter_chars
            for g in self.cfg.group_roles:
                if g in found:
                    continue
                conn.search(dn, f"(memberOf:{_IN_CHAIN}:={escape_filter_chars(g)})", BASE,
                            attributes=["1.1"])
                if any(e.get("type") == "searchResEntry" for e in conn.response or []):
                    found.append(g)
        return tuple(sorted(found))

    def authenticate(self, login: str, password: str) -> LdapIdentity:
        login_c = clean_login(login)
        if login_c is None or not password or len(password) > MAX_PASSWORD_LEN:
            raise LdapDenied("bad_credentials")
        svc = self.service_connection()
        try:
            dn, attrs = self.find_user(svc, login_c)
            if self._bind(dn, password) is None:
                raise LdapDenied("bad_credentials")
            groups = self.groups_of(svc, dn, attrs.get("memberOf", []))
        finally:
            _unbind(svc)
        roles = frozenset().union(*(self.cfg.group_roles[g] for g in groups)) if groups else frozenset()
        if not roles:
            raise LdapDenied("no_group")
        name_vals = _lookup(attrs, self.cfg.username_attr)
        username = (str(name_vals[0]) if name_vals else login_c).strip().lower()
        disp = _lookup(attrs, self.cfg.display_name_attr)
        return LdapIdentity(username=username, dn=dn,
                            display_name=str(disp[0]) if disp else None,
                            groups=groups, roles=roles)


def _as_list(v) -> list:
    if v is None:
        return []
    return list(v) if isinstance(v, (list, tuple)) else [v]


def _lookup(attrs: dict[str, list], name: str) -> list:
    for k, v in attrs.items():
        if k.lower() == name.lower():
            return v
    return []


def _unbind(conn) -> None:
    with contextlib.suppress(Exception):   # закрытие соединения не должно ронять вход
        conn.unbind()
