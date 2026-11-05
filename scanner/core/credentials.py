"""Учётные записи активов: хранение секретов и выбор учётки для хоста.

Учётная запись (логин + пароль или SSH-ключ) заводится в договоре и
используется модулями аутентифицированной инвентаризации (`auth_inventory`) и
аудита конфигураций (`config_audit`). Для аудита конфигураций нужны права root:
поле `become` (`sudo` | `none`) говорит, повышать ли права через sudo.

Поле `protocol` (`ssh` | `winrm` | `netssh` | `snmp`) — способ входа. Учётки WinRM
(Windows, только пароль, логин `ДОМЕН\\user` или `user@домен`) использует модуль
`win_inventory`; учётки сетевого оборудования — `netssh` (SSH в CLI коммутатора
или маршрутизатора) и `snmp` (SNMPv2c community или SNMPv3 USM, только чтение) —
модуль `netdev_audit`. SSH-модули чужие учётки не видят: `credentials_for_host`
по умолчанию отдаёт только SSH.

Несекретные параметры учётки (платформа сетевого устройства, версия SNMP,
алгоритмы SNMPv3) — в `options`; секреты SNMP (community, ключи SNMPv3) шифруются
как пароль: community / ключ аутентификации — `password`, ключ шифрования
SNMPv3 — `passphrase`.

Безопасность:
- секреты (пароль, закрытый ключ, парольная фраза) хранятся в БД только
  зашифрованными (`CredentialVault`, Fernet: AES-128-CBC + HMAC-SHA256). Ключ
  шифрования — из окружения (`SCANNER_CREDENTIALS_KEY`, иначе
  `SCANNER_API_SECRET`); без ключа учётки нельзя ни завести, ни использовать;
- API секреты не возвращает (только метаданные и отпечаток открытого ключа),
  в аудит пишутся только id, имя, логин, порт и способ аутентификации;
- в `HostCredential` секреты помечены repr=False — не попадут в логи через repr;
- область действия учётки (`targets`) — IP/подсети, входящие в allowlist
  договора; пустая область — все цели прогона (они уже прошли allowlist).
"""
from __future__ import annotations

import base64
import hashlib
import io
import ipaddress
import json
import re
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field

from cryptography.fernet import Fernet, InvalidToken
from pydantic_settings import BaseSettings, SettingsConfigDict

AUTH_PASSWORD = "password"
AUTH_KEY = "key"
AUTH_KINDS = (AUTH_PASSWORD, AUTH_KEY)

# Повышение прав на хосте: sudo (пароль учётки подаётся sudo через stdin,
# для ключа — только NOPASSWD) или без повышения (вход сразу под root либо
# проверка без root — часть правил аудита конфигураций тогда не проверится).
BECOME_SUDO = "sudo"
BECOME_NONE = "none"
BECOME_KINDS = (BECOME_SUDO, BECOME_NONE)

# Способ входа на хост: SSH (Linux/Unix) или WinRM (Windows, HTTPS + NTLM).
PROTOCOL_SSH = "ssh"
PROTOCOL_WINRM = "winrm"
# Сетевое оборудование (netdev_audit): SSH в CLI устройства и SNMP только чтение.
PROTOCOL_NETSSH = "netssh"
PROTOCOL_SNMP = "snmp"
PROTOCOLS = (PROTOCOL_SSH, PROTOCOL_WINRM, PROTOCOL_NETSSH, PROTOCOL_SNMP)
NETDEV_PROTOCOLS = (PROTOCOL_NETSSH, PROTOCOL_SNMP)
DEFAULT_PORTS = {PROTOCOL_SSH: 22, PROTOCOL_WINRM: 5986, PROTOCOL_NETSSH: 22,
                 PROTOCOL_SNMP: 161}

# Платформы сетевых устройств (подсказка в учётке netssh; auto — определить по
# приглашению CLI и выводу show version / display version).
NETDEV_PLATFORMS = ("auto", "cisco_ios", "cisco_xe", "cisco_nxos", "cisco_asa", "junos",
                    "routeros", "huawei_vrp", "eltex_esr", "eltex_mes")
SNMP_VERSIONS = ("2c", "3")
SNMP_AUTH_PROTOCOLS = ("sha", "sha224", "sha256", "sha384", "sha512", "md5")
# aes192/aes256 — стандартное расширение ключа (Blumenthal), aes192c/aes256c —
# вариант Cisco (Reeder); des — устаревший, только для старых устройств.
SNMP_PRIV_PROTOCOLS = ("aes", "aes192", "aes256", "aes192c", "aes256c", "des", "none")

# Сколько учёток пробовать на одном хосте: учётки задаёт оператор, но
# серия неудачных входов может заблокировать учётную запись на цели.
MAX_CREDENTIALS_PER_HOST = 3

MAX_SECRET_LEN = 16 * 1024
_USER_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.@\\-]{0,127}$")


class CredentialError(ValueError):
    """Недопустимая учётная запись (логин, ключ, область действия)."""


class VaultUnavailable(RuntimeError):
    """Не задан ключ шифрования учётных записей."""


# ---------- шифрование ----------

class _VaultSettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="SCANNER_", env_file=".env",
                                      extra="ignore")

    credentials_key: str = ""
    api_secret: str = ""


class CredentialVault:
    """Шифрование секретов учётных записей ключом из окружения."""

    def __init__(self, material: str):
        if len(material) < 16:
            raise VaultUnavailable("ключ шифрования учётных записей короче 16 символов")
        digest = hashlib.sha256(b"scanner-credentials:" + material.encode()).digest()
        self._fernet = Fernet(base64.urlsafe_b64encode(digest))

    def encrypt(self, secrets: dict[str, str | None]) -> str:
        data = json.dumps({k: v for k, v in secrets.items() if v}).encode()
        return self._fernet.encrypt(data).decode()

    def decrypt(self, token: str) -> dict[str, str]:
        try:
            return json.loads(self._fernet.decrypt(token.encode()))
        except (InvalidToken, ValueError) as e:
            raise VaultUnavailable("не удалось расшифровать учётную запись: "
                                   "ключ шифрования изменился?") from e

    def encrypt_entries(self, entries: list[tuple[str, str]]) -> str:
        """Шифрует список пар логин/секрет набора проверки учёток.

        В отличие от `encrypt`, не отбрасывает пустые значения: пустой пароль —
        допустимая и важная для проверки запись, он должен сохраниться.
        """
        data = json.dumps([[u, s] for u, s in entries]).encode()
        return self._fernet.encrypt(data).decode()

    def decrypt_entries(self, token: str) -> list[tuple[str, str]]:
        try:
            raw = json.loads(self._fernet.decrypt(token.encode()))
            return [(str(u), str(s)) for u, s in raw]
        except (InvalidToken, ValueError, TypeError) as e:
            raise VaultUnavailable("не удалось расшифровать набор проверки учёток: "
                                   "ключ шифрования изменился?") from e


def load_vault(material: str | None = None) -> CredentialVault | None:
    """Хранилище из окружения: SCANNER_CREDENTIALS_KEY, иначе SCANNER_API_SECRET.

    None — ключ не задан (или слишком короткий): учётки недоступны.
    """
    if material is None:
        s = _VaultSettings()
        material = s.credentials_key or s.api_secret
    try:
        return CredentialVault(material) if material else None
    except VaultUnavailable:
        return None


# ---------- ключи SSH ----------

def load_private_key(text: str, passphrase: str | None = None):
    """Закрытый ключ OpenSSH/PEM -> paramiko.PKey. CredentialError на мусоре."""
    import paramiko

    for cls in (paramiko.Ed25519Key, paramiko.ECDSAKey, paramiko.RSAKey):
        try:
            return cls.from_private_key(io.StringIO(text), password=passphrase or None)
        except paramiko.PasswordRequiredException as e:
            raise CredentialError("ключ зашифрован: укажите парольную фразу") from e
        except (paramiko.SSHException, ValueError, TypeError):
            continue
    raise CredentialError("не удалось прочитать закрытый ключ SSH "
                          "(поддерживаются Ed25519, ECDSA, RSA; формат OpenSSH/PEM)")


def key_fingerprint(text: str, passphrase: str | None = None) -> str:
    """Отпечаток открытого ключа в формате OpenSSH: SHA256:<base64>."""
    pkey = load_private_key(text, passphrase)
    digest = hashlib.sha256(pkey.asbytes()).digest()
    return "SHA256:" + base64.b64encode(digest).decode().rstrip("=")


# ---------- область действия ----------

def normalize_scope(targets: Iterable[str]) -> list[str]:
    """IP и подсети области действия -> нормализованные CIDR (без повторов)."""
    out: list[str] = []
    for raw in targets:
        spec = raw.strip()
        if not spec:
            continue
        try:
            net = ipaddress.ip_network(spec, strict=False)
        except ValueError as e:
            raise CredentialError(f"не IP/подсеть: {spec}") from e
        if str(net) not in out:
            out.append(str(net))
    return out


def validate_username(username: str) -> str:
    username = username.strip()
    if not _USER_RE.match(username):
        raise CredentialError(f"недопустимый логин: {username!r}")
    return username


# ---------- наборы проверки учёток (аудит паролей) ----------

# Жёсткий лимит записей в одном наборе: набор задаёт оператор под договор,
# встроенных словарей нет; лимит отсекает попытку залить массовый список.
MAX_CRED_SET_ENTRIES = 200


def validate_cred_set_entries(
        entries: Iterable[tuple[str, str]]) -> list[tuple[str, str]]:
    """Проверяет пары логин/секрет набора. Секрет в текст ошибки не попадает.

    Логин проверяется мягче, чем у учёток активов (допускаются доменные формы);
    пустой секрет допустим — это проверка пустого пароля. CredentialError —
    недопустимые данные или превышение лимита записей.
    """
    out: list[tuple[str, str]] = []
    for username, secret in entries:
        u = (username or "").strip()
        if not u or any(c in u for c in "\x00\r\n"):
            raise CredentialError("логин: пустой или содержит управляющие символы")
        if any(c in secret for c in "\x00\r\n"):
            raise CredentialError(f"секрет учётки {u!r}: управляющие символы недопустимы")
        if len(u) > 128 or len(secret) > MAX_SECRET_LEN:
            raise CredentialError(f"логин или секрет учётки {u!r} слишком длинный")
        out.append((u, secret))
    if not out:
        raise CredentialError("набор пуст: добавьте хотя бы одну запись логин/пароль")
    if len(out) > MAX_CRED_SET_ENTRIES:
        raise CredentialError(
            f"в наборе больше {MAX_CRED_SET_ENTRIES} записей — уменьшите список")
    return out


def mask_username(username: str) -> str:
    """Маскированный логин для выдачи наружу: видно начало, остальное скрыто."""
    u = username.strip()
    if len(u) <= 2:
        return u[:1] + "*"
    return u[:2] + "*" * min(len(u) - 2, 6)


# ---------- учётка в прогоне ----------

@dataclass(frozen=True, slots=True)
class HostCredential:
    """Расшифрованная учётка для прогона. Секреты не выводятся в repr."""
    id: int
    name: str
    auth: str                                   # password | key
    username: str
    port: int = 22
    targets: tuple[str, ...] = ()               # CIDR; пусто — все цели прогона
    password: str | None = field(default=None, repr=False)
    private_key: str | None = field(default=None, repr=False)
    passphrase: str | None = field(default=None, repr=False)
    become: str = BECOME_SUDO                   # sudo | none
    protocol: str = PROTOCOL_SSH                # ssh | winrm | netssh | snmp
    # Несекретные параметры: platform (netssh), snmp_version/auth_proto/priv_proto.
    options: dict = field(default_factory=dict, compare=False, hash=False)

    def scope_prefix(self, host: str) -> int | None:
        """Длина префикса самой узкой подсети области, куда входит хост.

        -1 — учётка без области (подходит любому хосту), None — не подходит.
        """
        if not self.targets:
            return -1
        addr = ipaddress.ip_address(host)
        best = None
        for t in self.targets:
            net = ipaddress.ip_network(t, strict=False)
            if addr.version == net.version and addr in net:
                best = net.prefixlen if best is None else max(best, net.prefixlen)
        return best

    def describe(self) -> dict[str, object]:
        """Описание для аудита и находок — без секретов."""
        out: dict[str, object] = {
            "credential_id": self.id, "credential": self.name, "user": self.username,
            "port": self.port, "auth": self.auth, "become": self.become,
            "protocol": self.protocol}
        if self.options:
            out["options"] = dict(self.options)
        return out


def validate_become(become: str) -> str:
    if become not in BECOME_KINDS:
        raise CredentialError(f"недопустимое повышение прав: {become!r} "
                              f"(допустимо: {', '.join(BECOME_KINDS)})")
    return become


def validate_protocol(protocol: str) -> str:
    if protocol not in PROTOCOLS:
        raise CredentialError(f"недопустимый протокол входа: {protocol!r} "
                              f"(допустимо: {', '.join(PROTOCOLS)})")
    return protocol


def validate_options(protocol: str, options: dict | None) -> dict:
    """Несекретные параметры учётки по протоколу; лишние ключи отбрасываются.

    netssh: platform (NETDEV_PLATFORMS, по умолчанию auto).
    snmp: snmp_version (2c | 3), для v3 — auth_proto и priv_proto.
    """
    raw = dict(options or {})
    if protocol == PROTOCOL_NETSSH:
        platform = str(raw.get("platform") or "auto")
        if platform not in NETDEV_PLATFORMS:
            raise CredentialError(f"неизвестная платформа устройства: {platform!r} "
                                  f"(допустимо: {', '.join(NETDEV_PLATFORMS)})")
        return {"platform": platform}
    if protocol == PROTOCOL_SNMP:
        version = str(raw.get("snmp_version") or "3")
        if version not in SNMP_VERSIONS:
            raise CredentialError(f"версия SNMP: {version!r} (допустимо: 2c, 3)")
        if version == "2c":
            return {"snmp_version": "2c"}
        auth = str(raw.get("auth_proto") or "sha").lower()
        priv = str(raw.get("priv_proto") or "aes").lower()
        if auth not in SNMP_AUTH_PROTOCOLS:
            raise CredentialError(f"алгоритм аутентификации SNMPv3: {auth!r} "
                                  f"(допустимо: {', '.join(SNMP_AUTH_PROTOCOLS)})")
        if priv not in SNMP_PRIV_PROTOCOLS:
            raise CredentialError(f"алгоритм шифрования SNMPv3: {priv!r} "
                                  f"(допустимо: {', '.join(SNMP_PRIV_PROTOCOLS)})")
        return {"snmp_version": "3", "auth_proto": auth, "priv_proto": priv}
    return {}


def credentials_for_host(host: str, creds: Sequence[HostCredential],
                         limit: int = MAX_CREDENTIALS_PER_HOST, *,
                         protocol: str = PROTOCOL_SSH) -> list[HostCredential]:
    """Учётки, применимые к хосту: сначала с самой узкой областью действия.

    Только учётки нужного протокола: по умолчанию SSH — модули, входящие по
    SSH, никогда не получат учётку WinRM (и наоборот, если просить winrm).
    """
    ranked = [(p, i, c) for i, c in enumerate(creds)
              if c.protocol == protocol and (p := c.scope_prefix(host)) is not None]
    ranked.sort(key=lambda x: (-x[0], x[1]))
    return [c for _, _, c in ranked[:limit]]
