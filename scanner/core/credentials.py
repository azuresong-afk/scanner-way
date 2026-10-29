"""Учётные записи активов: хранение секретов и выбор учётки для хоста.

Учётная запись (логин + пароль или SSH-ключ) заводится в договоре и
используется модулем аутентифицированной инвентаризации (`auth_inventory`).

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
        return {"credential_id": self.id, "credential": self.name,
                "user": self.username, "port": self.port, "auth": self.auth}


def credentials_for_host(host: str, creds: Sequence[HostCredential],
                         limit: int = MAX_CREDENTIALS_PER_HOST) -> list[HostCredential]:
    """Учётки, применимые к хосту: сначала с самой узкой областью действия."""
    ranked = [(p, i, c) for i, c in enumerate(creds)
              if (p := c.scope_prefix(host)) is not None]
    ranked.sort(key=lambda x: (-x[0], x[1]))
    return [c for _, _, c in ranked[:limit]]
