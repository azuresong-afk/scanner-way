"""Пароли (scrypt) и подписанные токены доступа (HMAC-SHA256).

Без внешних зависимостей: только стандартная библиотека. Токен —
`base64url(payload).base64url(hmac)`, payload = {"uid", "iat", "exp"[, "typ"][, "sid"]}.
`typ` отличает промежуточный токен второго шага входа (2FA, typ="mfa") от токена
доступа: токен без `typ` — токен доступа (так выпускались и раньше). Права в
токен не кладутся: они читаются из БД на каждый запрос, поэтому отзыв роли или
блокировка пользователя действуют сразу.

`sid` — сеанс входа (таблица auth_sessions, миграция 0030): токен доступа
принимается, только пока его сеанс не отозван, поэтому выход действует сразу,
а не по истечении срока токена (scanner.api.sessions).
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import threading
import time
from collections.abc import Callable

_SCRYPT_N, _SCRYPT_R, _SCRYPT_P = 2**14, 8, 1
# Типы токенов: доступ к API и промежуточный — между паролем и кодом 2FA.
ACCESS = "access"
MFA_PENDING = "mfa"
# Хэш-заглушка пользователя без локального пароля (вход через каталог): ни один
# пароль с ним не совпадёт — verify_password вернёт False.
NO_PASSWORD = "!external"
MIN_PASSWORD_LEN = 12


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    dk = hashlib.scrypt(password.encode(), salt=salt, n=_SCRYPT_N, r=_SCRYPT_R,
                        p=_SCRYPT_P, dklen=32)
    return f"scrypt${_SCRYPT_N}${_SCRYPT_R}${_SCRYPT_P}${salt.hex()}${dk.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        algo, n, r, p, salt, dk = stored.split("$")
        if algo != "scrypt":
            return False
        got = hashlib.scrypt(password.encode(), salt=bytes.fromhex(salt), n=int(n),
                             r=int(r), p=int(p), dklen=len(bytes.fromhex(dk)))
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(got.hex(), dk)


# Хэш-пустышка: verify для несуществующего пользователя занимает то же время.
DUMMY_HASH = hash_password(secrets.token_urlsafe(16))


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _unb64(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


class TokenSigner:
    def __init__(self, secret: str, ttl_seconds: int,
                 clock: Callable[[], float] = time.time):
        if len(secret) < 32:
            raise ValueError("token secret must be at least 32 characters")
        self._key = secret.encode()
        self.ttl = ttl_seconds
        self._clock = clock

    def _sig(self, body: str) -> str:
        return _b64(hmac.new(self._key, body.encode(), hashlib.sha256).digest())

    def issue(self, user_id: int, *, typ: str = ACCESS, ttl: int | None = None,
              sid: str | None = None, not_after: int | None = None) -> str:
        """Подписанный токен. not_after — срок не позже этого момента (unix-время):
        токен сеанса не переживает предельный срок самого сеанса."""
        now = int(self._clock())
        exp = now + (self.ttl if ttl is None else ttl)
        if not_after is not None:
            exp = min(exp, int(not_after))
        payload: dict[str, object] = {"uid": user_id, "iat": now, "exp": exp}
        if typ != ACCESS:
            payload["typ"] = typ
        if sid is not None:
            payload["sid"] = sid
        body = _b64(json.dumps(payload, separators=(",", ":")).encode())
        return f"{body}.{self._sig(body)}"

    def verify(self, token: str, *, typ: str = ACCESS) -> int | None:
        """user_id или None (подпись неверна / токен истёк / не того типа / мусор)."""
        claims = self.claims(token, typ=typ)
        return None if claims is None else claims[0]

    def claims(self, token: str, *, typ: str = ACCESS) -> tuple[int, str | None, int] | None:
        """(user_id, sid, exp) или None — те же проверки, что у verify."""
        try:
            body, sig = token.split(".")
            if not hmac.compare_digest(sig, self._sig(body)):
                return None
            payload = json.loads(_unb64(body))
            if int(payload["exp"]) < self._clock():
                return None
            if payload.get("typ", ACCESS) != typ:
                return None
            sid = payload.get("sid")
            return int(payload["uid"]), (str(sid) if sid is not None else None), \
                int(payload["exp"])
        except (ValueError, KeyError, TypeError):
            return None


class LoginThrottle:
    """Пауза после N неудачных входов подряд для одного имени (в памяти процесса)."""

    def __init__(self, max_failures: int, lockout_seconds: int,
                 clock: Callable[[], float] = time.monotonic):
        self.max_failures = max_failures
        self.lockout = lockout_seconds
        self._clock = clock
        self._state: dict[str, tuple[int, float]] = {}   # имя -> (неудач, до когда)
        self._lock = threading.Lock()

    def locked(self, username: str) -> bool:
        with self._lock:
            _, until = self._state.get(username, (0, 0.0))
            return until > self._clock()

    def failure(self, username: str) -> None:
        with self._lock:
            n, _ = self._state.get(username, (0, 0.0))
            n += 1
            until = self._clock() + self.lockout if n >= self.max_failures else 0.0
            self._state[username] = (0 if until else n, until)

    def success(self, username: str) -> None:
        with self._lock:
            self._state.pop(username, None)
