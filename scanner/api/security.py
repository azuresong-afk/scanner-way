"""Пароли (scrypt) и подписанные токены доступа (HMAC-SHA256).

Без внешних зависимостей: только стандартная библиотека. Токен —
`base64url(payload).base64url(hmac)`, payload = {"uid", "iat", "exp"}. Права в
токен не кладутся: они читаются из БД на каждый запрос, поэтому отзыв роли или
блокировка пользователя действуют сразу.
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

    def issue(self, user_id: int) -> str:
        now = int(self._clock())
        body = _b64(json.dumps({"uid": user_id, "iat": now, "exp": now + self.ttl},
                               separators=(",", ":")).encode())
        return f"{body}.{self._sig(body)}"

    def verify(self, token: str) -> int | None:
        """user_id или None (подпись неверна / токен истёк / мусор)."""
        try:
            body, sig = token.split(".")
            if not hmac.compare_digest(sig, self._sig(body)):
                return None
            payload = json.loads(_unb64(body))
            if int(payload["exp"]) < self._clock():
                return None
            return int(payload["uid"])
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
