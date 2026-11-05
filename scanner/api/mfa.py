"""Двухфакторный вход: одноразовые коды TOTP (RFC 6238) и коды восстановления.

Без внешних сервисов: код считает приложение-аутентификатор на телефоне
(Яндекс Ключ, Google Authenticator, FreeOTP, …) из общего секрета, который
пользователь один раз сканирует QR-кодом. Параметры — стандартные для всех
приложений: SHA-1, 6 цифр, шаг 30 секунд; допускается расхождение часов на
один шаг в обе стороны. Принятый шаг запоминается (`users.mfa_last_step`),
поэтому подсмотренный код нельзя использовать повторно.

Секрет хранится в БД зашифрованным тем же ключом, что и учётные записи
активов (`CredentialVault`), коды восстановления — только хэшами SHA-256
(у них 50 бит случайности, перебор по хэшу бессмыслен).
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import struct
import time
from urllib.parse import quote, urlencode

STEP_SECONDS = 30
DIGITS = 6
WINDOW = 1            # шагов в каждую сторону (расхождение часов телефона)
RECOVERY_CODES = 10
_RECOVERY_ALPHABET = "abcdefghjkmnpqrstuvwxyz23456789"   # без похожих 0/o, 1/l/i


def new_secret() -> str:
    """Случайный секрет 160 бит в base32 без «=» (так его ждут приложения)."""
    return base64.b32encode(secrets.token_bytes(20)).decode().rstrip("=")


def _key(secret: str) -> bytes:
    s = secret.strip().replace(" ", "").upper()
    return base64.b32decode(s + "=" * (-len(s) % 8))


def code_at(secret: str, step: int) -> str:
    digest = hmac.new(_key(secret), struct.pack(">Q", step), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    value = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(value % 10**DIGITS).zfill(DIGITS)


def current_step(now: float | None = None) -> int:
    return int((time.time() if now is None else now) // STEP_SECONDS)


def verify_code(secret: str, code: str, *, last_step: int | None,
                now: float | None = None) -> int | None:
    """Шаг, которому соответствует код, или None (неверный или уже использован)."""
    code = "".join(ch for ch in code if not ch.isspace())
    if len(code) != DIGITS or not code.isdigit():
        return None
    base = current_step(now)
    for step in range(base - WINDOW, base + WINDOW + 1):
        if last_step is not None and step <= last_step:
            continue
        if hmac.compare_digest(code_at(secret, step), code):
            return step
    return None


def otpauth_uri(secret: str, *, account: str, issuer: str) -> str:
    """Ссылка otpauth:// — её содержит QR-код для приложения-аутентификатора."""
    label = quote(f"{issuer}:{account}", safe=":@")
    query = urlencode({"secret": secret, "issuer": issuer, "algorithm": "SHA1",
                       "digits": DIGITS, "period": STEP_SECONDS})
    return f"otpauth://totp/{label}?{query}"


def qr_svg(text: str) -> str | None:
    """QR-код в SVG (для показа в интерфейсе) или None, если segno не установлен.

    Без QR-кода пользователь вводит секрет в приложение вручную.
    """
    try:
        import segno
    except ImportError:            # pragma: no cover - segno в зависимостях
        return None
    import io
    buf = io.BytesIO()
    segno.make(text, error="m").save(buf, kind="svg", scale=6, border=2,
                                     xmldecl=False, svgns=True, dark="#000",
                                     light="#fff")
    return buf.getvalue().decode()


# ---------- коды восстановления ----------

def new_recovery_codes(n: int = RECOVERY_CODES) -> list[str]:
    """Одноразовые коды на случай потери телефона: «xxxxx-xxxxx»."""
    def one() -> str:
        raw = "".join(secrets.choice(_RECOVERY_ALPHABET) for _ in range(10))
        return f"{raw[:5]}-{raw[5:]}"
    return [one() for _ in range(n)]


def _norm_recovery(code: str) -> str:
    return "".join(ch for ch in code.lower() if ch.isalnum())


def hash_recovery(code: str) -> str:
    return hashlib.sha256(b"scanner-mfa-recovery:" + _norm_recovery(code).encode()).hexdigest()


def use_recovery(code: str, hashes: list[str] | None) -> list[str] | None:
    """Новый список хэшей без использованного кода или None (код не подошёл)."""
    if not hashes or len(_norm_recovery(code)) != 10:
        return None
    h = hash_recovery(code)
    for i, stored in enumerate(hashes):
        if hmac.compare_digest(stored, h):
            return hashes[:i] + hashes[i + 1:]
    return None
