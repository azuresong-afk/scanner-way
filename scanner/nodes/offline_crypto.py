"""Ключи и криптография автономного режима узлов-сканеров.

У каждой стороны (центр и автономный узел) две пары ключей:

* Ed25519 — подпись файлов. Центр подписывает задание, узел — результат;
  получатель проверяет подпись по заранее закреплённому открытому ключу
  отправителя (ключ центра ставится на узел при установке, ключ узла
  загружается в карточку узла в центре).
* X25519 — шифрование для получателя. Тело задания (цели, учётные записи)
  шифруется на ключ узла, тело результата (находки) — на ключ центра. Схема:
  эфемерный X25519 -> HKDF-SHA256 -> AES-256-GCM; заголовок файла входит в
  дополнительные данные AEAD, поэтому его нельзя подменить, не сломав
  расшифровку.

Открытые ключи передаются одной строкой ``scanner-node-key:v1:<b64 sign>:<b64 enc>``
(``scanner-center-key:…`` для центра). Отпечаток — первые 16 байт SHA-256
от обоих открытых ключей, в виде ``ab12-cd34-…``: его сверяют по телефону
или по акту при установке, как отпечаток SSH-ключа.

Закрытые ключи центра не хранятся: они выводятся HKDF из секрета, которым
уже шифруются учётные записи (SCANNER_CREDENTIALS_KEY, иначе SCANNER_API_SECRET).
Смена секрета = смена ключа центра, и тогда ключ центра нужно заново
поставить на автономные узлы (как и учётки, зашифрованные прежним секретом,
перестают читаться).
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
from dataclasses import dataclass, field

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

ROLE_NODE = "node"
ROLE_CENTER = "center"
_PREFIX = {ROLE_NODE: "scanner-node-key", ROLE_CENTER: "scanner-center-key"}
KEY_VERSION = "v1"
ENC_ALG = "X25519-HKDF-SHA256-AES256GCM"
SIG_ALG = "Ed25519"
_RAW = serialization.Encoding.Raw
_RAW_PUB = serialization.PublicFormat.Raw
_RAW_PRIV = serialization.PrivateFormat.Raw
_NOENC = serialization.NoEncryption()


class OfflineCryptoError(Exception):
    """Ключ повреждён, подпись не сходится или файл зашифрован не для нас."""


def b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def b64d(text: str, what: str = "данные") -> bytes:
    try:
        return base64.b64decode(text.encode("ascii"), validate=True)
    except (ValueError, UnicodeEncodeError, AttributeError) as e:
        raise OfflineCryptoError(f"{what}: не base64") from e


def canonical(obj: object) -> bytes:
    """Однозначная сериализация для подписи и AAD."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


# ========== Открытые ключи ==========
@dataclass(frozen=True, slots=True)
class PublicKeys:
    role: str
    sign: bytes          # Ed25519, 32 байта
    enc: bytes           # X25519, 32 байта

    @property
    def fingerprint(self) -> str:
        return fingerprint(self.sign, self.enc)

    def export(self) -> str:
        return f"{_PREFIX[self.role]}:{KEY_VERSION}:{b64e(self.sign)}:{b64e(self.enc)}"

    def verify(self, signature: bytes, data: bytes) -> None:
        try:
            Ed25519PublicKey.from_public_bytes(self.sign).verify(signature, data)
        except (InvalidSignature, ValueError) as e:
            raise OfflineCryptoError("подпись не сходится") from e


def fingerprint(sign: bytes, enc: bytes) -> str:
    h = hashlib.sha256(b"scanner-offline-fp\0" + sign + enc).hexdigest()[:32]
    return "-".join(h[i:i + 4] for i in range(0, 32, 4))


def parse_public(text: str, role: str) -> PublicKeys:
    """Строка открытого ключа -> ключи. Ключ чужой роли не принимается:
    ключ центра нельзя по ошибке загрузить как ключ узла и наоборот."""
    raw = (text or "").strip()
    # файл ключа может содержать комментарии (# …) — берём первую строку ключа
    lines = [ln.strip() for ln in raw.splitlines()
             if ln.strip() and not ln.lstrip().startswith("#")]
    if not lines:
        raise OfflineCryptoError("пустой ключ")
    parts = lines[0].split(":")
    if len(parts) != 4 or parts[0] not in _PREFIX.values():
        raise OfflineCryptoError("не похоже на открытый ключ сканера "
                                 "(ожидается scanner-node-key:v1:… или scanner-center-key:v1:…)")
    if parts[0] != _PREFIX[role]:
        want = "узла" if role == ROLE_NODE else "центра"
        raise OfflineCryptoError(f"это не ключ {want}")
    if parts[1] != KEY_VERSION:
        raise OfflineCryptoError(f"неизвестная версия ключа: {parts[1]}")
    sign, enc = b64d(parts[2], "ключ подписи"), b64d(parts[3], "ключ шифрования")
    if len(sign) != 32 or len(enc) != 32:
        raise OfflineCryptoError("неверная длина ключа")
    try:
        Ed25519PublicKey.from_public_bytes(sign)
        X25519PublicKey.from_public_bytes(enc)
    except ValueError as e:
        raise OfflineCryptoError("ключ повреждён") from e
    return PublicKeys(role, sign, enc)


# ========== Закрытые ключи ==========
@dataclass(slots=True)
class KeyPair:
    role: str
    sign_key: Ed25519PrivateKey = field(repr=False)
    enc_key: X25519PrivateKey = field(repr=False)

    @classmethod
    def generate(cls, role: str) -> KeyPair:
        return cls(role, Ed25519PrivateKey.generate(), X25519PrivateKey.generate())

    @classmethod
    def derive(cls, role: str, secret: str | bytes, *, purpose: str) -> KeyPair:
        """Детерминированные ключи из секрета (ключи центра)."""
        if not secret:
            raise OfflineCryptoError("не задан секрет для ключей центра")
        ikm = secret.encode("utf-8") if isinstance(secret, str) else secret

        def _hkdf(info: str) -> bytes:
            return HKDF(algorithm=hashes.SHA256(), length=32,
                        salt=b"scanner-offline-v1", info=info.encode()).derive(ikm)

        return cls(role,
                   Ed25519PrivateKey.from_private_bytes(_hkdf(f"{purpose}:sign")),
                   X25519PrivateKey.from_private_bytes(_hkdf(f"{purpose}:enc")))

    @property
    def public(self) -> PublicKeys:
        return PublicKeys(self.role,
                          self.sign_key.public_key().public_bytes(_RAW, _RAW_PUB),
                          self.enc_key.public_key().public_bytes(_RAW, _RAW_PUB))

    def sign(self, data: bytes) -> bytes:
        return self.sign_key.sign(data)

    # --- хранение (только ключи узла; файл с правами 0600) ---
    def to_json(self) -> dict:
        return {"role": self.role, "version": KEY_VERSION,
                "sign": b64e(self.sign_key.private_bytes(_RAW, _RAW_PRIV, _NOENC)),
                "enc": b64e(self.enc_key.private_bytes(_RAW, _RAW_PRIV, _NOENC))}

    @classmethod
    def from_json(cls, data: dict) -> KeyPair:
        try:
            if data.get("version") != KEY_VERSION:
                raise OfflineCryptoError("неизвестная версия файла ключей")
            return cls(str(data["role"]),
                       Ed25519PrivateKey.from_private_bytes(b64d(data["sign"], "ключ")),
                       X25519PrivateKey.from_private_bytes(b64d(data["enc"], "ключ")))
        except (KeyError, TypeError, ValueError) as e:
            raise OfflineCryptoError("файл ключей повреждён") from e


# ========== Шифрование для получателя ==========
def _kdf(shared: bytes, epk: bytes, recipient: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=epk + recipient,
                info=b"scanner-offline-seal-v1").derive(shared)


def seal(plaintext: bytes, recipient: PublicKeys, aad: bytes) -> dict:
    """Шифрует для владельца recipient.enc. Возвращает {alg, epk, nonce, ct}."""
    eph = X25519PrivateKey.generate()
    epk = eph.public_key().public_bytes(_RAW, _RAW_PUB)
    shared = eph.exchange(X25519PublicKey.from_public_bytes(recipient.enc))
    key = _kdf(shared, epk, recipient.enc)
    nonce = os.urandom(12)
    ct = AESGCM(key).encrypt(nonce, plaintext, aad)
    return {"alg": ENC_ALG, "epk": b64e(epk), "nonce": b64e(nonce), "ct": b64e(ct)}


def unseal(box: dict, keys: KeyPair, aad: bytes) -> bytes:
    if not isinstance(box, dict) or box.get("alg") != ENC_ALG:
        raise OfflineCryptoError("неизвестный алгоритм шифрования")
    epk = b64d(box.get("epk", ""), "epk")
    nonce = b64d(box.get("nonce", ""), "nonce")
    ct = b64d(box.get("ct", ""), "шифртекст")
    my_pub = keys.public.enc
    try:
        shared = keys.enc_key.exchange(X25519PublicKey.from_public_bytes(epk))
        return AESGCM(_kdf(shared, epk, my_pub)).decrypt(nonce, ct, aad)
    except (InvalidTag, ValueError) as e:
        raise OfflineCryptoError("не удалось расшифровать: файл повреждён "
                                 "или зашифрован не для этого ключа") from e
