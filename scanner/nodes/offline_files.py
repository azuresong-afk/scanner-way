"""Файлы автономного режима: задание (центр -> узел) и результат (узел -> центр).

Файл — один JSON-документ (UTF-8), его можно открыть и прочитать заголовок
глазами, но не тело:

    {
      "format":  "scanner-offline-job" | "scanner-offline-result",
      "version": 1,
      "header":  {…открытая сводка: id задания, прогон, узел, сроки, счётчики,
                  отпечатки ключей отправителя и получателя…},
      "box":     {"alg": "X25519-HKDF-SHA256-AES256GCM", "epk", "nonce", "ct"},
      "sig_alg": "Ed25519",
      "sig":     "<подпись отправителя над всем документом без поля sig>"
    }

* Тело (`box`) — gzip(JSON) зашифрованный на ключ получателя; заголовок —
  дополнительные данные AEAD, поэтому заголовок от другого тела не подставить.
* Подпись покрывает и заголовок, и шифртекст: проверяется ДО расшифровки,
  чужой или изменённый файл отклоняется, не доходя до разбора тела.
* Размеры ограничены (файл и распакованное тело), чтобы файл с носителя не
  исчерпал память («gzip-бомба»).
"""
from __future__ import annotations

import hashlib
import json
import zlib
from dataclasses import dataclass
from typing import Any

from scanner.nodes.offline_crypto import (
    SIG_ALG,
    KeyPair,
    OfflineCryptoError,
    PublicKeys,
    b64d,
    b64e,
    canonical,
    seal,
    unseal,
)

FORMAT_JOB = "scanner-offline-job"
FORMAT_RESULT = "scanner-offline-result"
FILE_VERSION = 1
FILE_SUFFIX = {FORMAT_JOB: ".scnjob", FORMAT_RESULT: ".scnres"}
MAX_FILE_BYTES = 256 * 1024 * 1024        # файл на носителе
MAX_BODY_BYTES = 1024 * 1024 * 1024       # тело после распаковки
_FORMAT_LABEL = {FORMAT_JOB: "файл задания", FORMAT_RESULT: "файл результата"}


class OfflineFileError(Exception):
    """Файл не принят: не тот формат, подпись, получатель, повреждён."""


@dataclass(slots=True)
class Envelope:
    format: str
    header: dict[str, Any]
    doc: dict[str, Any]
    sha256: str              # хеш файла целиком — для журнала и защиты от повтора

    def verify(self, signer: PublicKeys) -> None:
        """Подпись отправителя и совпадение отпечатка в заголовке."""
        if self.header.get("signer") != signer.fingerprint:
            raise OfflineFileError(
                f"{_FORMAT_LABEL[self.format]} подписан другим ключом "
                f"(в файле {self.header.get('signer')}, ожидается {signer.fingerprint})")
        unsigned = {k: v for k, v in self.doc.items() if k != "sig"}
        try:
            signer.verify(b64d(str(self.doc.get("sig", "")), "подпись"), canonical(unsigned))
        except OfflineCryptoError as e:
            raise OfflineFileError(f"{_FORMAT_LABEL[self.format]}: подпись не сходится — "
                                   "файл изменён или подделан") from e

    def open(self, keys: KeyPair) -> dict[str, Any]:
        """Расшифровать тело. Вызывать только после verify()."""
        if self.header.get("recipient") != keys.public.fingerprint:
            raise OfflineFileError(
                f"{_FORMAT_LABEL[self.format]} выпущен для другого получателя "
                f"({self.header.get('recipient')}), а ключ здесь {keys.public.fingerprint}")
        try:
            packed = unseal(self.doc["box"], keys, _aad(self.format, self.header))
        except OfflineCryptoError as e:
            raise OfflineFileError(str(e)) from e
        try:
            d = zlib.decompressobj(wbits=31)      # gzip
            raw = d.decompress(packed, MAX_BODY_BYTES + 1)
            if len(raw) > MAX_BODY_BYTES or d.unconsumed_tail:
                raise OfflineFileError("тело файла слишком большое")
            body = json.loads(raw.decode("utf-8"))
        except (zlib.error, UnicodeDecodeError, ValueError) as e:
            raise OfflineFileError("тело файла повреждено") from e
        if not isinstance(body, dict):
            raise OfflineFileError("тело файла повреждено")
        return body


def _aad(fmt: str, header: dict[str, Any]) -> bytes:
    return canonical({"format": fmt, "version": FILE_VERSION, "header": header})


def build(fmt: str, header: dict[str, Any], body: dict[str, Any], *,
          signer: KeyPair, recipient: PublicKeys) -> bytes:
    """Подписанный и зашифрованный файл. В header дописываются отпечатки."""
    header = {**header, "signer": signer.public.fingerprint,
              "recipient": recipient.fingerprint}
    packed = zlib.compressobj(6, zlib.DEFLATED, 31)
    plain = packed.compress(canonical(body)) + packed.flush()
    doc: dict[str, Any] = {"format": fmt, "version": FILE_VERSION, "header": header,
                           "box": seal(plain, recipient, _aad(fmt, header)),
                           "sig_alg": SIG_ALG}
    doc["sig"] = b64e(signer.sign(canonical(doc)))
    data = json.dumps(doc, ensure_ascii=False, indent=1).encode("utf-8")
    if len(data) > MAX_FILE_BYTES:
        raise OfflineFileError("файл получился больше допустимого размера")
    return data


def parse(data: bytes, fmt: str) -> Envelope:
    """Разобрать файл без проверки подписи (заголовок — для показа и поиска ключа)."""
    label = _FORMAT_LABEL[fmt]
    if len(data) > MAX_FILE_BYTES:
        raise OfflineFileError(f"{label} слишком большой")
    try:
        doc = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as e:
        raise OfflineFileError(f"это не {label} сканера (не JSON)") from e
    if not isinstance(doc, dict):
        raise OfflineFileError(f"это не {label} сканера")
    got = doc.get("format")
    if got != fmt:
        other = _FORMAT_LABEL.get(str(got))
        raise OfflineFileError(f"ожидается {label}, а это {other}" if other
                               else f"это не {label} сканера")
    if doc.get("version") != FILE_VERSION:
        raise OfflineFileError(f"{label}: неподдерживаемая версия {doc.get('version')}")
    if doc.get("sig_alg") != SIG_ALG or not isinstance(doc.get("header"), dict) \
            or not isinstance(doc.get("box"), dict):
        raise OfflineFileError(f"{label} повреждён")
    return Envelope(fmt, doc["header"], doc, hashlib.sha256(data).hexdigest())
