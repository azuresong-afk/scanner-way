"""Автономный режим: ключи, подпись и шифрование файлов задания/результата."""
from __future__ import annotations

import json
import zlib

import pytest

from scanner.nodes import offline_files as of
from scanner.nodes.offline_crypto import (
    ROLE_CENTER,
    ROLE_NODE,
    KeyPair,
    OfflineCryptoError,
    parse_public,
)


@pytest.fixture
def center():
    return KeyPair.derive(ROLE_CENTER, "a-very-long-secret-value", purpose="scanner-center")


@pytest.fixture
def node():
    return KeyPair.generate(ROLE_NODE)


def test_center_keys_deterministic_and_secret_bound():
    a = KeyPair.derive(ROLE_CENTER, "secret-1234567890", purpose="p")
    b = KeyPair.derive(ROLE_CENTER, "secret-1234567890", purpose="p")
    c = KeyPair.derive(ROLE_CENTER, "secret-0987654321", purpose="p")
    assert a.public == b.public
    assert a.public.fingerprint != c.public.fingerprint


def test_public_key_roundtrip_and_role_check(node, center):
    text = f"# комментарий\n{node.public.export()}\n"
    assert parse_public(text, ROLE_NODE) == node.public
    with pytest.raises(OfflineCryptoError, match="не ключ центра"):
        parse_public(text, ROLE_CENTER)
    with pytest.raises(OfflineCryptoError):
        parse_public("ssh-ed25519 AAAA…", ROLE_NODE)
    broken = node.public.export()[:-6] + "AAAA=="
    with pytest.raises(OfflineCryptoError):
        parse_public(broken, ROLE_NODE)


def test_private_keys_roundtrip(node):
    again = KeyPair.from_json(json.loads(json.dumps(node.to_json())))
    assert again.public == node.public


def _job(center, node, body=None):
    return of.build(of.FORMAT_JOB, {"job_id": "j1", "run_id": 7},
                    body or {"job": {"targets": ["10.0.0.5"], "secret": "p@ss"}},
                    signer=center, recipient=node.public)


def test_roundtrip_and_body_is_encrypted(center, node):
    data = _job(center, node)
    assert b"p@ss" not in data and b"10.0.0.5" not in data
    env = of.parse(data, of.FORMAT_JOB)
    assert env.header["job_id"] == "j1"
    assert env.header["signer"] == center.public.fingerprint
    assert env.header["recipient"] == node.public.fingerprint
    env.verify(center.public)
    assert env.open(node)["job"]["secret"] == "p@ss"


def test_tampered_header_is_rejected(center, node):
    doc = json.loads(_job(center, node))
    doc["header"]["run_id"] = 8
    env = of.parse(json.dumps(doc).encode(), of.FORMAT_JOB)
    with pytest.raises(of.OfflineFileError, match="подпись"):
        env.verify(center.public)


def test_tampered_ciphertext_is_rejected(center, node):
    doc = json.loads(_job(center, node))
    ct = doc["box"]["ct"]
    doc["box"]["ct"] = ("B" if ct[0] != "B" else "C") + ct[1:]
    env = of.parse(json.dumps(doc).encode(), of.FORMAT_JOB)
    with pytest.raises(of.OfflineFileError):
        env.verify(center.public)


def test_resigned_by_other_key_is_rejected(center, node):
    """Злоумышленник с носителем переподписывает задание своим ключом."""
    evil = KeyPair.generate(ROLE_CENTER)
    data = of.build(of.FORMAT_JOB, {"job_id": "j1"}, {"job": {}}, signer=evil,
                    recipient=node.public)
    env = of.parse(data, of.FORMAT_JOB)
    with pytest.raises(of.OfflineFileError, match="другим ключом"):
        env.verify(center.public)


def test_header_swap_breaks_decryption(center, node):
    """Даже при корректной подписи (свой центр) тело привязано к заголовку."""
    a = json.loads(_job(center, node))
    b = json.loads(of.build(of.FORMAT_JOB, {"job_id": "j2"}, {"job": {}},
                            signer=center, recipient=node.public))
    a["box"] = b["box"]
    a.pop("sig")
    from scanner.nodes.offline_crypto import b64e, canonical
    a["sig"] = b64e(center.sign(canonical(a)))
    env = of.parse(json.dumps(a).encode(), of.FORMAT_JOB)
    env.verify(center.public)
    with pytest.raises(of.OfflineFileError, match="расшифровать"):
        env.open(node)


def test_other_recipient_cannot_open(center, node):
    other = KeyPair.generate(ROLE_NODE)
    env = of.parse(_job(center, node), of.FORMAT_JOB)
    with pytest.raises(of.OfflineFileError, match="другого получателя"):
        env.open(other)


def test_wrong_format_and_garbage(center, node):
    data = _job(center, node)
    with pytest.raises(of.OfflineFileError, match="ожидается файл результата"):
        of.parse(data, of.FORMAT_RESULT)
    with pytest.raises(of.OfflineFileError, match="не JSON"):
        of.parse(b"\x00\x01garbage", of.FORMAT_JOB)
    doc = json.loads(data)
    doc["version"] = 99
    with pytest.raises(of.OfflineFileError, match="версия"):
        of.parse(json.dumps(doc).encode(), of.FORMAT_JOB)


def test_gzip_bomb_is_limited(center, node, monkeypatch):
    monkeypatch.setattr(of, "MAX_BODY_BYTES", 1024)
    data = of.build(of.FORMAT_JOB, {"job_id": "j"}, {"pad": "x" * 100_000},
                    signer=center, recipient=node.public)
    assert len(data) < 10_000            # сжалось
    env = of.parse(data, of.FORMAT_JOB)
    env.verify(center.public)
    with pytest.raises(of.OfflineFileError, match="слишком большое"):
        env.open(node)


def test_body_is_gzip_json(center, node):
    env = of.parse(_job(center, node), of.FORMAT_JOB)
    from scanner.nodes.offline_crypto import b64d, unseal
    raw = unseal(env.doc["box"], node, of._aad(of.FORMAT_JOB, env.header))
    assert json.loads(zlib.decompress(raw, 31))["job"]["targets"] == ["10.0.0.5"]
    assert b64d(env.doc["sig"])
