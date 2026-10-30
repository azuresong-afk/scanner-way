"""Учётные записи активов: шифрование, ключи SSH, область действия, хранение в БД."""
from __future__ import annotations

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from sqlalchemy import select

from scanner.core import repository as repo
from scanner.core.credentials import (
    CredentialError,
    CredentialVault,
    HostCredential,
    VaultUnavailable,
    credentials_for_host,
    key_fingerprint,
    load_vault,
)
from scanner.core.db import HostCredentialRow, session_scope

PASSWORD = "S3cret-p@ss-for-host"


def make_key(passphrase: bytes | None = None) -> str:
    key = ed25519.Ed25519PrivateKey.generate()
    enc = (serialization.BestAvailableEncryption(passphrase) if passphrase
           else serialization.NoEncryption())
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.OpenSSH,
                             enc).decode()


@pytest.fixture
def vault():
    return CredentialVault("k" * 32)


# ---------- шифрование ----------
def test_vault_round_trip_and_wrong_key(vault):
    token = vault.encrypt({"password": PASSWORD, "passphrase": None})
    assert PASSWORD not in token
    assert vault.decrypt(token) == {"password": PASSWORD}
    with pytest.raises(VaultUnavailable):
        CredentialVault("z" * 32).decrypt(token)


def test_vault_requires_long_key(monkeypatch):
    with pytest.raises(VaultUnavailable):
        CredentialVault("short")
    monkeypatch.setenv("SCANNER_CREDENTIALS_KEY", "")
    monkeypatch.setenv("SCANNER_API_SECRET", "")
    assert load_vault() is None
    monkeypatch.setenv("SCANNER_API_SECRET", "a" * 40)
    assert load_vault() is not None


# ---------- ключи ----------
def test_key_fingerprint_and_passphrase():
    plain = make_key()
    fp = key_fingerprint(plain)
    assert fp.startswith("SHA256:") and fp == key_fingerprint(plain)
    locked = make_key(b"phrase-123")
    with pytest.raises(CredentialError, match="парольную фразу"):
        key_fingerprint(locked)
    assert key_fingerprint(locked, "phrase-123").startswith("SHA256:")
    with pytest.raises(CredentialError):
        key_fingerprint("-----BEGIN OPENSSH PRIVATE KEY-----\nmusor\n")


# ---------- область действия ----------
def test_credentials_for_host_prefers_narrow_scope():
    wide = HostCredential(1, "все", "password", "a", password="x")
    net = HostCredential(2, "подсеть", "password", "b", targets=("10.0.0.0/24",),
                         password="x")
    one = HostCredential(3, "хост", "password", "c", targets=("10.0.0.5/32",),
                         password="x")
    other = HostCredential(4, "чужая", "password", "d", targets=("10.9.0.0/16",),
                           password="x")
    creds = [wide, net, one, other]
    assert [c.id for c in credentials_for_host("10.0.0.5", creds)] == [3, 2, 1]
    assert [c.id for c in credentials_for_host("10.0.0.6", creds)] == [2, 1]
    assert [c.id for c in credentials_for_host("10.9.1.1", creds, limit=1)] == [4]
    assert "x" not in repr(one) and "password='x'" not in repr(one)


# ---------- хранение ----------
def _engagement(s, *cidrs):
    eid = repo.create_engagement(s, name="Д-1")
    for c in cidrs:
        repo.add_allowlist_entry(s, engagement_id=eid, cidr=c)
    return eid


def test_store_encrypts_and_loads(sqlite_factory, vault):
    key = make_key()
    with session_scope(sqlite_factory) as s:
        eid = _engagement(s, "10.0.0.0/24")
        pid = repo.create_host_credential(s, vault, engagement_id=eid, name="пароль",
                                          auth="password", username="audit",
                                          password=PASSWORD, targets=["10.0.0.7"])
        kid = repo.create_host_credential(s, vault, engagement_id=eid, name="ключ",
                                          auth="key", username="root", port=2222,
                                          private_key=key, become="none")
    with session_scope(sqlite_factory) as s:
        rows = list(s.scalars(select(HostCredentialRow).order_by(HostCredentialRow.id)))
        assert [r.targets for r in rows] == [["10.0.0.7/32"], []]
        assert all(PASSWORD not in r.secret_enc and "PRIVATE KEY" not in r.secret_enc
                   for r in rows)
        assert rows[0].key_fingerprint is None and rows[1].key_fingerprint.startswith("SHA256:")
        got = repo.load_host_credentials(s, vault, eid, [kid, pid, 999])
    assert [c.id for c in got] == [kid, pid]
    assert got[0].private_key.strip() == key.strip() and got[0].port == 2222
    assert got[1].password == PASSWORD and got[1].private_key is None
    assert [c.become for c in got] == ["none", "sudo"]           # по умолчанию sudo
    assert PASSWORD not in repr(got) and got[1].describe()["become"] == "sudo"
    assert "password" not in got[1].describe()


def test_store_rejects_scope_outside_allowlist_and_bad_input(sqlite_factory, vault):
    with session_scope(sqlite_factory) as s:
        eid = _engagement(s, "10.0.0.0/24")
        with pytest.raises(CredentialError, match="allowlist"):
            repo.create_host_credential(s, vault, engagement_id=eid, name="x",
                                        auth="password", username="a", password="p",
                                        targets=["10.0.1.0/24"])
        with pytest.raises(CredentialError, match="логин"):
            repo.create_host_credential(s, vault, engagement_id=eid, name="x",
                                        auth="password", username="a b; rm", password="p")
        with pytest.raises(CredentialError, match="пароль"):
            repo.create_host_credential(s, vault, engagement_id=eid, name="x",
                                        auth="password", username="a")
        with pytest.raises(CredentialError, match="ключ"):
            repo.create_host_credential(s, vault, engagement_id=eid, name="x",
                                        auth="key", username="a", private_key="nope")
        with pytest.raises(CredentialError, match="повышение прав"):
            repo.create_host_credential(s, vault, engagement_id=eid, name="x",
                                        auth="password", username="a", password="p",
                                        become="su")


def test_other_engagement_credentials_are_not_loaded(sqlite_factory, vault):
    with session_scope(sqlite_factory) as s:
        e1, e2 = _engagement(s, "10.0.0.0/24"), _engagement(s, "10.1.0.0/24")
        cid = repo.create_host_credential(s, vault, engagement_id=e1, name="x",
                                          auth="password", username="a", password="p")
        assert repo.load_host_credentials(s, vault, e2, [cid]) == []
