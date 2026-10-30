"""Наборы проверки учёток (аудит паролей): кандидаты из контекста, бэкенды,
хранение и сквозной прогон. Секреты не должны утечь в аудит/находки/БД.
"""
from __future__ import annotations

import sys
import types

import pytest

from scanner.core import repository as repo
from scanner.core.audit import DbAuditSink
from scanner.core.credentials import (
    CredentialError,
    CredentialVault,
    mask_username,
    validate_cred_set_entries,
)
from scanner.core.db import session_scope
from scanner.core.models import FindingType, Severity
from scanner.core.orchestrator import (
    RunService,
    default_module_registry,
    inline_executor,
)
from scanner.core.ratelimit import get_profile
from scanner.modules.authenticators import (
    CompositeAuthenticator,
    build_default_authenticator,
)
from scanner.modules.authenticators.ssh import SshPasswordAuthenticator
from scanner.modules.base import ScanContext
from scanner.modules.cred_audit import (
    AuthOutcome,
    AuthResult,
    Credential,
    CredentialAuditModule,
    CredentialAuditOptions,
    Probe,
)

SECRET = "LeakMe-NOT-9000"


class ListAudit:
    def __init__(self):
        self.records = []

    def record(self, **kw):
        self.records.append(kw)


def _ctx(targets, candidates=None, rate=None):
    return ScanContext(engagement_id=1, scan_run_id=1, targets=targets,
                       rate=rate or get_profile("gentle"), audit=ListAudit(),
                       cred_candidates=list(candidates or []))


class ScriptedAuth:
    def __init__(self, by_cred=None, default=AuthOutcome.FAILURE):
        self.by_cred = by_cred or {}
        self.default = default
        self.calls = []

    def authenticate(self, host, port, service, credential, timeout):
        self.calls.append((host, port, service, credential.username, credential.secret))
        return AuthResult(self.by_cred.get((credential.username, credential.secret),
                                           self.default))


# --- кандидаты из ctx.cred_candidates ------------------------------------------

def test_candidates_from_context_used_when_no_operator_options():
    auth = ScriptedAuth(by_cred={("admin", SECRET): AuthOutcome.SUCCESS})
    mod = CredentialAuditModule(
        CredentialAuditOptions(probes=[Probe("10.0.0.5", 22, "ssh")]),
        authenticator=auth, sleep=lambda s: None)
    ctx = _ctx(["10.0.0.5"], candidates=[("admin", SECRET)])
    findings = mod.run(ctx)
    cred = [f for f in findings if f.finding_type is FindingType.CRED]
    assert len(cred) == 1 and cred[0].vuln_id == "CRED:ssh/admin"
    assert auth.calls and auth.calls[0][0] == "10.0.0.5"
    # секрет не утёк ни в находку, ни в аудит
    blob = repr(findings) + repr(ctx.audit.records)
    assert SECRET not in blob


def test_no_candidates_and_no_options_is_inert():
    auth = ScriptedAuth()
    mod = CredentialAuditModule(
        CredentialAuditOptions(probes=[Probe("10.0.0.5", 22, "ssh")]),
        authenticator=auth, sleep=lambda s: None)
    ctx = _ctx(["10.0.0.5"], candidates=[])
    assert mod.run(ctx) == []
    assert auth.calls == []
    assert any(r["action"] == "cred_audit_skip" and r["result"] == "no_credentials"
               for r in ctx.audit.records)


def test_operator_options_take_precedence_over_candidates():
    auth = ScriptedAuth(default=AuthOutcome.FAILURE)
    mod = CredentialAuditModule(
        CredentialAuditOptions(credentials=[Credential("op", "x")],
                               probes=[Probe("10.0.0.5", 22, "ssh")]),
        authenticator=auth, sleep=lambda s: None)
    ctx = _ctx(["10.0.0.5"], candidates=[("ignored", "y")])
    mod.run(ctx)
    assert {c[3] for c in auth.calls} == {"op"}  # кандидаты не использованы


def test_invalid_candidate_skipped_without_crash():
    auth = ScriptedAuth()
    mod = CredentialAuditModule(
        CredentialAuditOptions(probes=[Probe("10.0.0.5", 22, "ssh")]),
        authenticator=auth, sleep=lambda s: None)
    ctx = _ctx(["10.0.0.5"], candidates=[("bad\nuser", "p")])
    assert mod.run(ctx) == []  # единственный кандидат невалиден -> нет попыток
    assert any(r["result"] == "invalid_candidate" for r in ctx.audit.records)


# --- бэкенды проверки ----------------------------------------------------------

def test_composite_dispatches_and_reports_unsupported():
    class SshFake:
        def authenticate(self, *a, **k):
            return AuthResult(AuthOutcome.SUCCESS)
    comp = CompositeAuthenticator({"ssh": SshFake()})
    cred = Credential("u", "p")
    assert comp.authenticate("10.0.0.5", 22, "ssh", cred, 1.0).outcome is AuthOutcome.SUCCESS
    # сервис без бэкенда -> UNSUPPORTED (модуль перейдёт к следующей пробе)
    assert comp.authenticate("10.0.0.5", 3389, "ms-wbt-server", cred,
                             1.0).outcome is AuthOutcome.UNSUPPORTED


def test_default_authenticator_has_ssh_backend():
    comp = build_default_authenticator()
    cred = Credential("u", "p")
    # для RDP бэкенда нет -> UNSUPPORTED
    assert comp.authenticate("10.0.0.5", 3389, "rdp", cred, 1.0).outcome \
        is AuthOutcome.UNSUPPORTED


def _fake_paramiko(behaviour):
    """Поддельный модуль paramiko: connect() выполняет behaviour(), close() — no-op."""
    mod = types.ModuleType("paramiko")

    class AuthenticationException(Exception):
        pass

    class SSHException(Exception):
        pass

    class AutoAddPolicy:
        pass

    class SSHClient:
        def set_missing_host_key_policy(self, policy):
            pass

        def connect(self, **kw):
            behaviour(kw)

        def close(self):
            pass

    mod.AuthenticationException = AuthenticationException
    mod.SSHException = SSHException
    mod.AutoAddPolicy = AutoAddPolicy
    mod.SSHClient = SSHClient
    return mod


@pytest.mark.parametrize("behaviour,expected", [
    (lambda kw: None, AuthOutcome.SUCCESS),
    (lambda kw: (_ for _ in ()).throw(sys.modules["paramiko"].AuthenticationException()),
     AuthOutcome.FAILURE),
])
def test_ssh_adapter_success_and_failure(monkeypatch, behaviour, expected):
    fake = _fake_paramiko(behaviour)
    monkeypatch.setitem(sys.modules, "paramiko", fake)
    res = SshPasswordAuthenticator().authenticate("10.0.0.5", 22, "ssh",
                                                  Credential("u", SECRET), 1.0)
    assert res.outcome is expected
    assert SECRET not in (res.detail or "")


def test_ssh_adapter_lockout_and_network(monkeypatch):
    fake = _fake_paramiko(lambda kw: None)
    monkeypatch.setitem(sys.modules, "paramiko", fake)

    def lockout(kw):
        raise fake.SSHException("Error reading SSH: Too many authentication failures")
    monkeypatch.setattr(fake.SSHClient, "connect", lambda self, **kw: lockout(kw))
    assert SshPasswordAuthenticator().authenticate(
        "10.0.0.5", 22, "ssh", Credential("u", SECRET), 1.0).outcome is AuthOutcome.LOCKOUT

    monkeypatch.setattr(fake.SSHClient, "connect",
                        lambda self, **kw: (_ for _ in ()).throw(OSError("refused")))
    assert SshPasswordAuthenticator().authenticate(
        "10.0.0.5", 22, "ssh", Credential("u", SECRET), 1.0).outcome is AuthOutcome.ERROR


# --- валидация и маскирование --------------------------------------------------

def test_validate_cred_set_entries_rules():
    assert validate_cred_set_entries([("root", ""), ("admin", "p")]) == \
        [("root", ""), ("admin", "p")]
    with pytest.raises(CredentialError):
        validate_cred_set_entries([])
    with pytest.raises(CredentialError):
        validate_cred_set_entries([("bad\nuser", "p")])
    with pytest.raises(CredentialError):
        validate_cred_set_entries([("u", "p\x00")])
    with pytest.raises(CredentialError):
        validate_cred_set_entries([(f"u{i}", "p") for i in range(201)])


def test_mask_username():
    assert mask_username("administrator") == "ad******"
    assert mask_username("a") == "a*"


def test_vault_entries_roundtrip_preserves_empty_secret():
    vault = CredentialVault("k" * 32)
    token = vault.encrypt_entries([("root", ""), ("admin", SECRET)])
    assert SECRET not in token  # зашифровано
    assert vault.decrypt_entries(token) == [("root", ""), ("admin", SECRET)]


# --- хранение набора и сквозной прогон -----------------------------------------

def test_repo_cred_set_crud_and_masking(sqlite_factory):
    vault = CredentialVault("k" * 32)
    with session_scope(sqlite_factory) as s:
        eid = repo.create_engagement(s, name="E")
        sid = repo.create_cred_audit_set(s, vault, engagement_id=eid, name="набор",
                                         entries=[("root", ""), ("admin", SECRET)],
                                         services=["ssh"])
    with session_scope(sqlite_factory) as s:
        rows = repo.list_cred_audit_sets(s, eid)
        assert len(rows) == 1 and rows[0].entry_count == 2
        assert list(rows[0].services) == ["ssh"]
        masked = repo.cred_set_masked_usernames(vault, rows[0])
        assert masked == ["ro**", "ad***"] and SECRET not in repr(masked)
        pairs = repo.load_cred_set_entries(s, vault, eid, [sid])
        assert ("admin", SECRET) in pairs and ("root", "") in pairs
        # неизвестный сервис отклоняется
        with pytest.raises(CredentialError):
            repo.create_cred_audit_set(s, vault, engagement_id=eid, name="x",
                                       entries=[("u", "p")], services=["carrier-pigeon"])


def test_runservice_passes_cred_set_to_module(sqlite_factory):
    """Сквозь RunService: набор расшифровывается и попадает в ctx.cred_candidates;
    модуль находит слабую учётку; секрет не оседает в аудите/находках/БД."""
    vault = CredentialVault("s" * 32)
    captured = {}

    class SpyAuth:
        def authenticate(self, host, port, service, credential, timeout):
            captured.setdefault("pairs", []).append((credential.username,
                                                      credential.secret))
            ok = (credential.username, credential.secret) == ("admin", SECRET)
            return AuthResult(AuthOutcome.SUCCESS if ok else AuthOutcome.FAILURE)

    class StubDiscovery:
        name = "discovery"

        def run(self, ctx):
            from scanner.core.models import ServiceInfo
            ctx.services = [ServiceInfo("10.0.0.5", 22, "tcp", "ssh")]
            return []

    registry = {
        "discovery": lambda: StubDiscovery(),
        "cred_audit": lambda: CredentialAuditModule(authenticator=SpyAuth(),
                                                    sleep=lambda s: None),
    }
    with session_scope(sqlite_factory) as s:
        eid = repo.create_engagement(s, name="E")
        repo.add_allowlist_entry(s, engagement_id=eid, cidr="10.0.0.0/24")
        sid = repo.create_cred_audit_set(s, vault, engagement_id=eid, name="набор",
                                         entries=[("admin", SECRET), ("x", "y")])
    svc = RunService(sqlite_factory, DbAuditSink(sqlite_factory), registry=registry,
                     executor=inline_executor(), vault=vault)
    run_id = svc.submit(engagement_id=eid, modules=["discovery", "cred_audit"],
                        rate_profile="gentle", requested_targets=["10.0.0.5"],
                        actor="tester", cred_set_ids=[sid])
    with session_scope(sqlite_factory) as s:
        run = repo.get_scan_run(s, run_id)
        assert run.status == "done" and run.cred_set_ids == [sid]
        findings = repo.get_findings(s, run_id)
    assert any(f.vuln_id == "CRED:ssh/admin" and f.severity is Severity.CRITICAL
               for f in findings)
    assert ("admin", SECRET) in captured["pairs"]
    # секрет не в аудите и не в находках
    with session_scope(sqlite_factory) as s:
        from sqlalchemy import select

        from scanner.core.db import AuditLogRow
        audit_blob = repr([tuple(r) for r in s.execute(
            select(AuditLogRow.action, AuditLogRow.result, AuditLogRow.details))])
    assert SECRET not in audit_blob
    assert SECRET not in repr(findings)


def test_default_registry_cred_audit_has_authenticator():
    mod = default_module_registry()["cred_audit"]()
    assert isinstance(mod, CredentialAuditModule)
    assert mod._auth is not None  # бэкенды подключены по умолчанию (SSH)
