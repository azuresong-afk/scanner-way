"""Тесты контролируемого аудита учётных данных.

Фокус — защитные ограничения, а не «взлом»: соблюдение жёстких лимитов попыток,
остановка при блокировке (lockout) и при серии ошибок, отсутствие встроенных
словарей/бэкенда, неразглашение паролей в аудите и находках. Реальная сеть не
используется — аутентификатор подменяется фейком.
"""
from __future__ import annotations

import pytest

from scanner.core.models import FindingType, ServiceInfo, Severity
from scanner.core.ratelimit import RateProfile, get_profile
from scanner.modules.base import ScanContext
from scanner.modules.cred_audit import (
    AuthOutcome,
    AuthResult,
    Credential,
    CredentialAuditModule,
    CredentialAuditOptions,
    Probe,
    _Backoff,
    probes_from_services,
    validate_targets,
)


class ListAudit:
    def __init__(self):
        self.records = []

    def record(self, **kw):
        self.records.append(kw)


def _ctx(targets, services=None, rate=None):
    return ScanContext(engagement_id=1, scan_run_id=1, targets=targets,
                       rate=rate or get_profile("gentle"), audit=ListAudit(),
                       services=services)


class ScriptedAuth:
    """Фейковый бэкенд: отдаёт заранее заданные исходы по порядку вызовов.

    `by_cred` — словарь (user, secret) -> исход для точечных сценариев;
    `default` — для всего остального. Фиксирует все вызовы (без пароля? нет —
    фейк видит пароль, но в аудит его кладёт модуль, не фейк)."""

    def __init__(self, default=AuthOutcome.FAILURE, by_cred=None, sequence=None):
        self.default = default
        self.by_cred = by_cred or {}
        self.sequence = list(sequence or [])
        self.calls = []

    def authenticate(self, host, port, service, credential, timeout):
        self.calls.append((host, port, service, credential.username, credential.secret))
        if self.sequence:
            return AuthResult(self.sequence.pop(0))
        outcome = self.by_cred.get((credential.username, credential.secret), self.default)
        return AuthResult(outcome)


def _creds(*pairs):
    return [Credential(u, s) for u, s in pairs]


# --- allowlist / отбор целей ------------------------------------------------------

def test_non_ip_targets_rejected_without_attempts():
    auth = ScriptedAuth()
    mod = CredentialAuditModule(
        CredentialAuditOptions(credentials=_creds(("admin", "admin")),
                               probes=[Probe("web01.local", 22, "ssh")]),
        authenticator=auth, sleep=lambda s: None)
    ctx = _ctx(["web01.local", "10.0.0.0/24"])
    findings = mod.run(ctx)
    assert findings == []
    assert auth.calls == []  # ни одной попытки
    denied = {(r["target"], r["result"]) for r in ctx.audit.records
              if r["action"] == "cred_audit_deny"}
    # имя и подсеть отклонены как не-IP; проба по имени вне allowlist — тоже отказ
    assert ("web01.local", "not_an_ip_literal") in denied
    assert ("10.0.0.0/24", "not_an_ip_literal") in denied


def test_probe_outside_allowlist_is_denied():
    auth = ScriptedAuth(default=AuthOutcome.FAILURE)
    opts = CredentialAuditOptions(credentials=_creds(("admin", "x")),
                                  probes=[Probe("10.0.0.5", 22, "ssh"),
                                          Probe("10.0.0.9", 22, "ssh")])
    ctx = _ctx(["10.0.0.5"])  # .9 не в allowlist
    CredentialAuditModule(opts, authenticator=auth, sleep=lambda s: None).run(ctx)
    assert {c[0] for c in auth.calls} == {"10.0.0.5"}
    assert any(r["action"] == "cred_audit_deny" and r["target"] == "10.0.0.9"
               and r["result"] == "target_not_in_allowlist" for r in ctx.audit.records)


def test_validate_targets_splits_ip_and_rest():
    ok, rejected = validate_targets(["10.0.0.1", " 10.0.0.2 ", "host", "10.0.0.0/24"])
    assert ok == {"10.0.0.1", "10.0.0.2"}
    assert rejected == ["host", "10.0.0.0/24"]


def test_probes_from_services_filters_allowlist_and_supported():
    services = [
        ServiceInfo("10.0.0.5", 22, "tcp", service="ssh"),
        ServiceInfo("10.0.0.5", 80, "tcp", service="http"),      # не auth-сервис
        ServiceInfo("10.0.0.9", 22, "tcp", service="ssh"),       # не в allowlist
        ServiceInfo("10.0.0.5", 22, "tcp", service="ssh"),       # дубль (host,port)
        ServiceInfo("10.0.0.5", 3389, "tcp", service="ms-wbt-server"),
    ]
    probes = probes_from_services(services, {"10.0.0.5"},
                                  CredentialAuditOptions().services)
    assert probes == [Probe("10.0.0.5", 22, "ssh"),
                      Probe("10.0.0.5", 3389, "ms-wbt-server")]


# --- инертность по умолчанию ------------------------------------------------------

def test_no_credentials_means_no_attempts():
    auth = ScriptedAuth()
    mod = CredentialAuditModule(
        CredentialAuditOptions(probes=[Probe("10.0.0.5", 22, "ssh")]),
        authenticator=auth, sleep=lambda s: None)
    ctx = _ctx(["10.0.0.5"])
    assert mod.run(ctx) == []
    assert auth.calls == []
    assert any(r["action"] == "cred_audit_skip" and r["result"] == "no_credentials"
               for r in ctx.audit.records)


def test_no_authenticator_means_no_attempts():
    opts = CredentialAuditOptions(credentials=_creds(("admin", "admin")),
                                  probes=[Probe("10.0.0.5", 22, "ssh")])
    mod = CredentialAuditModule(opts, authenticator=None, sleep=lambda s: None)
    ctx = _ctx(["10.0.0.5"])
    assert mod.run(ctx) == []
    assert any(r["action"] == "cred_audit_skip" and r["result"] == "no_authenticator"
               for r in ctx.audit.records)


def test_no_embedded_dictionaries_in_source():
    """Модуль не должен содержать встроенных списков учёток/паролей."""
    import inspect

    from scanner.modules import cred_audit
    src = inspect.getsource(cred_audit).lower()
    for banned in ("admin/admin", "root:toor", "password123", "123456",
                   "default_passwords", "wordlist"):
        assert banned not in src


# --- успешная находка слабой учётки ----------------------------------------------

def test_weak_credential_becomes_finding_without_leaking_secret():
    auth = ScriptedAuth(by_cred={("admin", "admin"): AuthOutcome.SUCCESS})
    opts = CredentialAuditOptions(credentials=_creds(("admin", "admin")),
                                  probes=[Probe("10.0.0.5", 22, "ssh")])
    ctx = _ctx(["10.0.0.5"])
    findings = CredentialAuditModule(opts, authenticator=auth,
                                     sleep=lambda s: None).run(ctx)
    cred = [f for f in findings if f.finding_type is FindingType.CRED]
    assert len(cred) == 1
    f = cred[0]
    assert f.module == "cred_audit" and f.host == "10.0.0.5" and f.port == 22
    assert f.vuln_id == "CRED:ssh/admin"
    assert f.severity is Severity.CRITICAL  # административная учётка
    # пароль не утёк ни в находку, ни в аудит
    assert "admin" in f.title
    dump = repr(findings) + repr(ctx.audit.records)
    assert "secret=***" not in dump or "admin" in dump  # репр маскирует секрет
    # сам секрет как значение details не присутствует
    attempt = next(r for r in ctx.audit.records if r["action"] == "cred_audit_attempt")
    assert attempt["details"]["user"] == "admin"
    assert "secret" not in str(attempt["details"]).replace("secret_id", "")


def test_dedup_key_stable_across_runs():
    def run_once():
        auth = ScriptedAuth(by_cred={("u", "p"): AuthOutcome.SUCCESS})
        opts = CredentialAuditOptions(credentials=_creds(("u", "p")),
                                      probes=[Probe("10.0.0.5", 22, "ssh")])
        return CredentialAuditModule(opts, authenticator=auth,
                                     sleep=lambda s: None).run(_ctx(["10.0.0.5"]))
    a, b = run_once(), run_once()
    assert [f.dedup_key() for f in a] == [f.dedup_key() for f in b]


def test_blank_and_admin_passwords_are_critical():
    auth = ScriptedAuth(default=AuthOutcome.SUCCESS)
    opts = CredentialAuditOptions(
        credentials=[Credential("alice", "")],   # пустой пароль
        service_credentials={"ssh": [Credential("bob", "s3cret")]},  # обычный
        probes=[Probe("10.0.0.5", 22, "ssh")],
        max_attempts_per_account=1)
    findings = CredentialAuditModule(opts, authenticator=auth,
                                     sleep=lambda s: None).run(_ctx(["10.0.0.5"]))
    sev = {f.vuln_id: f.severity for f in findings if f.finding_type is FindingType.CRED}
    assert sev["CRED:ssh/alice"] is Severity.CRITICAL   # пустой пароль
    assert sev["CRED:ssh/bob"] is Severity.HIGH          # обычная учётка


# --- жёсткие лимиты попыток -------------------------------------------------------

def test_per_target_cap_enforced():
    # cap=3 (профиль gentle); даём 10 учёток — должно быть ровно 3 попытки
    auth = ScriptedAuth(default=AuthOutcome.FAILURE)
    creds = _creds(*[(f"user{i}", f"pw{i}") for i in range(10)])
    opts = CredentialAuditOptions(credentials=creds,
                                  probes=[Probe("10.0.0.5", 22, "ssh")],
                                  max_attempts_per_account=99)
    ctx = _ctx(["10.0.0.5"], rate=get_profile("gentle"))  # max_auth_attempts=3
    CredentialAuditModule(opts, authenticator=auth, sleep=lambda s: None).run(ctx)
    assert len(auth.calls) == 3
    limit = [r for r in ctx.audit.records if r["action"] == "cred_audit_limit"]
    assert limit and limit[0]["details"] == {"attempts": 3, "cap": 3}


def test_per_account_cap_prevents_lockout():
    # Много паролей для ОДНОЙ учётки; на аккаунт не больше 2 попыток.
    auth = ScriptedAuth(default=AuthOutcome.FAILURE)
    creds = _creds(("root", "a"), ("root", "b"), ("root", "c"), ("root", "d"))
    rate = RateProfile("t", 100, 8, 0.0, 50, 2.0)  # большой общий потолок
    opts = CredentialAuditOptions(credentials=creds,
                                  probes=[Probe("10.0.0.5", 22, "ssh")],
                                  max_attempts_per_account=2)
    ctx = _ctx(["10.0.0.5"], rate=rate)
    CredentialAuditModule(opts, authenticator=auth, sleep=lambda s: None).run(ctx)
    assert len(auth.calls) == 2  # остальные две — пропущены
    skips = [r for r in ctx.audit.records
             if r["action"] == "cred_audit_skip" and r["result"] == "account_limit_reached"]
    assert len(skips) == 2


# --- остановка при блокировке / ошибках ------------------------------------------

def test_lockout_stops_host_immediately_but_not_other_hosts():
    # Первый хост: вторая попытка -> lockout (стоп по хосту). Второй хост работает.
    auth = ScriptedAuth(default=AuthOutcome.FAILURE,
                        sequence=[AuthOutcome.FAILURE, AuthOutcome.LOCKOUT,
                                  AuthOutcome.FAILURE])
    creds = _creds(("u1", "p1"), ("u2", "p2"), ("u3", "p3"))
    rate = RateProfile("t", 100, 8, 0.0, 50, 2.0)
    opts = CredentialAuditOptions(credentials=creds, max_attempts_per_account=9,
                                  probes=[Probe("10.0.0.5", 22, "ssh"),
                                          Probe("10.0.0.6", 22, "ssh")])
    ctx = _ctx(["10.0.0.5", "10.0.0.6"], rate=rate)
    findings = CredentialAuditModule(opts, authenticator=auth,
                                     sleep=lambda s: None).run(ctx)
    # на первом хосте не более 2 попыток (стоп на lockout), второй хост опрошен
    host5 = [c for c in auth.calls if c[0] == "10.0.0.5"]
    host6 = [c for c in auth.calls if c[0] == "10.0.0.6"]
    assert len(host5) == 2 and len(host6) >= 1
    assert any(r["action"] == "cred_audit_lockout" and r["target"] == "10.0.0.5"
               for r in ctx.audit.records)
    assert any(f.vuln_id == "INFO:cred-audit-lockout" for f in findings)


def test_consecutive_errors_stop_host():
    auth = ScriptedAuth(default=AuthOutcome.ERROR)
    creds = _creds(*[(f"u{i}", "p") for i in range(10)])
    rate = RateProfile("t", 100, 8, 0.0, 50, 2.0)
    opts = CredentialAuditOptions(credentials=creds, max_attempts_per_account=9,
                                  max_consecutive_errors=3,
                                  probes=[Probe("10.0.0.5", 22, "ssh")])
    ctx = _ctx(["10.0.0.5"], rate=rate)
    findings = CredentialAuditModule(opts, authenticator=auth,
                                     sleep=lambda s: None).run(ctx)
    assert len(auth.calls) == 3  # стоп после 3 ошибок подряд
    assert any(r["action"] == "cred_audit_stop" and r["result"] == "too_many_errors"
               for r in ctx.audit.records)
    assert any(f.vuln_id == "INFO:cred-audit-errors" for f in findings)


def test_backend_exception_counts_as_error_not_crash():
    class Boom:
        def authenticate(self, *a, **k):
            raise RuntimeError("socket exploded")
    opts = CredentialAuditOptions(credentials=_creds(("u", "p")),
                                  probes=[Probe("10.0.0.5", 22, "ssh")])
    ctx = _ctx(["10.0.0.5"])
    findings = CredentialAuditModule(opts, authenticator=Boom(),
                                     sleep=lambda s: None).run(ctx)
    assert findings == []  # ошибка не роняет прогон
    attempt = next(r for r in ctx.audit.records if r["action"] == "cred_audit_attempt")
    assert attempt["result"] == "error"


# --- backoff ---------------------------------------------------------------------

def test_backoff_escalates_between_attempts():
    slept = []
    b = _Backoff(base=1.0, factor=2.0, max_sec=100.0, sleep=slept.append)
    for _ in range(4):
        b.wait()
    assert slept == [1.0, 2.0, 4.0]  # перед 1-й попыткой паузы нет


def test_backoff_capped_at_max():
    slept = []
    b = _Backoff(base=10.0, factor=10.0, max_sec=15.0, sleep=slept.append)
    for _ in range(3):
        b.wait()
    assert slept == [10.0, 15.0]  # вторая пауза упёрлась в потолок


def test_module_waits_between_attempts_within_host():
    slept = []
    auth = ScriptedAuth(default=AuthOutcome.FAILURE)
    creds = _creds(("a", "1"), ("b", "2"), ("c", "3"))
    # поля RateProfile: name, rps, concurrency, delay_between_attempts_sec,
    # max_auth_attempts_per_target, backoff_factor
    rate = RateProfile("t", 100, 8, 0.5, 50, 2.0)
    opts = CredentialAuditOptions(credentials=creds, max_attempts_per_account=9,
                                  probes=[Probe("10.0.0.5", 22, "ssh")])
    CredentialAuditModule(opts, authenticator=auth,
                          sleep=slept.append).run(_ctx(["10.0.0.5"], rate=rate))
    assert slept == [0.5, 1.0]  # 3 попытки -> 2 паузы, экспоненциальные


# --- неразглашение секретов -------------------------------------------------------

def test_secret_never_appears_in_audit_or_repr():
    auth = ScriptedAuth(by_cred={("admin", "SuperSecret123"): AuthOutcome.SUCCESS})
    opts = CredentialAuditOptions(credentials=_creds(("admin", "SuperSecret123")),
                                  probes=[Probe("10.0.0.5", 22, "ssh")])
    ctx = _ctx(["10.0.0.5"])
    findings = CredentialAuditModule(opts, authenticator=auth,
                                     sleep=lambda s: None).run(ctx)
    blob = repr(ctx.audit.records) + repr(findings) + repr(opts.credentials)
    assert "SuperSecret123" not in blob
    c = Credential("admin", "SuperSecret123")
    assert "SuperSecret123" not in repr(c)
    assert c.masked() == f"admin:#{c.secret_id}"
    assert Credential("x", "").masked() == "x:<пустой>"


def test_credential_validation():
    with pytest.raises(ValueError):
        Credential("", "p")
    with pytest.raises(ValueError):
        Credential("user\n", "p")
    with pytest.raises(ValueError):
        Credential("user", "pass\x00word")
    Credential("user", "")  # пустой пароль допустим


def test_unsupported_service_skips_to_next_probe():
    auth = ScriptedAuth(sequence=[AuthOutcome.UNSUPPORTED, AuthOutcome.SUCCESS])
    creds = _creds(("u", "p"), ("u2", "p2"))
    rate = RateProfile("t", 100, 8, 0.0, 50, 2.0)
    opts = CredentialAuditOptions(credentials=creds, max_attempts_per_account=9,
                                  probes=[Probe("10.0.0.5", 22, "ssh"),
                                          Probe("10.0.0.5", 3389, "ms-wbt-server")])
    ctx = _ctx(["10.0.0.5"], rate=rate)
    findings = CredentialAuditModule(opts, authenticator=auth,
                                     sleep=lambda s: None).run(ctx)
    # первый сервис вернул unsupported на первой учётке -> переход к след. пробе
    assert auth.calls[0][1] == 22 and auth.calls[1][1] == 3389
    assert any(f.finding_type is FindingType.CRED for f in findings)
