"""Проверка парольной политики: только из фикстуры конфигурации, без сети."""
from __future__ import annotations

from scanner.core.models import FindingType, Severity
from scanner.core.ratelimit import get_profile
from scanner.modules.base import ScanContext
from scanner.modules.password_policy import (
    FAILLOCK,
    LOGIN_DEFS,
    PAM_PASSWORD,
    PWQUALITY,
    PasswordPolicyModule,
    analyze_policy,
)


class ListAudit:
    def __init__(self):
        self.records = []

    def record(self, **kw):
        self.records.append(kw)


def _ctx(configs):
    return ScanContext(engagement_id=1, scan_run_id=1, targets=["10.0.0.5"],
                       rate=get_profile("gentle"), audit=ListAudit(),
                       host_policy_configs=configs)


WEAK = {
    LOGIN_DEFS: "PASS_MAX_DAYS\t400\nPASS_MIN_LEN 6\n",
    PWQUALITY: "# пусто\n",
}

STRONG = {
    FAILLOCK: "deny = 5\nunlock_time = 900\n",
    PWQUALITY: "minlen = 14\nminclass = 3\n",
    LOGIN_DEFS: "PASS_MAX_DAYS 90\n",
}


def _keys(findings):
    return {f.vuln_id for f in findings}


def test_weak_policy_reports_all_issues():
    findings = analyze_policy("10.0.0.5", WEAK)
    keys = _keys(findings)
    assert keys == {"POLICY:password-lockout", "POLICY:password-min-length",
                    "POLICY:password-complexity", "POLICY:password-max-age"}
    assert all(f.finding_type is FindingType.CONFIG for f in findings)
    assert all(f.host == "10.0.0.5" and f.port is None for f in findings)
    # документ контроля указан в evidence
    assert all("http" in (f.evidence or "") for f in findings)


def test_strong_policy_has_no_findings():
    assert analyze_policy("10.0.0.5", STRONG) == []


def test_lockout_via_pam_faillock_counts():
    configs = {PAM_PASSWORD: "auth required pam_faillock.so preauth deny=3 unlock_time=600",
               PWQUALITY: "minlen=12\nminclass=2\n"}
    assert "POLICY:password-lockout" not in _keys(analyze_policy("h", configs))


def test_min_length_from_login_defs_when_pwquality_absent():
    configs = {LOGIN_DEFS: "PASS_MIN_LEN 12\n", FAILLOCK: "deny=3\n",
               PWQUALITY: "minclass=2\n"}
    keys = _keys(analyze_policy("h", configs))
    assert "POLICY:password-min-length" not in keys


def test_complexity_via_credits():
    configs = {FAILLOCK: "deny=3\n", PWQUALITY: "minlen=12\ndcredit=-1\nucredit=-1\n"}
    assert "POLICY:password-complexity" not in _keys(analyze_policy("h", configs))


def test_severity_levels():
    sev = {f.vuln_id: f.severity for f in analyze_policy("h", WEAK)}
    assert sev["POLICY:password-lockout"] is Severity.MEDIUM
    assert sev["POLICY:password-min-length"] is Severity.MEDIUM
    assert sev["POLICY:password-complexity"] is Severity.LOW
    assert sev["POLICY:password-max-age"] is Severity.LOW


def test_module_inert_without_data():
    ctx = _ctx({})
    assert PasswordPolicyModule().run(ctx) == []
    assert any(r["action"] == "password_policy_skip" and r["result"] == "no_policy_data"
               for r in ctx.audit.records)


def test_module_evaluates_per_host_from_fixture():
    ctx = _ctx({"10.0.0.5": WEAK, "10.0.0.6": STRONG})
    findings = PasswordPolicyModule().run(ctx)
    hosts = {f.host for f in findings}
    assert hosts == {"10.0.0.5"}  # у 10.0.0.6 политика в порядке
    assert any(r["action"] == "password_policy_eval" and r["target"] == "10.0.0.5"
               for r in ctx.audit.records)
    # dedup-ключи стабильны между прогонами
    again = PasswordPolicyModule().run(_ctx({"10.0.0.5": WEAK}))
    assert ([f.dedup_key() for f in PasswordPolicyModule().run(_ctx({"10.0.0.5": WEAK}))]
            == [f.dedup_key() for f in again])


def test_shadow_hashes_are_never_requested():
    """Модуль анализирует только файлы политики; /etc/shadow среди них нет."""
    from scanner.modules import password_policy as pp
    analyzed = {v for v in vars(pp).values()
                if isinstance(v, str) and v.startswith("/etc")}
    assert analyzed and not any("shadow" in f for f in analyzed)
