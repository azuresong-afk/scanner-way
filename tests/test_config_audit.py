"""Тесты аудита конфигураций на эталонном выводе OpenSCAP/Lynis — без SSH.

Фикстуры сняты с реальных движков: oscap 1.3.9 + SSG Debian 12 (профиль
standard, урезано до 6 правил, результаты проставлены) и Lynis 3.0.9
(добавлены строки warning[] в формате report.dat).
"""
import gzip
import io
import tarfile
from pathlib import Path

import pytest

from scanner.core.models import FindingType, Severity
from scanner.core.ratelimit import RateProfile, get_profile
from scanner.modules.base import ScanContext
from scanner.modules.config_audit import (
    ConfigAuditError,
    ConfigAuditModule,
    ConfigAuditOptions,
    RunResult,
    SshCredentials,
    _Throttle,
    build_lynis_bundle,
    build_ssh_command,
    lynis_script,
    openscap_script,
    parse_lynis_report,
    parse_openscap_results,
    redact_command,
)
from scanner.reporting.remediation import RemediationResolver, RemediationSource

FIX = Path(__file__).parent / "fixtures"
OSCAP = (FIX / "oscap_results.xml").read_bytes()
LYNIS = (FIX / "lynis_report.dat").read_text()
RULE = "xccdf_org.ssgproject.content_rule_"
KEY = "/secrets/engagement-42/id_ed25519"


class ListAudit:
    def __init__(self):
        self.records = []

    def record(self, **kw):
        self.records.append(kw)


def _ctx(targets, rate=None):
    return ScanContext(engagement_id=1, scan_run_id=1, targets=targets,
                       rate=rate or get_profile("gentle"), audit=ListAudit())


def _creds(**kw):
    return SshCredentials(username="auditor", key_path=KEY, **kw)


@pytest.fixture
def scap_file(tmp_path):
    p = tmp_path / "ds.xml"
    p.write_bytes(b"<ds/>")
    return str(p)


# --- разбор OpenSCAP -----------------------------------------------------------

def test_openscap_only_failed_rules_become_findings():
    findings, rem = parse_openscap_results(OSCAP, "10.0.0.5")
    config = {f.vuln_id: f for f in findings if f.finding_type is FindingType.CONFIG}
    assert set(config) == {RULE + "sshd_disable_root_login", RULE + "package_telnetd_removed",
                           RULE + "accounts_password_minlen_login_defs"}
    root = config[RULE + "sshd_disable_root_login"]
    assert root.title == "[OpenSCAP] Disable SSH Root Login"
    assert root.severity is Severity.MEDIUM and root.host == "10.0.0.5"
    assert root.module == "config_audit" and root.port is None
    assert "content_profile_standard" in root.evidence
    assert "Debian 12" in root.evidence and "CIS Controls" in root.evidence
    assert config[RULE + "package_telnetd_removed"].severity is Severity.HIGH
    # рекомендация — из описания правила бенчмарка
    assert "PermitRootLogin no" in rem[RULE + "sshd_disable_root_login"]
    assert set(rem) == set(config)


def test_openscap_errors_summarised_as_info():
    findings, _ = parse_openscap_results(OSCAP, "10.0.0.5")
    info = [f for f in findings if f.finding_type is FindingType.INFO]
    assert len(info) == 1 and info[0].vuln_id == "INFO:openscap-check-error"
    assert "file_permissions_etc_shadow" in info[0].evidence


def test_openscap_dedup_key_stable_across_runs():
    a, _ = parse_openscap_results(OSCAP, "10.0.0.5")
    b, _ = parse_openscap_results(OSCAP, "10.0.0.5")
    assert [f.dedup_key() for f in a] == [f.dedup_key() for f in b]


def test_openscap_rejects_entities_and_garbage():
    bomb = b'<?xml version="1.0"?><!DOCTYPE x [<!ENTITY a "aaaa">]><x>&a;</x>'
    with pytest.raises(ConfigAuditError):
        parse_openscap_results(bomb, "10.0.0.5")
    with pytest.raises(ConfigAuditError):
        parse_openscap_results(b"<not-closed", "10.0.0.5")
    with pytest.raises(ConfigAuditError, match="TestResult"):
        parse_openscap_results(b"<Benchmark/>", "10.0.0.5")


# --- разбор Lynis ----------------------------------------------------------------

def test_lynis_warnings_and_suggestions():
    findings, rem = parse_lynis_report(LYNIS, "10.0.0.6")
    by_id = {f.vuln_id: f for f in findings}
    assert "LYNIS:LYNIS" not in by_id          # строка про версию самого Lynis
    assert by_id["LYNIS:FIRE-4512"].severity is Severity.MEDIUM
    assert by_id["LYNIS:DEB-0880"].severity is Severity.LOW
    assert all(f.finding_type is FindingType.CONFIG
               for k, f in by_id.items() if k.startswith("LYNIS:"))
    # SSH-7408: warning с деталями и решением; в той же выгрузке есть suggestion
    ssh = by_id["LYNIS:SSH-7408"]
    assert ssh.severity is Severity.MEDIUM
    assert "PermitRootLogin:yes" in ssh.evidence
    assert rem["LYNIS:SSH-7408"].startswith("Set PermitRootLogin to no")
    # без решения рекомендацией служит сам текст Lynis
    assert rem["LYNIS:DEB-0880"].startswith("Install fail2ban")


def test_lynis_same_test_id_merged_into_one_finding():
    findings, _ = parse_lynis_report(LYNIS, "10.0.0.6")
    f6310 = [f for f in findings if f.vuln_id == "LYNIS:FILE-6310"]
    assert len(f6310) == 1
    assert "/home" in f6310[0].evidence and "/var" in f6310[0].evidence
    assert "(и ещё 2)" in f6310[0].title
    assert len({f.vuln_id for f in findings}) == len(findings)


def test_lynis_hardening_index_info():
    findings, _ = parse_lynis_report(LYNIS, "10.0.0.6")
    hi = next(f for f in findings if f.vuln_id == "INFO:lynis-hardening-index")
    assert hi.title.endswith("57/100") and "Ubuntu 24.04" in hi.evidence


def test_remediations_feed_resolver_as_benchmark():
    findings, rem = parse_openscap_results(OSCAP, "10.0.0.5")
    resolver = RemediationResolver(benchmark=rem)
    f = next(f for f in findings if f.vuln_id == RULE + "sshd_disable_root_login")
    r = resolver.resolve(f)
    assert r.source is RemediationSource.BENCHMARK and "PermitRootLogin no" in r.text


# --- SSH, сценарии, секреты ------------------------------------------------------

def test_ssh_command_is_non_interactive_and_key_only():
    opts = ConfigAuditOptions(known_hosts_file="/data/known_hosts", strict_host_keys=True)
    cmd = build_ssh_command("10.0.0.5", _creds(port=2222), "echo hi", opts)
    joined = " ".join(cmd)
    for o in ("BatchMode=yes", "PasswordAuthentication=no", "StrictHostKeyChecking=yes",
              "UserKnownHostsFile=/data/known_hosts", "IdentitiesOnly=yes"):
        assert o in joined
    assert cmd[cmd.index("-p") + 1] == "2222" and cmd[cmd.index("-l") + 1] == "auditor"
    assert cmd[-3:] == ["--", "10.0.0.5", "sh -c 'echo hi'"]


def test_redacted_command_hides_key_path():
    cmd = build_ssh_command("10.0.0.5", _creds(), "secret-script", ConfigAuditOptions())
    red = redact_command(cmd, _creds())
    assert KEY not in red and "secret-script" not in red and "***" in red


def test_credentials_validation_and_repr():
    assert KEY not in repr(_creds())
    with pytest.raises(ValueError):
        SshCredentials(username="-oProxyCommand=x", key_path=KEY)
    with pytest.raises(ValueError):
        SshCredentials(username="auditor", key_path="-oProxyCommand=x")
    with pytest.raises(ValueError):
        SshCredentials(username="auditor", key_path=KEY, port=0)


def test_scripts_use_tempdir_cleanup_and_sudo():
    s = openscap_script("xccdf_org.ssgproject.content_profile_cis", _creds())
    assert "mktemp -d" in s and "trap 'sudo -n rm -rf \"$d\"' EXIT" in s
    assert "sudo -n oscap xccdf eval --profile xccdf_org.ssgproject.content_profile_cis" in s
    nosudo = lynis_script(_creds(sudo=False))
    assert "sudo" not in nosudo and "--usecwd" in nosudo and "trap" in nosudo
    with pytest.raises(ValueError):
        openscap_script("x; rm -rf /", _creds())


def test_lynis_bundle_from_package_layout(tmp_path):
    share, etc = tmp_path / "share", tmp_path / "etc"
    (share / "include").mkdir(parents=True)
    (share / "db").mkdir()
    (share / "include" / "consts").write_text("x")
    (share / "db" / "tests.db").write_text("x")
    etc.mkdir()
    (etc / "default.prf").write_text("x")
    script = tmp_path / "lynis"
    script.write_text("#!/bin/sh\n")
    data = build_lynis_bundle(ConfigAuditOptions(lynis_script=str(script),
                                                 lynis_share_dir=str(share),
                                                 lynis_etc_dir=str(etc)))
    with tarfile.open(fileobj=io.BytesIO(data)) as tar:
        members = {m.name: m for m in tar.getmembers()}
    assert {"lynis/lynis", "lynis/include/consts", "lynis/db/tests.db",
            "lynis/default.prf"} <= set(members)
    assert all(m.uid == 0 for m in members.values())
    assert members["lynis/lynis"].mode == 0o755
    assert members["lynis/include/consts"].mode == 0o644


# --- модуль целиком: allowlist, аудит, лимиты, ошибки ----------------------------

class FakeRunner:
    def __init__(self, by_backend):
        self.by_backend = by_backend
        self.calls = []

    def __call__(self, cmd, stdin, timeout):
        backend = "openscap" if "oscap xccdf eval" in cmd[-1] else "lynis"
        self.calls.append((cmd, backend, stdin))
        return self.by_backend[backend]


def _ok_runner():
    return FakeRunner({"openscap": RunResult(0, gzip.compress(OSCAP), ""),
                       "lynis": RunResult(0, LYNIS.encode(), "")})


def test_run_end_to_end_with_audit(scap_file):
    runner = _ok_runner()
    mod = ConfigAuditModule(ConfigAuditOptions(credentials=_creds(), scap_content=scap_file,
                                               lynis_bundle=scap_file),
                            runner=runner, sleep=lambda s: None)
    ctx = _ctx(["10.0.0.5", "web01.client.local", "10.0.0.0/24"])
    findings = mod.run(ctx)

    # только IP-литерал; остальное — отказ в аудите и никаких подключений
    assert {c[0][-2] for c in runner.calls} == {"10.0.0.5"}
    denied = [r for r in ctx.audit.records if r["action"] == "config_audit_deny"]
    assert {r["target"] for r in denied} == {"web01.client.local", "10.0.0.0/24"}

    ssh = [r for r in ctx.audit.records if r["action"] == "config_audit_ssh"]
    assert [(r["details"]["backend"], r["result"]) for r in ssh] == [
        ("openscap", "started"), ("openscap", "ok"), ("lynis", "started"), ("lynis", "ok")]
    assert ssh[0]["details"]["user"] == "auditor"
    assert KEY not in repr(ctx.audit.records)       # секреты не попадают в аудит
    # datastream передан сжатым через stdin
    assert gzip.decompress(runner.calls[0][2]) == b"<ds/>"

    vids = {f.vuln_id for f in findings}
    assert RULE + "sshd_disable_root_login" in vids and "LYNIS:SSH-7408" in vids
    assert RULE + "sshd_disable_root_login" in mod.remediations
    assert "LYNIS:SSH-7408" in mod.remediations


def test_per_host_credentials_and_skip_without_them(scap_file):
    runner = _ok_runner()
    opts = ConfigAuditOptions(host_credentials={"10.0.0.6": _creds(port=2200)},
                              backends=("lynis",), lynis_bundle=scap_file)
    ctx = _ctx(["10.0.0.5", "10.0.0.6"])
    ConfigAuditModule(opts, runner=runner, sleep=lambda s: None).run(ctx)
    assert [c[0][-2] for c in runner.calls] == ["10.0.0.6"]
    assert "2200" in runner.calls[0][0]
    skip = [r for r in ctx.audit.records if r["action"] == "config_audit_skip"]
    assert [(r["target"], r["result"]) for r in skip] == [("10.0.0.5", "no_credentials")]


def test_backend_failure_is_recorded_not_fatal(scap_file):
    runner = FakeRunner({
        "openscap": RunResult(127, b"", "oscap (openscap-scanner) not found on target"),
        "lynis": RunResult(0, LYNIS.encode(), "")})
    mod = ConfigAuditModule(ConfigAuditOptions(credentials=_creds(), scap_content=scap_file,
                                               lynis_bundle=scap_file),
                            runner=runner, sleep=lambda s: None)
    ctx = _ctx(["10.0.0.5"])
    findings = mod.run(ctx)
    err = next(f for f in findings if f.vuln_id == "INFO:config-audit-error/openscap")
    assert "not found on target" in err.evidence
    results = [(r["details"]["backend"], r["result"]) for r in ctx.audit.records]
    assert ("openscap", "error") in results and ("lynis", "ok") in results
    assert any(f.vuln_id.startswith("LYNIS:") for f in findings)


def test_corrupted_openscap_output_is_error(scap_file):
    runner = FakeRunner({"openscap": RunResult(0, b"not gzip", "")})
    mod = ConfigAuditModule(ConfigAuditOptions(credentials=_creds(), scap_content=scap_file,
                                               backends=("openscap",)),
                            runner=runner, sleep=lambda s: None)
    findings = mod.run(_ctx(["10.0.0.5"]))
    assert [f.vuln_id for f in findings] == ["INFO:config-audit-error/openscap"]


def test_unknown_backend_rejected():
    mod = ConfigAuditModule(ConfigAuditOptions(backends=("agent",)))
    with pytest.raises(ValueError):
        mod.run(_ctx(["10.0.0.5"]))


def test_concurrency_bounded_by_rate_profile(scap_file):
    import threading
    import time as _t

    active, peak, lock = 0, 0, threading.Lock()

    def runner(cmd, stdin, timeout):
        nonlocal active, peak
        with lock:
            active += 1
            peak = max(peak, active)
        _t.sleep(0.02)
        with lock:
            active -= 1
        return RunResult(0, LYNIS.encode(), "")

    rate = RateProfile("t", 1000, 2, 0.0, 3, 2.0)
    mod = ConfigAuditModule(ConfigAuditOptions(credentials=_creds(), backends=("lynis",),
                                               lynis_bundle=scap_file, max_parallel_hosts=8),
                            runner=runner)
    mod.run(_ctx([f"10.0.0.{i}" for i in range(1, 9)], rate=rate))
    assert peak == 2


def test_throttle_spaces_connection_starts():
    now = [0.0]
    slept = []

    def sleep(s):
        slept.append(s)
        now[0] += s

    th = _Throttle(RateProfile("t", 2, 1, 0.0, 3, 2.0), sleep=sleep, clock=lambda: now[0])
    for _ in range(3):
        th.wait()
    assert slept == [pytest.approx(0.5), pytest.approx(0.5)]
    # delay_between_attempts_sec сильнее, чем rps
    th2 = _Throttle(RateProfile("t", 100, 1, 1.5, 3, 2.0), sleep=sleep, clock=lambda: now[0])
    assert th2.interval == 1.5
