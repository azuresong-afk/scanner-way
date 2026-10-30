"""Тесты аудита конфигураций на эталонном выводе OpenSCAP/Lynis — без SSH.

Фикстуры сняты с реальных движков: oscap 1.3.9 + SSG Debian 12 (профиль
standard, урезано до 6 правил, результаты проставлены) и Lynis 3.0.9
(добавлены строки warning[] в формате report.dat). Транспорт — фейковый
RemoteShell: проверяется, что пароль sudo уходит только в stdin канала, а
секреты не попадают в аудит, находки и тексты ошибок.
"""
import gzip
import io
import json
import tarfile
import threading
from pathlib import Path

import pytest

from scanner.core.credentials import HostCredential
from scanner.core.models import FindingType, HostOs, ServiceInfo, Severity
from scanner.core.ratelimit import RateProfile, get_profile
from scanner.core.sshexec import AuthFailed, CommandResult, SshError
from scanner.modules.base import ScanContext
from scanner.modules.config_audit import (
    MKTEMP_COMMAND,
    PREFLIGHT_COMMAND,
    PROFILE_PREFERENCE,
    ConfigAuditError,
    ConfigAuditModule,
    ConfigAuditOptions,
    HostOsInfo,
    _Throttle,
    build_lynis_bundle,
    cleanup_command,
    lynis_script,
    openscap_script,
    parse_lynis_report,
    parse_openscap_results,
    parse_preflight,
    pick_profile,
    ssg_datastream,
)
from scanner.reporting.remediation import RemediationResolver, RemediationSource

FIX = Path(__file__).parent / "fixtures"
OSCAP = (FIX / "oscap_results.xml").read_bytes()
LYNIS = (FIX / "lynis_report.dat").read_text()
RULE = "xccdf_org.ssgproject.content_rule_"
PASSWORD = "Sudo-Pa55-never-leak"
KEY_TEXT = "-----BEGIN OPENSSH PRIVATE KEY-----\nAAAAkeymaterialnotleak\n-----END OPENSSH PRIVATE KEY-----\n"
TMP = "/tmp/scanner-cfg.Ab12Cd34"
STANDARD = "xccdf_org.ssgproject.content_profile_standard"


class ListAudit:
    def __init__(self):
        self.records = []

    def record(self, **kw):
        self.records.append(kw)


def _ctx(targets, creds=(), rate=None):
    return ScanContext(engagement_id=1, scan_run_id=1, targets=targets,
                       rate=rate or get_profile("gentle"), audit=ListAudit(),
                       credentials=list(creds))


def pw_cred(id=1, name="аудит", targets=(), become="sudo", **kw):
    return HostCredential(id=id, name=name, auth="password", username="auditor",
                          targets=tuple(targets), password=PASSWORD, become=become, **kw)


def key_cred(id=2, name="ключ", targets=(), become="sudo"):
    return HostCredential(id=id, name=name, auth="key", username="auditor",
                          targets=tuple(targets), private_key=KEY_TEXT, become=become)


DS = (b'<ds:data-stream-collection><xccdf:Benchmark>'
      b'<xccdf-1.2:Profile id="' + STANDARD.encode() + b'"/>'
      b'<xccdf-1.2:Profile id="xccdf_org.ssgproject.content_profile_anssi_bp28_high"/>'
      b'</xccdf:Benchmark></ds:data-stream-collection>')


@pytest.fixture
def scap_dir(tmp_path):
    d = tmp_path / "ssg"
    d.mkdir()
    (d / "ssg-debian12-ds.xml").write_bytes(DS)
    return str(d)


@pytest.fixture
def lynis_bundle(tmp_path):
    p = tmp_path / "lynis.tar.gz"
    p.write_bytes(b"lynis-bundle")
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



# --- выбор контента по ОС ----------------------------------------------------------

@pytest.mark.parametrize("family,version,expected", [
    ("debian", "12", "ssg-debian12-ds.xml"),
    ("ubuntu", "22.04", "ssg-ubuntu2204-ds.xml"),
    ("ubuntu", "22.10", None),
    ("rhel", "9.4", "ssg-rhel9-ds.xml"),
    ("oracle", "8.10", "ssg-ol8-ds.xml"),
    ("fedora", "40", "ssg-fedora-ds.xml"),
    ("astra", "1.7_x86-64", None),
    ("redos", "7.3", None),
    ("alt", "10", None),
    ("linux", None, None),
    (None, None, None),
])
def test_ssg_datastream_table(family, version, expected):
    assert ssg_datastream(family, version) == expected


def test_pick_profile_prefers_cis_then_standard():
    assert pick_profile(DS) == STANDARD
    cis = DS.replace(b"anssi_bp28_high", b"cis_level1_server")
    assert pick_profile(cis) == PROFILE_PREFERENCE[0]
    assert pick_profile(b"<Benchmark/>") is None


def test_plan_by_os_family(scap_dir, lynis_bundle):
    mod = ConfigAuditModule(ConfigAuditOptions(scap_dir=scap_dir, lynis_bundle=lynis_bundle))
    tools = frozenset({"oscap", "timeout"})
    deb = mod.plan(HostOsInfo("debian", "12", "Debian 12"), tools)
    assert deb.backends == ["openscap", "lynis"] and deb.profile == STANDARD
    assert deb.content.endswith("ssg-debian12-ds.xml") and not deb.notes
    # Astra Linux: SSG-контента нет — только Lynis, причина в пояснениях
    astra = mod.plan(HostOsInfo("astra", "1.7_x86-64", "Astra Linux"), tools)
    assert astra.backends == ["lynis"] and "Astra Linux" in astra.notes[0]
    # на цели нет oscap — не падаем, только Lynis
    no_oscap = mod.plan(HostOsInfo("debian", "12"), frozenset({"timeout"}))
    assert no_oscap.backends == ["lynis"] and "нет oscap" in no_oscap.notes[0]
    # контент для версии есть в таблице, но не установлен на сканере
    rhel = mod.plan(HostOsInfo("rhel", "9.4"), tools)
    assert rhel.backends == ["lynis"] and "не найден" in rhel.notes[0]


def test_explicit_content_and_profile_override(tmp_path, lynis_bundle):
    ds = tmp_path / "fstec-ds.xml"
    ds.write_bytes(b"<Benchmark/>")
    mod = ConfigAuditModule(ConfigAuditOptions(scap_content=str(ds), scap_profile="fstec_k1",
                                               lynis_bundle=lynis_bundle))
    plan = mod.plan(HostOsInfo("astra", "1.7"), frozenset({"oscap"}))
    assert plan.backends == ["openscap", "lynis"] and plan.profile == "fstec_k1"


def test_parse_preflight():
    pre = parse_preflight("@@os-release\nID=ubuntu\nVERSION_ID=\"22.04\"\n"
                          "PRETTY_NAME=\"Ubuntu 22.04.4 LTS\"\n@@tools\noscap\ntimeout\n"
                          "rm\n@@uid\n1000\n@@end\n")
    assert pre.os == HostOsInfo("ubuntu", "22.04", "Ubuntu 22.04.4 LTS")
    assert pre.tools == {"oscap", "timeout"} and pre.uid == 1000
    astra = parse_preflight("@@os-release\nID=astra\nID_LIKE=debian\nVERSION_ID=1.7_x86-64\n"
                            "PRETTY_NAME=\"Astra Linux\"\n@@tools\n@@uid\n0\n")
    assert astra.os.family == "astra" and astra.uid == 0 and not astra.tools


# --- сценарии на цели ---------------------------------------------------------------

def test_scripts_cleanup_timeout_and_validation():
    s = openscap_script(TMP, "xccdf_org.ssgproject.content_profile_cis", 600)
    assert "trap 'rm -rf \"$d\"' EXIT" in s and "exec </dev/null" in s
    assert 'T="timeout -k 15 600"' in s and "sudo" not in s
    assert "$T oscap xccdf eval --profile xccdf_org.ssgproject.content_profile_cis" in s
    ly = lynis_script(TMP, 600)
    assert "--usecwd" in ly and "trap" in ly and "$d/lynis.tar.gz" in ly
    with pytest.raises(ValueError):
        openscap_script(TMP, "x; rm -rf /", 600)
    for bad in ("/", "/tmp", "/tmp/scanner-cfg.x; rm -rf /", "/etc/scanner-cfg.Ab12Cd34"):
        with pytest.raises(ValueError):
            lynis_script(bad, 600)
        with pytest.raises(ValueError):
            cleanup_command(bad)
    assert cleanup_command(TMP) == f"rm -rf -- {TMP}"


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



# --- модуль целиком на фейковом SSH ------------------------------------------------

DEBIAN = ('@@os-release\nPRETTY_NAME="Debian GNU/Linux 12 (bookworm)"\nID=debian\n'
          'VERSION_ID="12"\n@@tools\noscap\ntimeout\n@@uid\n1001\n@@end\n')
ASTRA = ('@@os-release\nPRETTY_NAME="Astra Linux 1.7"\nID=astra\nID_LIKE=debian\n'
         'VERSION_ID=1.7_x86-64\n@@tools\ntimeout\n@@uid\n1001\n@@end\n')


class FakeShell:
    """Фейковая SSH-сессия: отвечает по виду команды, всё записывает."""

    def __init__(self, net, host, cred):
        self.net, self.host, self.cred = net, host, cred
        self.closed = False

    def run(self, command, timeout, stdin=None):
        self.net.calls.append((self.host, self.cred.id, command, stdin))
        if self.net.drop_on and self.net.drop_on in command:
            self.net.drop_on = None
            raise SshError("SSHException: соединение разорвано")
        if command == PREFLIGHT_COMMAND:
            return CommandResult(0, self.net.os.get(self.host, DEBIAN).encode(), "")
        if command.endswith("true"):
            return self.net.sudo.get(self.cred.id, CommandResult(0, b"", ""))
        if command == MKTEMP_COMMAND:
            return CommandResult(0, (TMP + "\n").encode(), "")
        if "rm -rf --" in command:
            return CommandResult(0, b"", "")
        if "oscap xccdf eval" in command:
            return self.net.oscap
        if "lynis audit system" in command:
            return CommandResult(0, LYNIS.encode(), "")
        raise AssertionError(f"неожиданная команда: {command[:80]}")

    def put(self, path, data, timeout):
        self.net.puts.append((self.host, path, data))

    def close(self):
        self.closed = True


class FakeNet:
    def __init__(self, auth_fail=(), os=None, sudo=None, drop_on=None):
        self.auth_fail = set(auth_fail)
        self.os = os or {}
        self.sudo = sudo or {}
        self.drop_on = drop_on
        self.oscap = CommandResult(0, gzip.compress(OSCAP), "")
        self.calls, self.puts, self.connects, self.shells = [], [], [], []
        self.lock = threading.Lock()

    def __call__(self, host, cred, ssh_opts):
        with self.lock:
            self.connects.append((host, cred.id))
        if cred.id in self.auth_fail:
            raise AuthFailed("учётные данные отклонены")
        sh = FakeShell(self, host, cred)
        self.shells.append(sh)
        return sh


def _mod(net, scap_dir, lynis_bundle, **kw):
    return ConfigAuditModule(ConfigAuditOptions(scap_dir=scap_dir, lynis_bundle=lynis_bundle,
                                                **kw),
                             connector=net, sleep=lambda s: None)


def _dump(ctx, findings):
    """Всё, что уходит наружу: аудит и находки — одной строкой для поиска секретов."""
    return json.dumps(ctx.audit.records, default=str, ensure_ascii=False) + repr(findings)


def test_password_sudo_goes_only_to_stdin(scap_dir, lynis_bundle):
    net = FakeNet()
    mod = _mod(net, scap_dir, lynis_bundle)
    ctx = _ctx(["10.0.0.5"], [pw_cred()])
    findings = mod.run(ctx)

    sudo_calls = [(c, s) for _, _, c, s in net.calls if c.startswith("sudo")]
    assert sudo_calls and all(c.startswith("sudo -S -p '' ") for c, _ in sudo_calls)
    # пароль — только в stdin канала sudo, и ровно строкой с переводом строки
    assert all(s == (PASSWORD + "\n").encode() for _, s in sudo_calls)
    assert all(PASSWORD not in c for _, _, c, _ in net.calls)       # не в argv
    # команды без sudo (предпроверка, mktemp) stdin не получают
    plain = [s for _, _, c, s in net.calls if not c.startswith("sudo")]
    assert plain and all(s is None for s in plain)
    # контент — по SFTP во временный каталог, а не через stdin
    assert [p for _, p, _ in net.puts] == [f"{TMP}/ds.xml.gz", f"{TMP}/lynis.tar.gz"]
    assert gzip.decompress(net.puts[0][2]) == DS
    assert all(sh.closed for sh in net.shells)

    out = _dump(ctx, findings)
    assert PASSWORD not in out and "ds.xml" not in PASSWORD
    vids = {f.vuln_id for f in findings}
    assert RULE + "sshd_disable_root_login" in vids and "LYNIS:SSH-7408" in vids
    assert "INFO:config-audit-no-credentials" not in vids
    root = next(f for f in findings if f.vuln_id == RULE + "sshd_disable_root_login")
    assert "PermitRootLogin no" in root.remediation          # рекомендация в находке
    assert "учётная запись: «аудит» (auditor, password, sudo (пароль учётки))" in root.evidence
    assert "бэкенд: OpenSCAP" in root.evidence
    summary = next(f for f in findings if f.vuln_id == "INFO:config-audit")
    assert "Debian GNU/Linux 12" in summary.title and "OpenSCAP, Lynis" in summary.title
    assert STANDARD in summary.evidence
    become = [r for r in ctx.audit.records if r["action"] == "config_audit_become"]
    assert become[0]["result"] == "ok" and become[0]["details"]["mode"] == "sudo-password"
    execs = [(r["details"]["backend"], r["result"]) for r in ctx.audit.records
             if r["action"] == "config_audit_exec"]
    assert execs == [("openscap", "started"), ("openscap", "ok"),
                     ("lynis", "started"), ("lynis", "ok")]
    assert RULE + "sshd_disable_root_login" in mod.remediations


def test_key_without_nopasswd_gives_clear_error(scap_dir, lynis_bundle):
    net = FakeNet(sudo={2: CommandResult(1, b"", "sudo: a password is required")})
    ctx = _ctx(["10.0.0.5"], [key_cred()])
    findings = _mod(net, scap_dir, lynis_bundle).run(ctx)
    assert [c for _, _, c, _ in net.calls if "true" in c] == ["sudo -n true"]
    assert not net.puts and not any(c == MKTEMP_COMMAND for _, _, c, _ in net.calls)
    [f] = findings
    assert f.vuln_id == "INFO:config-audit-sudo" and "NOPASSWD" in f.evidence
    out = _dump(ctx, findings)
    assert "keymaterialnotleak" not in out and "PRIVATE KEY" not in out


def test_wrong_sudo_password_scrubbed_and_next_credential_used(scap_dir, lynis_bundle):
    # sudo «эхом» вернул пароль в stderr — в находку и аудит он не попадает
    net = FakeNet(sudo={1: CommandResult(1, b"", f"sudo: bad {PASSWORD}: 1 incorrect "
                                                 "password attempt")})
    other = pw_cred(id=3, name="запасная")
    ctx = _ctx(["10.0.0.5"], [pw_cred(), other])
    findings = _mod(net, scap_dir, lynis_bundle, backends=("lynis",)).run(ctx)
    assert net.connects == [("10.0.0.5", 1), ("10.0.0.5", 3)]
    summary = next(f for f in findings if f.vuln_id == "INFO:config-audit")
    assert "«запасная»" in summary.evidence
    assert PASSWORD not in _dump(ctx, findings)
    assert any(r["result"] == "sudo_failed" for r in ctx.audit.records)


def test_credential_scope_and_fallback_on_auth_failure(scap_dir, lynis_bundle):
    narrow = pw_cred(id=1, name="узкая", targets=("10.0.0.5/32",))
    wide = pw_cred(id=2, name="широкая", targets=("10.0.0.0/24",))
    foreign = pw_cred(id=3, name="чужая", targets=("10.9.0.0/24",))
    net = FakeNet(auth_fail={1})
    ctx = _ctx(["10.0.0.5"], [foreign, wide, narrow])
    findings = _mod(net, scap_dir, lynis_bundle, backends=("lynis",)).run(ctx)
    assert net.connects == [("10.0.0.5", 1), ("10.0.0.5", 2)]   # узкая первой, чужая — нет
    assert any(f.vuln_id == "LYNIS:SSH-7408" for f in findings)
    assert not any(f.vuln_id == "INFO:config-audit-auth-failed" for f in findings)
    results = [r["result"] for r in ctx.audit.records if r["action"] == "config_audit_ssh"]
    assert results == ["started", "auth_failed", "started"]


def test_astra_runs_lynis_only(scap_dir, lynis_bundle):
    net = FakeNet(os={"10.0.0.7": ASTRA})
    findings = _mod(net, scap_dir, lynis_bundle).run(_ctx(["10.0.0.7"], [pw_cred()]))
    assert not any("oscap xccdf eval" in c for _, _, c, _ in net.calls)
    assert [p for _, p, _ in net.puts] == [f"{TMP}/lynis.tar.gz"]
    summary = next(f for f in findings if f.vuln_id == "INFO:config-audit")
    assert summary.title.endswith("Lynis") and "нет SCAP-контента SSG" in summary.evidence


def test_host_without_credential_is_reported(scap_dir, lynis_bundle):
    net = FakeNet()
    cred = pw_cred(targets=("10.0.0.5/32",))
    ctx = _ctx(["10.0.0.5", "10.0.0.6", "web.local"], [cred])
    findings = _mod(net, scap_dir, lynis_bundle, backends=("lynis",)).run(ctx)
    none = [f for f in findings if f.vuln_id == "INFO:config-audit-no-credentials"]
    assert [f.host for f in none] == ["10.0.0.6"]
    assert {h for h, _ in net.connects} == {"10.0.0.5"}
    acts = {(r["action"], r["target"], r["result"]) for r in ctx.audit.records}
    assert ("config_audit_skip", "10.0.0.6", "no_credentials") in acts
    assert ("config_audit_deny", "web.local", "not_an_ip_literal") in acts


def test_no_credentials_at_all_reports_every_host(scap_dir, lynis_bundle):
    net = FakeNet()
    findings = _mod(net, scap_dir, lynis_bundle).run(_ctx(["10.0.0.5", "10.0.0.6"]))
    assert [f.vuln_id for f in findings] == ["INFO:config-audit-no-credentials"] * 2
    assert not net.connects


def test_connection_drop_cleans_up_in_new_session(scap_dir, lynis_bundle):
    net = FakeNet(drop_on="oscap xccdf eval")
    ctx = _ctx(["10.0.0.5"], [pw_cred()])
    findings = _mod(net, scap_dir, lynis_bundle).run(ctx)
    err = next(f for f in findings if f.vuln_id == "INFO:config-audit-error/openscap")
    assert "разорвано" in err.evidence
    cleanup = [r for r in ctx.audit.records if r["action"] == "config_audit_cleanup"]
    assert cleanup and cleanup[0]["result"] == "ok"
    assert cleanup[0]["details"] == {"tmpdir": TMP, "rc": 0, "new_session": True}
    rm = [(c, s) for _, _, c, s in net.calls if "rm -rf --" in c]
    assert rm == [(f"sudo -S -p '' rm -rf -- {TMP}", (PASSWORD + "\n").encode())]
    assert len(net.connects) == 2                       # вторая сессия — для уборки
    # Lynis после сбоя OpenSCAP всё равно выполнен
    assert any(f.vuln_id == "LYNIS:SSH-7408" for f in findings)
    summary = next(f for f in findings if f.vuln_id == "INFO:config-audit")
    assert summary.title.endswith("— Lynis")


def test_engine_failure_cleans_up_in_same_session(scap_dir, lynis_bundle):
    net = FakeNet()
    net.oscap = CommandResult(1, b"", "sudo: unable to execute")
    ctx = _ctx(["10.0.0.5"], [pw_cred()])
    findings = _mod(net, scap_dir, lynis_bundle, backends=("openscap",)).run(ctx)
    assert any(f.vuln_id == "INFO:config-audit-error/openscap" for f in findings)
    cleanup = [r for r in ctx.audit.records if r["action"] == "config_audit_cleanup"]
    assert cleanup[0]["details"]["new_session"] is False and len(net.connects) == 1


def test_corrupted_openscap_output_is_error(scap_dir, lynis_bundle):
    net = FakeNet()
    net.oscap = CommandResult(0, b"not gzip", "")
    findings = _mod(net, scap_dir, lynis_bundle, backends=("openscap",)).run(
        _ctx(["10.0.0.5"], [pw_cred()]))
    assert {f.vuln_id for f in findings} == {"INFO:config-audit",
                                             "INFO:config-audit-error/openscap"}


def test_become_none_and_root_login_skip_sudo(scap_dir, lynis_bundle):
    net = FakeNet(os={"10.0.0.8": DEBIAN.replace("@@uid\n1001", "@@uid\n0")})
    ctx = _ctx(["10.0.0.5", "10.0.0.8"], [pw_cred(become="none")])
    findings = _mod(net, scap_dir, lynis_bundle, backends=("lynis",)).run(ctx)
    assert not any(c.startswith("sudo") for _, _, c, _ in net.calls)
    assert all(s is None for _, _, _, s in net.calls)     # пароль не нужен — не отправляем
    by_host = {f.host: f for f in findings if f.vuln_id == "INFO:config-audit"}
    assert "без повышения прав" in by_host["10.0.0.5"].evidence
    assert "вход под root" in by_host["10.0.0.8"].evidence


def test_only_discovered_hosts(scap_dir, lynis_bundle):
    net = FakeNet()
    ctx = _ctx(["10.0.0.5", "10.0.0.6"], [pw_cred()])
    ctx.completed.add("discovery")
    ctx.services = [ServiceInfo("10.0.0.5", 22, "tcp", "ssh")]
    _mod(net, scap_dir, lynis_bundle, backends=("lynis",)).run(ctx)
    assert {h for h, _ in net.connects} == {"10.0.0.5"}
    assert any(r["result"] == "host_not_discovered" for r in ctx.audit.records)


def test_os_fallback_to_discovery_when_os_release_missing(scap_dir, lynis_bundle):
    net = FakeNet(os={"10.0.0.5": "@@os-release\n@@tools\noscap\n@@uid\n1001\n"})
    ctx = _ctx(["10.0.0.5"], [pw_cred()])
    ctx.hosts["10.0.0.5"] = HostOs("10.0.0.5", name="Astra Linux", family="astra")
    findings = _mod(net, scap_dir, lynis_bundle).run(ctx)
    summary = next(f for f in findings if f.vuln_id == "INFO:config-audit")
    assert "Astra Linux" in summary.evidence and summary.title.endswith("Lynis")


def test_unknown_backend_rejected():
    mod = ConfigAuditModule(ConfigAuditOptions(backends=("agent",)))
    with pytest.raises(ValueError):
        mod.run(_ctx(["10.0.0.5"], [pw_cred()]))


def test_concurrency_bounded_by_rate_profile(scap_dir, lynis_bundle):
    import time as _t

    active, peak, lock = 0, 0, threading.Lock()

    class SlowNet(FakeNet):
        def __call__(self, host, cred, ssh_opts):
            nonlocal active, peak
            with lock:
                active += 1
                peak = max(peak, active)
            sh = super().__call__(host, cred, ssh_opts)
            orig = sh.close

            def close():
                nonlocal active
                _t.sleep(0.02)
                with lock:
                    active -= 1
                orig()
            sh.close = close
            return sh

    rate = RateProfile("t", 1000, 2, 0.0, 3, 2.0)
    mod = ConfigAuditModule(ConfigAuditOptions(backends=("lynis",), lynis_bundle=lynis_bundle,
                                               scap_dir=scap_dir, max_parallel_hosts=8),
                            connector=SlowNet())
    mod.run(_ctx([f"10.0.0.{i}" for i in range(1, 9)], [pw_cred()], rate=rate))
    assert peak == 2


def test_config_remediation_refs_from_evidence():
    findings, _ = parse_openscap_results(OSCAP, "10.0.0.5")
    f = next(f for f in findings if f.vuln_id == RULE + "sshd_disable_root_login")
    assert "документы: " in f.evidence and "https://www.cisecurity.org/controls/" in f.evidence
    f.evidence += "; учётная запись: «аудит»"        # как дописывает модуль
    refs = RemediationResolver().references(f)
    assert "https://www.cisecurity.org/controls/" in refs     # без хвостовой «;»
    assert RemediationResolver().resolve(f).source is RemediationSource.BENCHMARK


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
