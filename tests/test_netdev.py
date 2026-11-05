"""Аудит сетевого оборудования (netdev_audit): платформы, правила, модуль, SNMP.

CLI устройства заменяется фейковой сессией (FakeSession): модуль выполняет свои
фиксированные команды просмотра, сессия отдаёт заранее заданный вывод — так
проверяются определение платформы, разбор версии, правила конфигурации,
маскирование секретов и сопоставление с NVD/БДУ без настоящего коммутатора.
SNMP проверяется и на фейке, и против живого snmpd (если он установлен).
"""
from __future__ import annotations

import shutil
import socket
import subprocess
import time
from pathlib import Path

import pytest

from scanner.compliance.catalog import default_catalog
from scanner.compliance.engine import evaluate_check
from scanner.core import netexec, sshexec
from scanner.core.credentials import (
    PROTOCOL_NETSSH,
    PROTOCOL_SNMP,
    PROTOCOL_SSH,
    CredentialError,
    HostCredential,
    validate_options,
)
from scanner.core.models import FindingType, Severity
from scanner.core.ratelimit import RateProfile
from scanner.feeds.bdu_fstec import BduRecord
from scanner.feeds.matcher import VulnMatcher
from scanner.feeds.nvd import CpeMatch, NvdRecord
from scanner.feeds.store import InMemoryReferenceStore
from scanner.modules.base import ScanContext
from scanner.modules.netdev import platforms as pf
from scanner.modules.netdev import rules as rl
from scanner.modules.netdev_audit import NetdevAuditModule
from tests.test_auth_inventory import Audit

FIX = Path(__file__).parent / "fixtures" / "netdev"
FAST = RateProfile("t", 1000, 4, 0.0, 3, 2.0)
HOST = "10.0.0.20"
PASSWORD = "Net-Pa55-do-not-leak"

IOS_VERSION = """\
Cisco IOS Software, C2960 Software (C2960-LANBASEK9-M), Version 15.0(2)SE11, RELEASE SOFTWARE (fc3)
Technical Support: http://www.cisco.com/techsupport
lab-sw1 uptime is 3 weeks, 2 days, 4 hours, 10 minutes
cisco WS-C2960-24TT-L (PowerPC405) processor (revision B0) with 65536K bytes of memory.
Model number                    : WS-C2960-24TT-L
System serial number            : FOC1234X0AB
"""
XE_VERSION = """\
Cisco IOS XE Software, Version 17.03.04
Cisco IOS Software [Amsterdam], Catalyst L3 Switch Software (CAT9K_IOSXE), Version 17.3.4, RELEASE SOFTWARE (fc3)
core1 uptime is 1 year, 2 weeks
"""
NXOS_VERSION = """\
Cisco Nexus Operating System (NX-OS) Software
  NXOS: version 9.3(8)
  cisco Nexus9000 C93180YC-EX chassis
  Device name: nx1
"""
ASA_VERSION = """\
Cisco Adaptive Security Appliance Software Version 9.8(4)32
Hardware:   ASA5516, 8192 MB RAM
Serial Number: JAD1234567
"""
JUNOS_VERSION = """\
Hostname: mx1
Model: mx480
Junos: 21.4R3-S5.4
JUNOS OS Kernel 64-bit  [20230101.abc_builder_stable_12]
"""
ROS_VERSION = """\
                   uptime: 3w2d
                  version: 7.12.1 (stable)
               board-name: CCR2004-1G-12S+2XS
                     name: edge-ros
"""
VRP_VERSION = """\
Huawei Versatile Routing Platform Software
VRP (R) software, Version 5.160 (AR3200 V200R007C00SPC500)
Copyright (C) 2011-2016 HUAWEI TECH CO., LTD
Huawei AR3260 Router uptime is 10 days
"""
ESR_VERSION = """\
Boot version:
  1.11.5.0 date 03/09/2021
SW version:
  1.11.5 build 19[2b4d8b1b0] date 03/09/2021
System type: Eltex Service Router ESR-200
"""
MES_VERSION = """\
Active-image: flash://system/images/mes3300-4015-R1.ros
  Version: 4.0.15.1
System Description: MES2324B 28-port 1G/10G Managed Aggregation Switch
"""

JUNOS_CONFIG = """\
set version 21.4R3-S5.4
set system host-name mx1
set system root-authentication encrypted-password "$6$abcdefgh$xyz"
set system services ssh root-login allow
set system services telnet
set system services web-management http
set system syslog host 10.0.0.50 any notice
set system ntp server 10.0.0.1
set snmp community public authorization read-only
set snmp community Wr1te authorization read-write
"""
ROS_CONFIG = """\
# 2024-01-01 12:00:00 by RouterOS 7.12.1
/ip service set telnet disabled=yes
/ip service set ftp disabled=yes
/ip service set www disabled=yes
/ip service set ssh address=10.0.0.0/24
/ip service set api disabled=yes
/ip ssh set strong-crypto=yes
/snmp set enabled=yes
/snmp community set [ find default=yes ] name=S3cretComm
/system ntp client set enabled=yes
/system logging action add name=remote remote=10.0.0.50 target=remote
/tool mac-server set allowed-interface-list=none
/user add name=ops password=hunter2 group=read
"""
VRP_CONFIG = """\
#
 sysname AR3200
#
 telnet server enable
 http server enable
#
aaa
 local-user admin password simple Admin123
 local-user ops password irreversible-cipher $1a$xyz$abc
#
snmp-agent community read cipher %^%#abc%^%#
snmp-agent sys-info version v2c v3
#
info-center loghost 10.0.0.50
#
user-interface vty 0 4
 authentication-mode aaa
 protocol inbound all
 idle-timeout 0 0
#
return
"""


class FakeSession:
    """CLI устройства: вывод по команде; записывает выполненные команды."""

    def __init__(self, outputs: dict[str, str], *, prompt: str = "lab-sw1#",
                 banner: str = "SSH-2.0-Cisco-1.25"):
        self.outputs = outputs
        self.prompt = prompt
        self.banner = banner
        self.commands: list[str] = []
        self.closed = False

    def run(self, command: str, timeout: float) -> str:
        self.commands.append(command)
        return self.outputs.get(command, "% Invalid input detected at '^' marker.")

    def close(self) -> None:
        self.closed = True


def _cred(cid=1, protocol=PROTOCOL_NETSSH, **options) -> HostCredential:
    return HostCredential(id=cid, name="Коммутаторы", auth="password", username="audit",
                          port=161 if protocol == PROTOCOL_SNMP else 22,
                          password=PASSWORD, protocol=protocol,
                          passphrase="PrivKey-do-not-leak" if protocol == PROTOCOL_SNMP
                          else None, options=options, become="none")


def _ctx(creds, targets=(HOST,)) -> ScanContext:
    return ScanContext(engagement_id=1, scan_run_id=1, targets=list(targets), rate=FAST,
                       audit=Audit(), credentials=list(creds))


def _ios_session() -> FakeSession:
    return FakeSession({"show version": IOS_VERSION, "terminal length 0": "",
                        "terminal width 0": "",
                        "show running-config": (FIX / "ios_insecure.txt").read_text()})


# ---------- платформы ----------

@pytest.mark.parametrize("text,platform,version,model", [
    (IOS_VERSION, "cisco_ios", "15.0(2)SE11", "WS-C2960-24TT-L"),
    (XE_VERSION, "cisco_xe", "17.03.04", None),
    (NXOS_VERSION, "cisco_nxos", "9.3(8)", "Nexus9000"),
    (ASA_VERSION, "cisco_asa", "9.8(4)32", "ASA5516"),
    (JUNOS_VERSION, "junos", "21.4R3-S5", "mx480"),
    (ROS_VERSION, "routeros", "7.12.1", "CCR2004-1G-12S+2XS"),
    (VRP_VERSION, "huawei_vrp", "V200R007C00SPC500", "AR3200"),
    (ESR_VERSION, "eltex_esr", "1.11.5", "ESR-200"),
    (MES_VERSION, "eltex_mes", "4.0.15.1", "MES2324B"),
])
def test_detect_and_parse_version(text, platform, version, model):
    assert pf.detect(text) == platform
    info = pf.parse_version(platform, text)
    assert info.version == version
    if model:
        assert info.model == model


def test_huawei_base_version_candidate():
    info = pf.parse_version("huawei_vrp", VRP_VERSION)
    assert info.extra_versions == ["V200R007C00"]
    assert pf.bdu_names(info) == ["Huawei AR3200", "AR3200"]
    assert pf.cpe_for(info) == "cpe:/o:huawei:ar3200_firmware"


@pytest.mark.parametrize("prompt,banner,expected", [
    ("<HUAWEI>", "SSH-2.0-HUAWEI-1.5", "huawei_vrp"),
    ("ops@mx1>", "SSH-2.0-OpenSSH_7.5", "junos"),
    ("[admin@MikroTik] >", "", "routeros"),
    ("sw1#", "SSH-2.0-ROSSSH", "routeros"),
    ("sw1#", "SSH-2.0-Cisco-1.25", None),
])
def test_detect_by_prompt(prompt, banner, expected):
    assert pf.detect_by_prompt(prompt, banner) == expected


def test_sysdescr_versions():
    descr = ("Cisco IOS Software, C2960 Software (C2960-LANBASEK9-M), Version 15.0(2)SE11, "
             "RELEASE SOFTWARE (fc3)")
    assert pf.parse_version(pf.detect(descr), descr).version == "15.0(2)SE11"
    jdescr = "Juniper Networks, Inc. ex2200-24t-4g Ethernet Switch, kernel JUNOS 12.3R12.4, Build"
    info = pf.parse_version(pf.detect(jdescr), jdescr)
    assert (info.platform, info.version, info.model) == ("junos", "12.3R12", "ex2200-24t-4g")


# ---------- правила конфигурации ----------

def _statuses(family, text):
    return {e.rule.id: e.result for e in rl.evaluate(family, text)}


def test_ios_insecure_config_fails():
    res = _statuses("ios", (FIX / "ios_insecure.txt").read_text())
    for rid in ("telnet_mgmt", "ssh_v2", "http_mgmt", "snmp_v12", "snmp_rw",
                "snmp_default_community", "password_encryption", "enable_secret",
                "local_user_secret", "aaa", "session_timeout", "mgmt_acl", "login_banner",
                "remote_logging", "ntp", "insecure_services", "source_route", "login_block"):
        assert res[rid].status == rl.FAIL, rid
    # vty 5 15 без transport input — тоже нарушение
    assert any("line vty 5 15" in x for x in res["telnet_mgmt"].evidence)


def test_ios_hardened_config_passes():
    res = _statuses("ios", (FIX / "ios_hardened.txt").read_text())
    failed = {k for k, v in res.items() if v.status == rl.FAIL}
    assert failed == set(), failed
    assert res["enable_secret"].status == rl.PASS


def test_evidence_never_contains_secrets():
    texts = [(FIX / "ios_insecure.txt").read_text(), (FIX / "ios_hardened.txt").read_text()]
    secrets = ["0822455D0A16544541", "13061E010803557878", "$1$mERr", "Wr1teC0mm",
               "104D000A0618", "AuthKey123", "PrivKey123", "$9$nhEmQ"]
    for text in texts:
        for e in rl.evaluate("ios", text):
            joined = "\n".join(e.result.evidence)
            for s in secrets:
                assert s not in joined, (e.rule.id, s)
    for family, text, secrets in (
            ("junos", JUNOS_CONFIG, ["$6$abcdefgh", "Wr1te"]),
            ("routeros", ROS_CONFIG, ["S3cretComm", "hunter2"]),
            ("vrp", VRP_CONFIG, ["Admin123", "$1a$xyz", "%^%#abc"])):
        for e in rl.evaluate(family, text):
            joined = "\n".join(e.result.evidence)
            for s in secrets:
                assert s not in joined, (family, e.rule.id, s)


def test_junos_rules():
    res = _statuses("junos", JUNOS_CONFIG)
    assert res["telnet_mgmt"].status == rl.FAIL
    assert res["ssh_root_login"].status == rl.FAIL
    assert res["http_mgmt"].status == rl.FAIL
    assert res["snmp_default_community"].status == rl.FAIL
    assert res["snmp_rw"].status == rl.FAIL
    assert res["remote_logging"].status == rl.PASS
    assert res["ntp"].status == rl.PASS


def test_routeros_hardened_export():
    res = _statuses("routeros", ROS_CONFIG)
    for rid in ("telnet_mgmt", "http_mgmt", "insecure_services", "mgmt_acl", "ssh_crypto",
                "remote_logging", "ntp", "mac_server", "snmp_default_community", "snmp_rw"):
        assert res[rid].status == rl.PASS, rid
    # community переименован, но SNMP v1/v2c разрешён (нет security=private)
    assert res["snmp_v12"].status == rl.FAIL


def test_routeros_defaults_fail():
    res = _statuses("routeros", "# by RouterOS 7.12\n/system identity set name=r1\n")
    for rid in ("telnet_mgmt", "http_mgmt", "insecure_services", "mac_server", "mgmt_acl"):
        assert res[rid].status == rl.FAIL, rid
    assert res["snmp_v12"].status == rl.PASS          # SNMP выключен по умолчанию


def test_huawei_rules():
    res = _statuses("vrp", VRP_CONFIG)
    for rid in ("telnet_mgmt", "http_mgmt", "snmp_v12", "local_user_secret",
                "session_timeout", "mgmt_acl"):
        assert res[rid].status == rl.FAIL, rid
    assert res["remote_logging"].status == rl.PASS


def test_eltex_explicit_unknown_is_na():
    res = _statuses("mes", "hostname mes\nlogging host 10.0.0.50\n")
    assert res["telnet_mgmt"].status == rl.NA
    assert res["remote_logging"].status == rl.PASS
    res = _statuses("esr", "hostname esr\nip telnet server\n")
    assert res["telnet_mgmt"].status == rl.FAIL


def test_compliance_catalog_references_existing_rules():
    cat = default_catalog()
    used = {r for c in cat.checks.values() for r in c.netdev}
    assert used, "каталог должен ссылаться на правила netdev"
    assert used <= set(rl.RULES_BY_ID), used - set(rl.RULES_BY_ID)


# ---------- модуль ----------

class FirmwareMatcher:
    """Слой сопоставления над справочником в памяти: CVE по CPE cisco:ios и запись
    БДУ для Huawei AR3200."""

    def __init__(self):
        store = InMemoryReferenceStore()
        store.upsert_nvd([NvdRecord(
            cve_id="CVE-2023-20198", cvss_v3=10.0, severity="CRITICAL",
            cpe_matches=[CpeMatch(cve_id="CVE-2023-20198",
                                  criteria="cpe:2.3:o:cisco:ios:15.0\\(2\\)se11:*:*:*:*:*:*:*",
                                  vendor="cisco", product="ios", version="15.0(2)se11")])])
        store.upsert_bdu([BduRecord(bdu_id="BDU:2017-00756", title="Уязвимость Huawei AR3200",
                                    software="Huawei AR3200",
                                    versions="до V200R007C00SPC600 (Huawei AR3200)",
                                    severity_text="Высокий уровень опасности (базовая оценка "
                                                  "CVSS 2.0 составляет 7,8)")])
        self.store = store
        self.m = VulnMatcher(store)

    def findings_for_firmware(self, host, **kw):
        return self.m.findings_for_firmware(host, **kw)


def test_module_cisco_full_cycle():
    session = _ios_session()
    opened = []

    def opener(host, cred, opts):
        opened.append((host, cred.id))
        return session

    ctx = _ctx([_cred()])
    mod = NetdevAuditModule(matcher=FirmwareMatcher(), cli_opener=opener,
                            snmp_getter=lambda *a: pytest.fail("SNMP не нужен"),
                            sleep=lambda s: None)
    findings = mod.run(ctx)
    assert opened == [(HOST, 1)] and session.closed
    # только команды из фиксированного списка
    assert session.commands == ["show version", "terminal length 0", "terminal width 0",
                                "show version", "show running-config"]
    inv = ctx.inventory[HOST]
    assert inv.os_id == "network" and inv.os_version == "15.0(2)SE11"
    assert inv.packages[0].manager == "firmware"
    vulns = [f for f in findings if f.finding_type is FindingType.VULN]
    assert [f.vuln_id for f in vulns] == ["CVE-2023-20198"]
    assert vulns[0].severity is Severity.CRITICAL
    assert "Бюллетени вендора" in vulns[0].evidence
    cfg = {f.vuln_id for f in findings if f.finding_type is FindingType.CONFIG}
    assert {"NETDEV:telnet_mgmt", "NETDEV:snmp_default_community",
            "NETDEV:enable_secret"} <= cfg
    summary = next(f for f in findings if f.vuln_id == "INFO:netdev-inventory")
    assert "Cisco IOS 15.0(2)SE11" in summary.title
    facts = ctx.compliance_facts[HOST]["netdev"]
    assert facts["platform"] == "cisco_ios" and facts["rules"]["telnet_mgmt"] == "fail"
    assert ctx.coverage.get(HOST, "netdev_audit").status == "completed"
    # пароль учётки и секреты конфигурации нигде не сохранились
    blob = repr(ctx.audit.records) + "".join(
        (f.evidence or "") + (f.remediation or "") + f.title for f in findings)
    for secret in (PASSWORD, "0822455D0A16544541", "Wr1teC0mm"):
        assert secret not in blob


def test_module_compliance_check_from_facts():
    ctx = _ctx([_cred()])
    mod = NetdevAuditModule(cli_opener=lambda *a: _ios_session(), sleep=lambda s: None)
    findings = mod.run(ctx)
    from scanner.compliance.engine import _HostData
    d = _HostData(facts=ctx.compliance_facts[HOST], findings=findings)
    cat = default_catalog()
    res = evaluate_check(cat.checks["insecure_remote_protocols"], d)
    assert res["status"] == "failed"
    assert any(x.get("vuln_id") == "NETDEV:telnet_mgmt" for x in res["failures"])


def test_module_denied_config_is_not_audited():
    session = FakeSession({"show version": IOS_VERSION})       # show run -> % Invalid input
    ctx = _ctx([_cred()])
    findings = NetdevAuditModule(cli_opener=lambda *a: session,
                                 sleep=lambda s: None).run(ctx)
    assert not [f for f in findings if f.finding_type is FindingType.CONFIG]
    summary = next(f for f in findings if f.vuln_id == "INFO:netdev-inventory")
    assert "нет прав" in summary.evidence


def test_module_platform_hint_skips_detection():
    session = FakeSession({"display version": VRP_VERSION, "screen-length 0 temporary": "",
                           "display current-configuration": VRP_CONFIG}, prompt="<AR3200>")
    ctx = _ctx([_cred(platform="huawei_vrp")])
    findings = NetdevAuditModule(matcher=FirmwareMatcher(), cli_opener=lambda *a: session,
                                 sleep=lambda s: None).run(ctx)
    assert session.commands[0] == "screen-length 0 temporary"
    vulns = [f.vuln_id for f in findings if f.finding_type is FindingType.VULN]
    assert vulns == ["BDU:2017-00756"]


def test_module_auth_failed_then_snmp_fallback():
    def opener(host, cred, opts):
        raise sshexec.AuthFailed("отклонено")

    descr = "Cisco IOS Software, C2960 Software, Version 15.0(2)SE11, RELEASE SOFTWARE"
    got = []

    def snmp(host, cred):
        got.append(cred.id)
        return {netexec.OID_SYS_DESCR: descr, netexec.OID_SYS_NAME: "lab-sw1"}

    ctx = _ctx([_cred(1), _cred(2, PROTOCOL_SNMP, snmp_version="2c")])
    findings = NetdevAuditModule(matcher=FirmwareMatcher(), cli_opener=opener,
                                 snmp_getter=snmp, sleep=lambda s: None).run(ctx)
    assert got == [2]
    assert ctx.inventory[HOST].hostname == "lab-sw1"
    ids = {f.vuln_id for f in findings}
    assert "CVE-2023-20198" in ids
    assert "NETDEV:snmp_v12" in ids                    # агент ответил на v2c
    assert ctx.compliance_facts[HOST]["netdev"]["source"] == "snmp"


def test_module_ignores_server_credentials():
    ctx = _ctx([HostCredential(id=9, name="linux", auth="password", username="root",
                               password="x", protocol=PROTOCOL_SSH)])
    findings = NetdevAuditModule(cli_opener=lambda *a: pytest.fail("нельзя"),
                                 sleep=lambda s: None).run(ctx)
    assert findings == []
    assert ctx.coverage.get(HOST, "netdev_audit").status == "not_applicable"


def test_module_unreachable_marks_coverage():
    def opener(host, cred, opts):
        raise sshexec.SshTimeout("таймаут TCP")
    ctx = _ctx([_cred()])
    findings = NetdevAuditModule(cli_opener=opener, sleep=lambda s: None).run(ctx)
    assert [f.vuln_id for f in findings] == ["INFO:netdev-unreachable"]
    assert ctx.coverage.get(HOST, "netdev_audit").status == "timeout"


# ---------- учётки ----------

def test_validate_options():
    assert validate_options(PROTOCOL_NETSSH, {}) == {"platform": "auto"}
    assert validate_options(PROTOCOL_SNMP, {"snmp_version": "2c", "x": 1}) == {
        "snmp_version": "2c"}
    assert validate_options(PROTOCOL_SNMP, {}) == {
        "snmp_version": "3", "auth_proto": "sha", "priv_proto": "aes"}
    with pytest.raises(CredentialError):
        validate_options(PROTOCOL_NETSSH, {"platform": "cisco; reload"})
    with pytest.raises(CredentialError):
        validate_options(PROTOCOL_SNMP, {"snmp_version": "1"})


def test_describe_has_no_secrets():
    d = _cred(protocol=PROTOCOL_SNMP, snmp_version="3", auth_proto="sha", priv_proto="aes")
    text = repr(d) + repr(d.describe())
    assert PASSWORD not in text and "PrivKey-do-not-leak" not in text


# ---------- интерактивный CLI ----------

class FakeChannel:
    """paramiko-канал интерактивного CLI: на каждую команду — вывод с пейджингом."""

    def __init__(self, prompt: str, replies: dict[str, list[str]]):
        self.prompt = prompt
        self.replies = replies
        self.pending: list[bytes] = [f"\r\nWelcome\r\n{prompt}".encode()]
        self.sent: list[str] = []
        self.closed = False
        self._more: list[str] = []

    def settimeout(self, t):
        pass

    def recv_ready(self):
        return bool(self.pending)

    def recv(self, n):
        return self.pending.pop(0)

    def exit_status_ready(self):
        return False

    def send(self, data: str):
        self.sent.append(data)
        if data == " " and self._more:
            self.pending.append(self._more.pop(0).encode())
            return
        cmd = data.rstrip("\n")
        parts = self.replies.get(cmd, [""])
        first, *rest = parts
        self._more = [p + (f"\r\n{self.prompt}" if i == len(rest) - 1 else "")
                      for i, p in enumerate(rest)]
        tail = "" if rest else f"\r\n{self.prompt}"
        self.pending.append(f"{cmd}\r\n{first}{tail}".encode())

    def close(self):
        self.closed = True


class FakeParamikoShell:
    def __init__(self, chan):
        self.chan = chan
        self.client = self
        self.closed = False

    def invoke_shell(self, **kw):
        return self.chan

    def close(self):
        self.closed = True


def test_shell_session_prompt_paging_and_echo():
    chan = FakeChannel("lab-sw1#", {
        "show version": ["Cisco IOS Software, Version 15.0(2)SE11\r\nline2\r\n --More-- ",
                         "\x1b[Kline3"]})
    sess = netexec.ShellSession(FakeParamikoShell(chan), "SSH-2.0-Cisco-1.25",
                                prompt_timeout=2, sleep=lambda s: None)
    assert sess.prompt == "lab-sw1#"
    out = sess.run("show version", 2)
    assert "Version 15.0(2)SE11" in out and "line3" in out
    assert "lab-sw1#" not in out and not out.startswith("show version")
    assert chan.sent == ["show version\n", " "]


def test_shell_session_rejects_multiline_command():
    chan = FakeChannel("<AR>", {})
    sess = netexec.ShellSession(FakeParamikoShell(chan), "", prompt_timeout=2,
                                sleep=lambda s: None)
    with pytest.raises(ValueError):
        sess.run("display version\nreboot", 2)


# ---------- проверка входа ----------

def test_credcheck_snmp():
    from scanner.core import credcheck

    def fake_get(host, cred, oids, opts):
        if cred.options.get("snmp_version") == "2c":
            raise netexec.SnmpTimeout("нет ответа")
        return {netexec.OID_SYS_DESCR: "Cisco IOS Software, Version 15.0(2)SE11"}

    c = credcheck.Connectors(ssh_options=sshexec.SshOptions(), win_options=None,
                             snmp_get=fake_get,
                             probe=lambda *a: pytest.fail("SNMP — без TCP-пробы"))
    ok = credcheck.check_login(HOST, _cred(1, PROTOCOL_SNMP, snmp_version="3"), c)
    assert ok.status == credcheck.OK and "агент ответил" in ok.message
    bad = credcheck.check_login(HOST, _cred(2, PROTOCOL_SNMP, snmp_version="2c"), c)
    assert bad.status == credcheck.TIMEOUT


# ---------- SNMP против живого snmpd ----------

def _free_udp_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture(scope="module")
def snmpd(tmp_path_factory):
    binary = shutil.which("snmpd") or ("/usr/sbin/snmpd" if Path("/usr/sbin/snmpd").exists()
                                       else None)
    if binary is None:
        pytest.skip("snmpd не установлен")
    pytest.importorskip("pysnmp")
    d = tmp_path_factory.mktemp("snmpd")
    port = _free_udp_port()
    (d / "snmpd.conf").write_text(
        f"agentAddress udp:127.0.0.1:{port}\n"
        "rocommunity labcomm 127.0.0.1\n"
        'createUser v3user SHA "authpass123" AES "privpass123"\n'
        "rouser v3user priv\n"
        "sysDescr Cisco IOS Software, C2960 Software (C2960-LANBASEK9-M), Version "
        "15.0(2)SE11, RELEASE SOFTWARE (fc3)\n"
        "sysName lab-sw1\n")
    proc = subprocess.Popen([binary, "-f", "-Lo", "-C", "-c", str(d / "snmpd.conf"),
                             f"--persistent-dir={d}"], stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL)
    time.sleep(1.0)
    yield port
    proc.terminate()
    proc.wait(timeout=5)


def _snmp_cred(port, **kw):
    base = {"id": 1, "name": "snmp", "auth": "password", "username": "v3user", "port": port,
            "password": "authpass123", "passphrase": "privpass123", "protocol": PROTOCOL_SNMP,
            "options": {"snmp_version": "3", "auth_proto": "sha", "priv_proto": "aes"}}
    base.update(kw)
    return HostCredential(**base)


def test_live_snmp_v3_and_v2c(snmpd):
    opts = netexec.SnmpOptions(timeout_sec=1, retries=0)
    v3 = netexec.snmp_get("127.0.0.1", _snmp_cred(snmpd), opts=opts)
    assert "15.0(2)SE11" in v3[netexec.OID_SYS_DESCR]
    assert v3[netexec.OID_SYS_NAME] == "lab-sw1"
    assert netexec.OID_MIKROTIK_VERSION not in v3          # нет такого OID — пропущен
    v2 = netexec.snmp_get("127.0.0.1", _snmp_cred(
        snmpd, username="community", password="labcomm", passphrase=None,
        options={"snmp_version": "2c"}), opts=opts)
    assert v2[netexec.OID_SYS_NAME] == "lab-sw1"


def test_live_snmp_errors(snmpd):
    opts = netexec.SnmpOptions(timeout_sec=1, retries=0)
    with pytest.raises(netexec.SnmpAuthFailed):
        netexec.snmp_get("127.0.0.1", _snmp_cred(snmpd, password="wrongpass1"), opts=opts)
    with pytest.raises(netexec.SnmpTimeout):
        netexec.snmp_get("127.0.0.1", _snmp_cred(
            snmpd, password="badcomm", options={"snmp_version": "2c"}), opts=opts)


def test_live_snmp_module(snmpd):
    ctx = _ctx([_snmp_cred(snmpd)], targets=("127.0.0.1",))
    mod = NetdevAuditModule(matcher=FirmwareMatcher(), sleep=lambda s: None)
    mod.options.snmp = netexec.SnmpOptions(timeout_sec=1, retries=0)
    findings = mod.run(ctx)
    assert "CVE-2023-20198" in {f.vuln_id for f in findings}
    assert ctx.inventory["127.0.0.1"].os_version == "15.0(2)SE11"


# ---------- состав прогона ----------

def test_plan_network_devices_profile_and_engine():
    from scanner.core.profiles import PROFILES, plan_modules
    prof = PROFILES["network_devices"]
    plan = plan_modules(prof.modules, protocols={"netssh"}, engine_modules=prof.modules)
    assert plan.names == ["discovery", "netdev_audit"] and not plan.warnings
    # движок «По учётной записи» с одной SSH-учёткой сервера: netdev_audit убран
    eng = ["discovery", "auth_inventory", "win_inventory", "netdev_audit"]
    plan = plan_modules(eng, protocols={"ssh"}, engine_modules=eng[1:])
    assert "netdev_audit" in [m.name for m in plan.removed]
    # только SNMP-учётка: серверные модули убраны, netdev остаётся
    plan = plan_modules(eng, protocols={"snmp"}, engine_modules=eng[1:])
    assert plan.names == ["discovery", "netdev_audit"]


def test_host_family_from_netdev_inventory():
    ctx = _ctx([_cred()])
    NetdevAuditModule(cli_opener=lambda *a: _ios_session(), sleep=lambda s: None).run(ctx)
    assert ctx.host_family(HOST) == "network"
