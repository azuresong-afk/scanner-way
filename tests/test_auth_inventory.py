"""Инвентаризация по учётной записи: разбор вывода, пакеты -> ПО, модуль, SSH.

SSH проверяется на настоящем протоколе: in-process сервер paramiko принимает
вход по паролю/ключу и исполняет полученную команду локально — так тест
прогоняет реальный INVENTORY_SCRIPT (dpkg-query контейнера CI) от и до.
"""
from __future__ import annotations

import socket
import subprocess
import threading

import paramiko
import pytest

from scanner.core.audit import AuditSink
from scanner.core.credentials import HostCredential
from scanner.core.models import FindingType, InstalledPackage, ServiceInfo, Severity
from scanner.core.ratelimit import RateProfile
from scanner.core.sshexec import (
    AuthFailed,
    CommandResult,
    HostKeyMismatch,
    SshOptions,
    Unreachable,
    connect,
)
from scanner.feeds import packages as pk
from scanner.feeds.bdu_fstec import BduRecord
from scanner.feeds.matcher import VulnMatcher
from scanner.feeds.nvd import parse_cve_item
from scanner.feeds.store import CachingReferenceStore, InMemoryReferenceStore
from scanner.modules.auth_inventory import (
    INVENTORY_COMMAND,
    AuthInventoryModule,
    AuthInventoryOptions,
    group_software,
    parse_inventory,
)
from scanner.modules.base import ScanContext
from tests.test_credentials import make_key
from tests.test_matcher import nvd_item

PASSWORD = "Very-Secret-Pa55"
FAST = RateProfile("t", 1000, 4, 0.0, 3, 2.0)


class Audit(AuditSink):
    def __init__(self):
        self.records: list[dict] = []

    def record(self, **kw):
        self.records.append(kw)

    def actions(self, action):
        return [r for r in self.records if r["action"] == action]


DPKG_OUT = """@@os-release
PRETTY_NAME="Debian GNU/Linux 12 (bookworm)"
NAME="Debian GNU/Linux"
VERSION_ID="12"
ID=debian
@@uname
Linux 6.1.0-18-amd64 x86_64
@@hostname
web01
@@dpkg
install ok installed\topenssh-server\t1:9.2p1-2+deb12u3\tamd64
install ok installed\topenssh-client\t1:9.2p1-2+deb12u3\tamd64
install ok installed\tlibssl3\t3.0.11-1~deb12u2\tamd64
install ok installed\topenssl\t3.0.11-1~deb12u2\tamd64
install ok installed\tlibssl1.1\t1.1.1n-0+deb11u5\tamd64
install ok installed\tlibc6\t2.36-9+deb12u4\tamd64
install ok installed\tvim\t2:9.0.1378-2\tamd64
install ok installed\tlinux-image-6.1.0-18-amd64\t6.1.76-1\tamd64
install ok installed\tlibfoo9\t1.0-1\tamd64
deinstall ok config-files\tapache2\t2.4.57-2\tamd64
@@end
"""

RPM_OUT = """@@os-release
NAME="RED OS"
VERSION_ID="7.3"
ID="redos"
@@rpm
openssh-server\t(none):8.8p1-6.el7\tx86_64
bash\t0:5.1.16-1\tx86_64
gpg-pubkey\t(none):abc-def\t(none)
@@end
"""

APK_OUT = """@@os-release
ID=alpine
VERSION_ID=3.19.1
@@apk
musl-1.2.4_git20230717-r4
busybox-1.36.1-r15
openssl-3.1.4-r5
@@end
"""


# ---------- разбор ----------
def test_parse_dpkg_inventory():
    inv = parse_inventory(DPKG_OUT, "10.0.0.5")
    assert inv.os_id == "debian" and inv.os_name == "Debian GNU/Linux 12 (bookworm)"
    assert inv.os_version == "12" and inv.hostname == "web01"
    assert inv.kernel == "Linux 6.1.0-18-amd64 x86_64"
    names = [p.name for p in inv.packages]
    assert "apache2" not in names           # удалён, остались только конфиги
    assert names[0] == "openssh-server" and inv.packages[0].version == "1:9.2p1-2+deb12u3"
    assert {p.manager for p in inv.packages} == {"dpkg"}


def test_parse_rpm_and_apk_inventory():
    rpm = parse_inventory(RPM_OUT, "10.0.0.6")
    assert rpm.os_label == "RED OS"
    assert [(p.name, p.version) for p in rpm.packages] == [
        ("openssh-server", "8.8p1-6.el7"), ("bash", "0:5.1.16-1")]
    apk = parse_inventory(APK_OUT, "10.0.0.7")
    assert apk.os_label == "alpine 3.19.1"
    assert ("openssl", "3.1.4-r5", "apk") in [(p.name, p.version, p.manager)
                                               for p in apk.packages]


def test_parse_garbage_is_not_an_error():
    inv = parse_inventory("bash: dpkg-query: not found\n\x00\x01", "10.0.0.8")
    assert inv.packages == [] and inv.os_label is None


# ---------- пакеты -> ПО ----------
@pytest.mark.parametrize(("raw", "up", "distro"), [
    ("1:9.2p1-2+deb12u3", "9.2p1", "9.2p1-2+deb12u3"),
    ("2.4.62-1~deb12u2", "2.4.62", "2.4.62-1~deb12u2"),
    ("1:3.0.7-27.el9", "3.0.7", "3.0.7-27.el9"),
    ("1.2.13.dfsg-1", "1.2.13.dfsg", "1.2.13.dfsg-1"),
    ("1:1.2.13+dfsg-1", "1.2.13", "1.2.13+dfsg-1"),
    ("3.1.4-r5", "3.1.4", "3.1.4-r5"),
    ("5.6.1+really5.4.5-1ubuntu0.4", "5.4.5", "5.6.1+really5.4.5-1ubuntu0.4"),
    ("5.1.16", "5.1.16", "5.1.16"),
])
def test_versions(raw, up, distro):
    assert pk.upstream_version(raw) == up
    assert pk.distro_version(raw) == distro


def test_lookup_known_packages():
    assert pk.lookup("openssh-server").cpe == "cpe:/a:openbsd:openssh"
    assert pk.lookup("libssl3").key == pk.lookup("openssl").key == "openssl"
    assert pk.lookup("apache2").product == "http_server"
    assert pk.lookup("httpd").product == "http_server"
    assert pk.lookup("postgresql-15").key == "postgresql"
    assert pk.lookup("libfoo9") is None
    assert pk.is_kernel("linux-image-6.1.0-18-amd64") and pk.is_kernel("kernel-core")
    assert pk.generic_software("vim-nox", {"vim nox"}).label == "vim-nox"
    assert pk.generic_software("linux", {"linux"}) is None
    assert pk.generic_software("libfoo9", {"vim"}) is None


def test_group_software_merges_packages_of_one_product():
    inv = parse_inventory(DPKG_OUT, "10.0.0.5")
    groups = {(g.software.key, g.upstream): g for g in group_software(inv.packages, set())}
    assert groups[("openssh", "9.2p1")].packages == ["openssh-server", "openssh-client"]
    assert groups[("openssl", "3.0.11")].packages == ["libssl3", "openssl"]
    assert ("openssl", "1.1.1n") in groups                       # другая версия — отдельно
    assert not any(k.startswith("linux") for k, _ in groups)     # ядро не сопоставляется
    assert not any("foo" in k for k, _ in groups)


# ---------- справочник ----------
def reference_store() -> InMemoryReferenceStore:
    store = InMemoryReferenceStore()
    store.upsert_nvd([parse_cve_item(nvd_item("CVE-2024-6387", 8.1, [{
        "vulnerable": True, "criteria": "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*",
        "versionStartIncluding": "8.5", "versionEndExcluding": "9.8"}]))])
    store.upsert_nvd([parse_cve_item(nvd_item("CVE-2023-0464", 7.5, [{
        "vulnerable": True, "criteria": "cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*",
        "versionStartIncluding": "1.1.1", "versionEndExcluding": "1.1.1u"}, {
        "vulnerable": True, "criteria": "cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*",
        "versionStartIncluding": "3.0.0", "versionEndExcluding": "3.0.12"}]))])
    store.upsert_bdu([
        BduRecord(bdu_id="BDU:2024-04970", title="Уязвимость OpenSSH (regreSSHion)",
                  vendor="OpenBSD Project", versions="от 8.5p1 до 9.8p1 (OpenSSH)",
                  severity_text="Высокий уровень опасности (базовая оценка CVSS 3.1 "
                                "составляет 8,1)",
                  cve_ids=["CVE-2024-6387"], remediation="Обновить OpenSSH"),
        # БДУ без CVE, граница в формате дистрибутива
        BduRecord(bdu_id="BDU:2024-11111", title="Уязвимость glibc (Debian)",
                  versions="до 2.36-9+deb12u7 (glibc), 12 (Debian GNU/Linux)",
                  severity_text="Средний уровень опасности (базовая оценка CVSS 3.0 "
                                "составляет 5,5)"),
        BduRecord(bdu_id="BDU:2024-22222", title="Уязвимость glibc (старая)",
                  versions="до 2.19-18+deb8u4 (glibc)",
                  severity_text="Средний уровень опасности"),
        # пакет вне таблицы — по совпадению имени с ПО в БДУ
        BduRecord(bdu_id="BDU:2023-03333", title="Уязвимость Vim",
                  versions="до 9.0.1500 (Vim)",
                  severity_text="Высокий уровень опасности (базовая оценка CVSS 3.0 "
                                "составляет 7,8)"),
        # ОС и ядро — не сопоставляются
        BduRecord(bdu_id="BDU:2024-99999", title="Уязвимость ядра Linux",
                  versions="от 6.0 до 6.2 (Linux), 12 (Debian GNU/Linux)",
                  severity_text="Высокий уровень опасности"),
    ])
    return store


def test_findings_for_package_uses_distro_version_for_distro_bounds():
    m = VulnMatcher(reference_store())
    found = m.findings_for_package("10.0.0.5", product="glibc", version="2.36",
                                   cpe="cpe:/a:gnu:glibc", distro_version="2.36-9+deb12u4",
                                   packages=["libc6"])
    assert [f.vuln_id for f in found] == ["BDU:2024-11111"]   # 2.36-9+deb12u4 < u7
    f = found[0]
    assert f.port is None and f.module == "auth_inventory"
    assert "libc6" in f.evidence and "бэкпорт" in f.evidence
    patched = m.findings_for_package("10.0.0.5", product="glibc", version="2.36",
                                     cpe="cpe:/a:gnu:glibc",
                                     distro_version="2.36-9+deb12u7")
    assert patched == []


# ---------- модуль с подменённым SSH ----------
class FakeShell:
    def __init__(self, output: str):
        self.output, self.commands, self.closed = output, [], False

    def run(self, command, timeout):
        self.commands.append(command)
        return CommandResult(0, self.output.encode(), "")

    def close(self):
        self.closed = True


def ctx_for(targets, creds, audit, services=None):
    return ScanContext(engagement_id=1, scan_run_id=7, targets=targets, rate=FAST,
                       audit=audit, services=services, credentials=list(creds),
                       completed={"discovery"} if services is not None else set())


def cred(i, **kw):
    kw.setdefault("password", PASSWORD)
    return HostCredential(id=i, name=f"учётка {i}", auth="password", username=f"u{i}", **kw)


def test_module_collects_and_matches():
    shells: dict[str, FakeShell] = {}

    def connector(host, c, opts):
        shells[host] = FakeShell(DPKG_OUT)
        return shells[host]

    audit = Audit()
    mod = AuthInventoryModule(matcher=VulnMatcher(reference_store()), connector=connector,
                              sleep=lambda s: None)
    ctx = ctx_for(["10.0.0.5"], [cred(1)], audit)
    findings = mod.run(ctx)
    assert shells["10.0.0.5"].commands == [INVENTORY_COMMAND] and shells["10.0.0.5"].closed
    by_id = {f.vuln_id: f for f in findings}
    # OpenSSH 9.2p1 ∈ [8.5, 9.8): CVE из NVD + связанная БДУ
    ssh = by_id["CVE-2024-6387"]
    assert ssh.bdu_ids == ["BDU:2024-04970"] and ssh.severity is Severity.HIGH
    assert "openssh-server, openssh-client" in ssh.evidence
    # OpenSSL: обе версии уязвимы, находка одна, в evidence — оба пакета
    ssl = by_id["CVE-2023-0464"]
    assert "libssl3" in ssl.evidence and "libssl1.1" in ssl.evidence
    assert "BDU:2024-11111" in by_id and "BDU:2024-22222" not in by_id
    assert "BDU:2023-03333" in by_id                         # vim — по имени из БДУ
    assert "BDU:2024-99999" not in by_id                     # ядро не сопоставляется
    summary = by_id["INFO:auth-inventory"]
    assert summary.finding_type is FindingType.INFO and "Debian GNU/Linux 12" in summary.title
    assert all(f.port is None for f in findings)
    inv = ctx.inventory["10.0.0.5"]
    assert inv.credential_id == 1 and len(inv.packages) == 9
    assert PASSWORD not in repr(audit.records)


def test_module_tries_next_credential_and_reports_errors():
    calls = []

    def connector(host, c, opts):
        calls.append((host, c.id))
        if host == "10.0.0.9":
            raise Unreachable("нет SSH-соединения: timeout")
        if host == "10.0.0.8":
            raise HostKeyMismatch("ключ хоста изменился")
        if c.id == 2:
            raise AuthFailed("учётные данные отклонены")
        return FakeShell(RPM_OUT)

    audit = Audit()
    mod = AuthInventoryModule(connector=connector, sleep=lambda s: None)
    creds = [cred(1), cred(2, targets=("10.0.0.5/32",))]
    findings = mod.run(ctx_for(["10.0.0.5", "10.0.0.8", "10.0.0.9"], creds, audit))
    # узкая область — первой; отказ входа -> следующая учётка
    assert calls[:2] == [("10.0.0.5", 2), ("10.0.0.5", 1)]
    # недоступный хост и подмена ключа — без перебора остальных учёток
    assert calls.count(("10.0.0.9", 1)) == 1 and calls.count(("10.0.0.8", 1)) == 1
    ids = {(f.host, f.vuln_id) for f in findings}
    assert ("10.0.0.5", "INFO:auth-inventory") in ids
    assert ("10.0.0.5", "INFO:auth-inventory-auth-failed") not in ids   # вход удался
    assert ("10.0.0.8", "INFO:auth-inventory-host-key") in ids
    assert ("10.0.0.9", "INFO:auth-inventory-unreachable") in ids
    results = [r["result"] for r in audit.actions("auth_inventory_ssh")]
    assert {"auth_failed", "host_key_mismatch", "unreachable"} <= set(results)


def test_module_skips_hosts_without_credentials_or_not_discovered():
    audit = Audit()
    mod = AuthInventoryModule(connector=lambda *a: pytest.fail("no ssh expected"),
                              sleep=lambda s: None)
    scoped = [cred(1, targets=("10.0.0.0/30",))]
    services = [ServiceInfo("10.0.0.2", 22, "tcp", "ssh")]
    assert mod.run(ctx_for(["10.0.0.9"], scoped, audit)) == []
    assert ("10.0.0.9", "no_credentials") in [(r["target"], r["result"])
                                               for r in audit.actions("auth_inventory_skip")]
    audit2 = Audit()
    mod2 = AuthInventoryModule(connector=lambda h, c, o: FakeShell(APK_OUT),
                               sleep=lambda s: None)
    found = mod2.run(ctx_for(["10.0.0.1", "10.0.0.2"], scoped, audit2, services=services))
    assert {f.host for f in found} == {"10.0.0.2"}
    assert [r["target"] for r in audit2.actions("auth_inventory_skip")] == ["10.0.0.1"]
    # discovery упал (нет nmap): ctx.services пуст, но фильтровать по нему нельзя
    audit3 = Audit()
    ctx = ctx_for(["10.0.0.1"], scoped, audit3)
    ctx.services = []
    assert {f.host for f in mod2.run(ctx)} == {"10.0.0.1"}


def test_caching_store_answers_repeated_lookups_once():
    store = reference_store()
    calls = []
    orig = store.bdu_by_software

    def counting(name):
        calls.append(name)
        return orig(name)

    store.bdu_by_software = counting
    mod = AuthInventoryModule(matcher=VulnMatcher(store),
                              connector=lambda h, c, o: FakeShell(DPKG_OUT),
                              sleep=lambda s: None)
    mod.run(ctx_for(["10.0.0.1", "10.0.0.2", "10.0.0.3"], [cred(1)], Audit()))
    assert len(calls) == len(set(c.upper() for c in calls))
    assert isinstance(mod._run_matcher().store, CachingReferenceStore)


# ---------- настоящий SSH (in-process сервер paramiko) ----------
class _Server(paramiko.ServerInterface):
    def __init__(self, password, pubkey):
        self.password, self.pubkey = password, pubkey
        self.exec_event, self.command = threading.Event(), None

    def get_allowed_auths(self, username):
        return "password,publickey"

    def check_auth_password(self, username, password):
        ok = username == "audit" and password == self.password
        return paramiko.AUTH_SUCCESSFUL if ok else paramiko.AUTH_FAILED

    def check_auth_publickey(self, username, key):
        ok = self.pubkey is not None and key.asbytes() == self.pubkey.asbytes()
        return paramiko.AUTH_SUCCESSFUL if ok else paramiko.AUTH_FAILED

    def check_channel_request(self, kind, chanid):
        return paramiko.OPEN_SUCCEEDED if kind == "session" else \
            paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_exec_request(self, channel, command):
        self.command = command.decode()
        self.exec_event.set()
        return True


class SshTestServer:
    """Слушает 127.0.0.1:<порт>; на exec исполняет команду локально."""

    def __init__(self, password=PASSWORD, pubkey=None):
        self.host_key = paramiko.Ed25519Key.from_private_key(
            __import__("io").StringIO(make_key()))
        self.password, self.pubkey = password, pubkey
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(5)
        self.port = self.sock.getsockname()[1]
        self.commands: list[str] = []
        threading.Thread(target=self._loop, daemon=True).start()

    def _loop(self):
        while True:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            threading.Thread(target=self._serve, args=(conn,), daemon=True).start()

    def _serve(self, conn):
        t = paramiko.Transport(conn)
        t.add_server_key(self.host_key)
        server = _Server(self.password, self.pubkey)
        try:
            t.start_server(server=server)
            chan = t.accept(10)
            if chan is None or not server.exec_event.wait(10):
                return
            self.commands.append(server.command)
            proc = subprocess.run(server.command, shell=True, capture_output=True,
                                  timeout=60, check=False)
            chan.sendall(proc.stdout)
            chan.send_exit_status(proc.returncode)
            chan.close()
        except (paramiko.SSHException, EOFError, OSError):
            pass
        finally:
            t.close()

    def close(self):
        self.sock.close()


@pytest.fixture
def ssh_server():
    srv = SshTestServer()
    yield srv
    srv.close()


def test_real_ssh_password_inventory(ssh_server, tmp_path):
    kh = tmp_path / "known_hosts"
    opts = AuthInventoryOptions(ssh=SshOptions(known_hosts_file=str(kh),
                                               connect_timeout_sec=5))
    c = HostCredential(1, "пароль", "password", "audit", port=ssh_server.port,
                       password=PASSWORD)
    audit = Audit()
    mod = AuthInventoryModule(opts, matcher=VulnMatcher(reference_store()),
                              sleep=lambda s: None)
    ctx = ctx_for(["127.0.0.1"], [c], audit)
    findings = mod.run(ctx)
    assert ssh_server.commands == [INVENTORY_COMMAND]
    inv = ctx.inventory["127.0.0.1"]
    assert inv.os_label                                   # /etc/os-release контейнера
    if inv.packages:                                      # dpkg/rpm/apk есть почти везде
        assert any(p.name == "bash" or p.name.startswith("lib") for p in inv.packages)
    assert any(f.vuln_id == "INFO:auth-inventory" for f in findings)
    # TOFU: ключ хоста запомнен в known_hosts
    line = kh.read_text().split()
    assert line[0] == f"[127.0.0.1]:{ssh_server.port}" and line[1] == "ssh-ed25519"
    assert PASSWORD not in repr(audit.records)


def test_real_ssh_key_auth_wrong_password_and_host_key_checks(tmp_path):
    key_text = make_key()
    pkey = paramiko.Ed25519Key.from_private_key(__import__("io").StringIO(key_text))
    srv = SshTestServer(pubkey=pkey)
    try:
        kh = tmp_path / "known_hosts"
        opts = SshOptions(known_hosts_file=str(kh), connect_timeout_sec=5)
        key_cred = HostCredential(1, "ключ", "key", "audit", port=srv.port,
                                  private_key=key_text)
        shell = connect("127.0.0.1", key_cred, opts)
        try:
            res = shell.run("echo ok", 10)
        finally:
            shell.close()
        assert res.returncode == 0 and res.stdout.strip() == b"ok"

        bad = HostCredential(2, "плохой", "password", "audit", port=srv.port,
                             password="wrong")
        with pytest.raises(AuthFailed):
            connect("127.0.0.1", bad, opts)

        # ключ хоста сменился -> отказ
        other = paramiko.Ed25519Key.from_private_key(__import__("io").StringIO(make_key()))
        kh.write_text(f"[127.0.0.1]:{srv.port} ssh-ed25519 {other.get_base64()}\n")
        with pytest.raises(HostKeyMismatch):
            connect("127.0.0.1", key_cred, opts)
        # строгий режим: неизвестный ключ -> отказ
        strict = SshOptions(known_hosts_file=str(tmp_path / "empty"), strict_host_keys=True,
                            connect_timeout_sec=5)
        with pytest.raises(HostKeyMismatch):
            connect("127.0.0.1", key_cred, strict)
    finally:
        srv.close()


def test_real_ssh_unreachable():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()                                              # порт гарантированно закрыт
    c = HostCredential(1, "x", "password", "audit", port=port, password="p")
    with pytest.raises(Unreachable):
        connect("127.0.0.1", c, SshOptions(connect_timeout_sec=3))


def test_installed_package_model_roundtrip():
    p = InstalledPackage("bash", "5.2.15-2+b2", "dpkg", "amd64")
    assert pk.upstream_version(p.version) == "5.2.15"
