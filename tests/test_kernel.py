"""Уязвимости ядра: проверяется РАБОТАЮЩЕЕ ядро (uname -r) по бюллетеням вендора.

Критерии приёмки:
* находки — по пакету работающего ядра, а не по всем установленным ядрам;
* «новое ядро установлено, но хост не перезагружен» — находка остаётся,
  рекомендация «перезагрузите», плюс отдельная находка о перезагрузке;
* livepatch (Canonical Livepatch, kpatch) закрывает CVE;
* Ubuntu — по проверкам «шаблон uname + ABI» из USN OVAL;
* находки привязаны к CVE и БДУ ФСТЭК, у каждой — рекомендация вендора;
* нет бюллетеней / самосборное ядро — явная пометка «не проверено».
"""
from __future__ import annotations

import io
import json
import re

from scanner.core.models import FindingType, InstalledPackage, Severity
from scanner.feeds import kernel as kn
from scanner.feeds.advisories.base import FIXED, OPEN, Advisory
from scanner.feeds.advisories.oval import parse_oval
from scanner.feeds.advisories.store import CachingAdvisoryStore, InMemoryAdvisoryStore
from scanner.feeds.bdu_fstec import BduRecord
from scanner.feeds.matcher import VulnMatcher
from scanner.modules.auth_inventory import (
    INVENTORY_SCRIPT,
    AuthInventoryModule,
    parse_inventory,
)
from tests.test_advisories import Audit, sqlite_store
from tests.test_auth_inventory import FakeShell, cred, ctx_for, reference_store


def dpkg(name, version, source="", source_version=""):
    return f"install ok installed\t{name}\t{version}\tamd64\t{source}\t{source_version}"


DEBIAN_HOST = "\n".join([
    "@@os-release", 'PRETTY_NAME="Debian GNU/Linux 12 (bookworm)"', 'VERSION_ID="12"',
    "VERSION_CODENAME=bookworm", "ID=debian",
    "@@uname", "Linux 6.1.0-18-amd64 x86_64",
    "@@dpkg",
    dpkg("linux-image-6.1.0-10-amd64", "6.1.38-1", "linux-signed-amd64", "6.1.38+1"),
    dpkg("linux-image-6.1.0-18-amd64", "6.1.76-1", "linux-signed-amd64", "6.1.76+1"),
    dpkg("linux-image-6.1.0-21-amd64", "6.1.90-1", "linux-signed-amd64", "6.1.90+1"),
    dpkg("linux-image-amd64", "6.1.90-1", "linux-signed-amd64", "6.1.90+1"),
    dpkg("linux-libc-dev", "6.1.90-1", "linux", ""),
    dpkg("openssl", "3.0.11-1~deb12u2"),
    "@@kernel-release", "6.1.0-18-amd64",
    "@@livepatch",
    "@@reboot-required", "yes",
    "@@end", ""])

DEB_KERNEL = [
    # закрыта уже в работающем 6.1.76-1
    Advisory("debian", "bookworm", "linux", "CVE-2023-1111", FIXED, "6.1.69-1", "DSA-5594-1"),
    # исправлена в 6.1.85-1: работает 6.1.76-1 — уязвим; установленный 6.1.90-1 закрывает
    Advisory("debian", "bookworm", "linux", "CVE-2024-1086", FIXED, "6.1.85-1", "DSA-5658-1"),
    # исправлена позже установленного нового ядра — перезагрузка не поможет
    Advisory("debian", "bookworm", "linux", "CVE-2024-2222", FIXED, "6.1.94-1", "DSA-5700-1"),
    # исправления нет — новых находок не создаёт
    Advisory("debian", "bookworm", "linux", "CVE-2024-3333", OPEN),
]


def matcher_with_kernel_bdu():
    store = reference_store()
    store.upsert_bdu([BduRecord(
        bdu_id="BDU:2024-00810", title="Уязвимость ядра Linux (nf_tables)",
        versions="от 3.15 до 6.7.3 (Linux)", cve_ids=["CVE-2024-1086"],
        severity_text="Высокий уровень опасности (базовая оценка CVSS 3.1 "
                      "составляет 7,8)")])
    return VulnMatcher(store)


def run(output, advisories, matcher=None):
    audit = Audit()
    mod = AuthInventoryModule(matcher=matcher or matcher_with_kernel_bdu(),
                              connector=lambda h, c, o: FakeShell(output),
                              sleep=lambda s: None, advisories=advisories)
    findings = mod.run(ctx_for(["10.0.0.5"], [cred(1)], audit))
    return {f.vuln_id: f for f in findings}, audit


# ---------- работающее ядро ----------

def test_running_kernel_debian_and_pending_reboot():
    inv = parse_inventory(DEBIAN_HOST, "10.0.0.5")
    assert inv.kernel_release == "6.1.0-18-amd64" and inv.reboot_required
    st = kn.kernel_state(inv.kernel_release, inv.packages)
    assert [p.name for p in st.running] == ["linux-image-6.1.0-18-amd64"]
    # мета-пакет linux-image-amd64 и linux-libc-dev — не образы ядра
    assert {p.name for p in st.images} == {"linux-image-6.1.0-10-amd64",
                                           "linux-image-6.1.0-18-amd64",
                                           "linux-image-6.1.0-21-amd64"}
    assert st.pending is not None and st.pending_release == "6.1.0-21-amd64"


def test_running_kernel_rpm_alt_alpine_and_kpatch():
    pk = [InstalledPackage("kernel-core", "5.14.0-362.8.1.el9_3", "rpm", "x86_64"),
          InstalledPackage("kernel-core", "5.14.0-427.13.1.el9_4", "rpm", "x86_64"),
          InstalledPackage("kernel-headers", "5.14.0-427.13.1.el9_4", "rpm", "x86_64"),
          InstalledPackage("kpatch-patch-5_14_0-362_8_1", "1-3.el9_3", "rpm", "x86_64")]
    st = kn.kernel_state("5.14.0-362.8.1.el9_3.x86_64", pk)
    assert st.package and st.package.version == "5.14.0-362.8.1.el9_3"
    assert st.pending and st.pending.version == "5.14.0-427.13.1.el9_4"
    assert [p.name for p in st.kpatch] == ["kpatch-patch-5_14_0-362_8_1"]
    # uname без архитектуры (РЕД ОС) и пакет kernel-lt
    st = kn.kernel_state("6.1.52-1.el7.3", [
        InstalledPackage("kernel-lt", "6.1.52-1.el7.3", "rpm", "x86_64")])
    assert st.package is not None
    # ALT: kernel-image-std-def 6.1.79-alt1 -> uname 6.1.79-std-def-alt1
    alt = InstalledPackage("kernel-image-std-def", "6.1.79-alt1", "rpm", "x86_64")
    assert kn.kernel_state("6.1.79-std-def-alt1", [alt]).package is alt
    # Alpine: linux-lts 6.6.14-r0 -> uname 6.6.14-0-lts
    lts = InstalledPackage("linux-lts", "6.6.14-r0", "apk")
    assert kn.kernel_state("6.6.14-0-lts", [lts]).package is lts
    # самосборное ядро — пакета нет
    assert kn.kernel_state("6.9.0-custom", pk).package is None
    assert kn.abi("5.15.0-89-generic") == "5.15.0-89"
    assert kn.flavor("5.15.0-89-generic") == "-generic"


def test_livepatch_parsing():
    doc = {"Status": [{"Kernel": "5.15.0-89.99-generic", "Running": True,
                       "Livepatch": {"State": "applied", "Fixes": [
                           {"Name": "cve-2024-1086", "Patched": True},
                           {"Name": "cve-2024-2222", "Patched": False}]}}]}
    assert kn.parse_canonical_livepatch(json.dumps(doc)) == {"CVE-2024-1086"}
    assert kn.parse_canonical_livepatch("not json") == set()
    assert kn.parse_livepatch_modules(["livepatch_5_15_0_89 1", "kpatch_old 0",
                                       "bad;name 1"]) == ["livepatch_5_15_0_89"]


def test_inventory_script_reads_kernel_state_read_only():
    s = INVENTORY_SCRIPT
    assert "uname -r" in s and "/sys/kernel/livepatch" in s
    assert "canonical-livepatch\" status --format json" in s.replace("$LP", "canonical-livepatch")
    # только чтение: ни одной команды, меняющей систему, и записи в файлы
    assert not re.search(r"(^|[\s;|&(])(sudo|rm|reboot|shutdown|apt|apt-get|yum|dnf|"
                         r"kill|modprobe|insmod|kpatch|tee)\s", s, re.MULTILINE)
    assert not re.search(r">\s*/(?!dev/null)", s)


# ---------- находки по бюллетеню ----------

def test_debian_running_kernel_findings_with_bdu_and_reboot():
    found, audit = run(DEBIAN_HOST, InMemoryAdvisoryStore(DEB_KERNEL))
    assert "CVE-2023-1111" not in found                    # закрыта в работающем
    assert "CVE-2024-3333" not in found                    # исправления нет
    f = found["CVE-2024-1086"]
    assert f.finding_type is FindingType.VULN and f.module == "auth_inventory"
    assert f.bdu_ids == ["BDU:2024-00810"] and f.severity is Severity.HIGH
    assert "6.1.0-18-amd64" in f.title and "6.1.85-1" in f.title
    assert "DSA-5658-1" in f.evidence and "6.1.76-1" in f.evidence
    assert "перезагрузите" in f.remediation and "6.1.0-21-amd64" in f.remediation
    g = found["CVE-2024-2222"]                             # новое ядро тоже уязвимо
    assert "Обновите ядро" in g.remediation and "6.1.94-1" in g.remediation
    assert g.severity is Severity.MEDIUM and "принят средний" in g.evidence
    r = found["KERNEL-REBOOT-PENDING"]
    assert r.finding_type is FindingType.CONFIG and r.severity is Severity.MEDIUM
    assert "Перезагрузка закроет уязвимостей ядра: 1" in r.evidence
    assert "reboot-required" in r.evidence
    s = found["INFO:auth-inventory"].evidence
    assert "уязвимостей работающего ядра по бюллетеням вендора: 2" in s
    assert "6.1.0-21-amd64, хост не перезагружен" in s
    rec = next(r for r in audit.records if r["action"] == "auth_inventory_kernel")
    assert rec["result"] == "ok" and rec["details"]["vulnerable"] == 2


def test_rebooted_host_with_old_kernels_left_installed():
    booted = DEBIAN_HOST.replace("6.1.0-18-amd64 x86_64", "6.1.0-21-amd64 x86_64") \
        .replace("@@kernel-release\n6.1.0-18-amd64", "@@kernel-release\n6.1.0-21-amd64")
    found, _ = run(booted, InMemoryAdvisoryStore(DEB_KERNEL))
    # старые ядра 6.1.0-10 и 6.1.0-18 установлены, но не работают — находок по ним нет
    assert "CVE-2024-1086" not in found and "KERNEL-REBOOT-PENDING" not in found
    assert "CVE-2024-2222" in found                        # 6.1.90-1 < 6.1.94-1


UBUNTU_OVAL = b"""<?xml version="1.0" encoding="UTF-8"?>
<oval_definitions xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5"
    xmlns:unix-def="http://oval.mitre.org/XMLSchema/oval-definitions-5#unix"
    xmlns:ind-def="http://oval.mitre.org/XMLSchema/oval-definitions-5#independent">
  <definitions>
    <definition class="patch" id="oval:com.ubuntu.jammy:def:66091000000" version="1">
      <metadata>
        <title>USN-6609-1 -- Linux kernel vulnerabilities</title>
        <reference source="USN" ref_id="USN-6609-1"/>
        <reference source="CVE" ref_id="CVE-2024-1086"/>
        <reference source="CVE" ref_id="CVE-2024-2222"/>
      </metadata>
      <criteria operator="OR">
        <criteria operator="AND">
          <criterion test_ref="oval:com.ubuntu.jammy:tst:660910000000"
              comment="Is kernel 5.15.0-\\d+(-generic|-lowlatency) currently running?"/>
          <criterion test_ref="oval:com.ubuntu.jammy:tst:660910000010"
              comment="kernel version comparison"/>
        </criteria>
        <criteria operator="AND">
          <criterion test_ref="oval:com.ubuntu.jammy:tst:660910000020"
              comment="Is kernel 5.15.0-\\d+(-aws) currently running?"/>
          <criterion test_ref="oval:com.ubuntu.jammy:tst:660910000030"
              comment="kernel version comparison"/>
        </criteria>
      </criteria>
    </definition>
  </definitions>
  <tests>
    <unix-def:uname_test check="at least one" id="oval:com.ubuntu.jammy:tst:660910000000" version="1">
      <unix-def:object object_ref="oval:com.ubuntu.jammy:obj:1"/>
      <unix-def:state state_ref="oval:com.ubuntu.jammy:ste:660910000000"/>
    </unix-def:uname_test>
    <ind-def:variable_test check="all" id="oval:com.ubuntu.jammy:tst:660910000010" version="1">
      <ind-def:object object_ref="oval:com.ubuntu.jammy:obj:660910000010"/>
      <ind-def:state state_ref="oval:com.ubuntu.jammy:ste:660910000010"/>
    </ind-def:variable_test>
    <unix-def:uname_test check="at least one" id="oval:com.ubuntu.jammy:tst:660910000020" version="1">
      <unix-def:object object_ref="oval:com.ubuntu.jammy:obj:1"/>
      <unix-def:state state_ref="oval:com.ubuntu.jammy:ste:660910000020"/>
    </unix-def:uname_test>
    <ind-def:variable_test check="all" id="oval:com.ubuntu.jammy:tst:660910000030" version="1">
      <ind-def:object object_ref="oval:com.ubuntu.jammy:obj:660910000010"/>
      <ind-def:state state_ref="oval:com.ubuntu.jammy:ste:660910000030"/>
    </ind-def:variable_test>
  </tests>
  <objects>
    <unix-def:uname_object id="oval:com.ubuntu.jammy:obj:1" version="1"/>
    <ind-def:variable_object id="oval:com.ubuntu.jammy:obj:660910000010" version="1">
      <ind-def:var_ref>oval:com.ubuntu.jammy:var:1</ind-def:var_ref>
    </ind-def:variable_object>
  </objects>
  <states>
    <unix-def:uname_state id="oval:com.ubuntu.jammy:ste:660910000000" version="1">
      <unix-def:os_release operation="pattern match">5.15.0-\\d+(-generic|-lowlatency)</unix-def:os_release>
    </unix-def:uname_state>
    <ind-def:variable_state id="oval:com.ubuntu.jammy:ste:660910000010" version="1">
      <ind-def:value datatype="debian_evr_string" operation="less than">0:5.15.0-94</ind-def:value>
    </ind-def:variable_state>
    <unix-def:uname_state id="oval:com.ubuntu.jammy:ste:660910000020" version="1">
      <unix-def:os_release operation="pattern match">5.15.0-\\d+(-aws)</unix-def:os_release>
    </unix-def:uname_state>
    <ind-def:variable_state id="oval:com.ubuntu.jammy:ste:660910000030" version="1">
      <ind-def:value datatype="debian_evr_string" operation="less than">0:5.15.0-1053</ind-def:value>
    </ind-def:variable_state>
  </states>
</oval_definitions>
"""

UBUNTU_HOST = "\n".join([
    "@@os-release", 'PRETTY_NAME="Ubuntu 22.04.3 LTS"', 'VERSION_ID="22.04"',
    "VERSION_CODENAME=jammy", "ID=ubuntu", "ID_LIKE=debian",
    "@@dpkg",
    dpkg("linux-image-5.15.0-89-generic", "5.15.0-89.99", "linux-signed", "5.15.0-89.99"),
    dpkg("linux-image-5.15.0-94-generic", "5.15.0-94.104", "linux-signed", "5.15.0-94.104"),
    "@@kernel-release", "5.15.0-89-generic",
    "@@livepatch", "livepatch_Ubuntu_5_15_0_89_99_generic_99 1",
    "@@canonical-livepatch",
    json.dumps({"Status": [{"Running": True, "Livepatch": {"Fixes": [
        {"Name": "cve-2024-2222", "Patched": True}]}}]}),
    "@@end", ""])


def ubuntu_records():
    return list(parse_oval(io.BytesIO(UBUNTU_OVAL), "ubuntu", ["jammy"]))


def test_ubuntu_oval_kernel_uname_records():
    recs = ubuntu_records()
    got = {(r.package, r.cve, r.fixed_version, r.advisory_id) for r in recs}
    gen = "uname:5.15.0-\\d+(-generic|-lowlatency)"
    assert (gen, "CVE-2024-1086", "0:5.15.0-94", "USN-6609-1") in got
    assert ("uname:5.15.0-\\d+(-aws)", "CVE-2024-1086", "0:5.15.0-1053",
            "USN-6609-1") in got
    assert kn.uname_matches(gen[len("uname:"):], "5.15.0-89-generic")
    assert not kn.uname_matches(gen[len("uname:"):], "5.15.0-1050-aws")
    assert not kn.uname_matches("(", "x")                  # битый шаблон — не совпадение


def test_ubuntu_kernel_by_uname_and_canonical_livepatch():
    found, audit = run(UBUNTU_HOST, InMemoryAdvisoryStore(ubuntu_records()))
    f = found["CVE-2024-1086"]
    assert f.bdu_ids == ["BDU:2024-00810"]
    assert "USN-6609-1" in f.evidence and "5.15.0-89" in f.evidence
    # 5.15.0-94-generic уже установлено -> перезагрузка закрывает
    assert "перезагрузите" in f.remediation
    # закрыта Canonical Livepatch — находки нет
    assert "CVE-2024-2222" not in found
    s = found["INFO:auth-inventory"].evidence
    assert "закрыто livepatch: 1" in s and "livepatch_Ubuntu_5_15_0_89" in s
    rec = next(r for r in audit.records if r["action"] == "auth_inventory_kernel")
    assert rec["details"]["livepatched"] == ["CVE-2024-2222"]
    # AWS-ядро сверяется со своей веткой ABI
    aws = UBUNTU_HOST.replace("5.15.0-89-generic", "5.15.0-1055-aws") \
        .replace("5.15.0-94-generic", "5.15.0-1056-aws")
    found2, _ = run(aws, InMemoryAdvisoryStore(ubuntu_records()))
    assert "CVE-2024-1086" not in found2


def test_rhel_kernel_core_and_kpatch():
    host = "\n".join([  # noqa: FLY002
        "@@os-release", 'PRETTY_NAME="Red Hat Enterprise Linux 9.3"', "ID=rhel",
        'VERSION_ID="9.3"',
        "@@rpm",
        "kernel-core\t(none):5.14.0-362.8.1.el9_3\tx86_64\tkernel-5.14.0-362.8.1.el9_3.src.rpm",
        "kernel\t(none):5.14.0-362.8.1.el9_3\tx86_64\tkernel-5.14.0-362.8.1.el9_3.src.rpm",
        ("kpatch-patch-5_14_0-362_8_1\t(none):1-3.el9_3\tx86_64\t"
         "kpatch-patch-5_14_0-362_8_1-1-3.el9_3.src.rpm"),
        "@@kernel-release", "5.14.0-362.8.1.el9_3.x86_64",
        "@@end", ""])
    recs = [Advisory("rhel", "9", n, "CVE-2024-1086", FIXED, "0:5.14.0-362.18.1.el9_3",
                     "RHSA-2024:0897") for n in ("kernel", "kernel-core")]
    recs += [Advisory("rhel", "9", "kernel-core", "CVE-2024-2222", FIXED,
                      "0:5.14.0-362.24.1.el9_3", "RHSA-2024:1248"),
             Advisory("rhel", "9", "kpatch-patch-5_14_0-362_8_1", "CVE-2024-2222", FIXED,
                      "0:1-3.el9_3", "RHSA-2024:1250")]
    found, _ = run(host, InMemoryAdvisoryStore(recs))
    f = found["CVE-2024-1086"]
    assert "RHSA-2024:0897" in f.evidence and f.bdu_ids == ["BDU:2024-00810"]
    assert "Обновите ядро" in f.remediation
    assert "CVE-2024-2222" not in found                    # закрыта kpatch
    # kpatch-пакет сам по себе находку «пакет ниже исправленного» не даёт
    assert not any("kpatch" in (x.title or "") for x in found.values())


def test_kernel_not_checked_is_reported_not_silent():
    # Debian, но бюллетени не загружены
    found, audit = run(DEBIAN_HOST, InMemoryAdvisoryStore([]))
    f = found["INFO:kernel-unchecked"]
    assert "6.1.0-18-amd64" in f.title and "не загружены" in f.evidence
    assert "уязвимости ядра не проверены" in found["INFO:auth-inventory"].evidence
    # перезагрузка нужна и без бюллетеней — новое ядро установлено
    assert found["KERNEL-REBOOT-PENDING"].severity is Severity.LOW
    rec = next(r for r in audit.records if r["action"] == "auth_inventory_kernel")
    assert rec["result"] == "not_checked"
    # самосборное ядро: пакета нет — сверить нельзя
    custom = DEBIAN_HOST.replace("@@kernel-release\n6.1.0-18-amd64",
                                 "@@kernel-release\n6.9.3-custom")
    found2, _ = run(custom, InMemoryAdvisoryStore(DEB_KERNEL))
    assert "самосборное" in found2["INFO:kernel-unchecked"].evidence
    assert "CVE-2024-1086" not in found2


def test_sql_and_caching_store_prefix_lookup():
    store = sqlite_store()
    store.replace_release("ubuntu", "jammy", ubuntu_records())
    got = store.with_prefix("ubuntu", "jammy", "uname:")
    assert len(got) == 2 and all(k.startswith("uname:") for k in got)
    assert store.with_prefix("ubuntu", "jammy", "uname_") == {}   # «_» — не шаблон LIKE
    cached = CachingAdvisoryStore(store)
    assert cached.with_prefix("ubuntu", "jammy", "uname:") == got
    mem = InMemoryAdvisoryStore(ubuntu_records())
    assert set(mem.with_prefix("ubuntu", "jammy", "uname:")) == set(got)
