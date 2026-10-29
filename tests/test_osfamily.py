"""Семейство ОС хоста: классификация, discovery (nmap -O + баннеры), инвентарь договора."""
from pathlib import Path

import pytest

from scanner.core import repository as repo
from scanner.core.db import session_scope
from scanner.core.models import HostInventory, HostOs
from scanner.core.osfamily import FAMILY_ORDER, classify, family_label, is_distro
from scanner.core.ratelimit import get_profile
from scanner.modules.auth_inventory import parse_inventory
from scanner.modules.base import ScanContext
from scanner.modules.discovery import DiscoveryModule, parse_nmap_report

SAMPLE = (Path(__file__).parent / "fixtures" / "nmap_sample.xml").read_text()


@pytest.mark.parametrize(("name", "family"), [
    ("Astra Linux SE 1.7 (Смоленск)", "astra"),
    ("RED OS MUROM (7.3.4)", "redos"),
    ("Альт Сервер 10.1", "alt"),
    ("ALT Linux p10", "alt"),
    ("ROSA Enterprise Linux Server", "rosa"),
    ("Ubuntu 22.04.3 LTS", "ubuntu"),
    ("Debian GNU/Linux 12 (bookworm)", "debian"),
    ("OpenSSH 8.4p1 Debian 5+deb11u1", "debian"),
    ("CentOS Linux 7 (Core)", "centos"),
    ("Red Hat Enterprise Linux 9.2 (Plow)", "rhel"),
    ("Linux 4.15 - 5.8", "linux"),
    ("Microsoft Windows Server 2016", "windows"),
    ("Cisco IOS 15.2", "network"),
    ("MikroTik RouterOS 6.40", "network"),
    ("FreeBSD 13.0", "bsd"),
    ("что-то своё", "other"),
    (None, None),
])
def test_classify_by_name(name, family):
    assert classify(name) == family


def test_classify_prefers_os_release_id():
    assert classify("Debian-like", os_id="astra") == "astra"
    assert classify("RED OS", os_id="redos") == "redos"
    # неизвестный дистрибутив — по ID_LIKE, без него — просто Linux
    assert classify("Linux Mint 21", "linuxmint", "ubuntu debian") == "ubuntu"
    assert classify(None, "elbrus") == "linux"


def test_labels_and_order():
    assert family_label("redos") == "РЕД ОС"
    assert family_label(None) == "ОС не определена"
    assert FAMILY_ORDER[0] == "astra" and FAMILY_ORDER[-1] == "unknown"
    assert is_distro("astra") and not is_distro("linux") and not is_distro("windows")


def test_os_release_family_from_inventory():
    text = ("@@os-release\nPRETTY_NAME=\"Astra Linux\"\nID=astra\nID_LIKE=debian\n"
            "VERSION_ID=1.7_x86-64\n")
    inv = parse_inventory(text, "10.0.0.9")
    assert (inv.os_id, inv.os_like, inv.os_family) == ("astra", "debian", "astra")


def test_discovery_refines_kernel_guess_with_banners():
    _, _, hosts = parse_nmap_report(SAMPLE)
    by = {h.host: h for h in hosts}
    # -O говорит «Linux 5.0 - 5.14», баннер OpenSSH — Ubuntu
    linux = by["10.0.0.5"]
    assert (linux.name, linux.accuracy) == ("Linux 5.0 - 5.14", 98)
    assert (linux.family, linux.source) == ("ubuntu", "banner")
    # -O не сработал, но RDP-сервис помечен ostype=Windows
    win = by["10.0.0.6"]
    assert (win.family, win.source, win.accuracy) == ("windows", "banner", None)
    assert "10.0.0.7" not in by        # down-хост


def test_discovery_module_fills_ctx_hosts():
    class Audit:
        def record(self, **kw):
            pass

    ctx = ScanContext(engagement_id=1, scan_run_id=1, targets=["10.0.0.5", "10.0.0.6"],
                      rate=get_profile("gentle"), audit=Audit())
    DiscoveryModule(runner=lambda cmd, timeout: SAMPLE).run(ctx)
    assert {h: o.family for h, o in ctx.hosts.items()} == {"10.0.0.5": "ubuntu",
                                                          "10.0.0.6": "windows"}


def _run(s, eid, hosts=(), inventory=()):
    rid = repo.create_scan_run(s, engagement_id=eid, modules=["discovery"])
    repo.save_hosts(s, scan_run_id=rid, hosts=hosts)
    if inventory:
        repo.save_inventory(s, scan_run_id=rid, inventories=inventory)
    return rid


def test_engagement_hosts_keeps_most_precise_os(sqlite_factory):
    with session_scope(sqlite_factory) as s:
        eid = repo.create_engagement(s, name="os")
        first = _run(s, eid, [HostOs("10.0.0.1", "Linux 4.15 - 5.8", "linux", 95, "nmap"),
                              HostOs("10.0.0.2", "Linux 4.15 - 5.8", "linux", 95, "nmap")],
                     [HostInventory("10.0.0.1", os_id="astra",
                                    os_name="Astra Linux SE 1.7")])
        # в следующем прогоне только nmap: Astra не затирается «просто Linux»,
        # а 10.0.0.2, ставший Windows, получает новое семейство
        _run(s, eid, [HostOs("10.0.0.1", "Linux 5.0 - 5.14", "linux", 98, "nmap"),
                      HostOs("10.0.0.2", "Microsoft Windows 10", "windows", 96, "nmap"),
                      HostOs("10.0.0.3")])
        # строка до миграции 0007: семейство выводится из os_guess
        legacy = repo.create_scan_run(s, engagement_id=eid, modules=["discovery"])
        repo.save_host(s, scan_run_id=legacy, host="10.0.0.4", os_guess="RED OS 7.3",
                       os_accuracy=100)

        by = {h["host"]: h for h in repo.engagement_hosts(s, eid)}
        assert (by["10.0.0.1"]["os_family"], by["10.0.0.1"]["os_source"],
                by["10.0.0.1"]["os_run_id"]) == ("astra", "ssh", first)
        assert by["10.0.0.1"]["os_guess"] == "Astra Linux SE 1.7"
        assert by["10.0.0.1"]["os_family_label"] == "Astra Linux"
        assert by["10.0.0.2"]["os_family"] == "windows"
        assert (by["10.0.0.3"]["os_family"], by["10.0.0.3"]["os_family_label"]) == (
            None, "ОС не определена")
        assert (by["10.0.0.4"]["os_family"], by["10.0.0.4"]["os_source"]) == ("redos", "ssh")

        assert [h["host"] for h in repo.engagement_hosts(s, eid, os_family="astra")] == [
            "10.0.0.1"]
        assert [h["host"] for h in repo.engagement_hosts(s, eid, os_family="unknown")] == [
            "10.0.0.3"]
