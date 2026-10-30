"""Учёт бэкпортов (R2): бюллетени дистрибутивов и решение по находкам.

Критерии приёмки: на «пакете с бэкпортом» находка не создаётся; «пакет ниже
fixed» — создаётся с БДУ; «нет данных вендора» — как раньше, с оговоркой.
"""
from __future__ import annotations

import bz2
import gzip
import json
import zipfile
from pathlib import Path

import pytest
from sqlalchemy import create_engine
from sqlalchemy.pool import StaticPool

from scanner.core.audit import AuditSink
from scanner.feeds.advisories import FAMILIES, host_release
from scanner.feeds.advisories.assess import Verdict, combine, decide
from scanner.feeds.advisories.base import FIXED, NOT_AFFECTED, OPEN, Advisory
from scanner.feeds.advisories.debian import parse_tracker
from scanner.feeds.advisories.oval import parse_oval
from scanner.feeds.advisories.store import (
    CachingAdvisoryStore,
    InMemoryAdvisoryStore,
    SqlAdvisoryStore,
)
from scanner.feeds.advisories.sync import AdvisoryError, parse_targets, sync_releases
from scanner.feeds.bdu_fstec import BduRecord
from scanner.feeds.matcher import BACKPORT_CAVEAT, VulnMatcher
from scanner.feeds.sources import SOURCES
from scanner.modules.auth_inventory import AuthInventoryModule, parse_inventory
from tests.test_auth_inventory import FakeShell, cred, ctx_for, reference_store

FIX = Path(__file__).parent / "fixtures" / "advisories"


class Audit(AuditSink):
    def __init__(self):
        self.records: list[dict] = []

    def record(self, **kw):
        self.records.append(kw)


# ---------- разбор источников ----------
def debian_records(releases=("bookworm",)):
    with (FIX / "debian.json").open("rb") as fh:
        return list(parse_tracker(fh, "debian", releases))


def test_debian_tracker():
    recs = {(r.package, r.cve): r for r in debian_records()}
    assert recs[("openssl", "CVE-2023-0464")] == Advisory(
        "debian", "bookworm", "openssl", "CVE-2023-0464", FIXED, "3.0.8-1")
    assert recs[("openssl", "CVE-2099-1111")].status == OPEN
    assert ("openssl", "CVE-2099-2222") not in recs          # undetermined — нет данных
    assert not any(r.cve.startswith("TEMP") for r in recs.values())
    assert recs[("vim", "CVE-2099-3333")].status == NOT_AFFECTED
    both = debian_records(("bookworm", "bullseye"))
    assert {r.release for r in both} == {"bookworm", "bullseye"}
    assert any(r.release == "bullseye" and r.package == "openssh"
               and r.status == NOT_AFFECTED for r in both)        # fixed_version «0»


def test_oval_ubuntu_constant_variable():
    with (FIX / "ubuntu-jammy.xml").open("rb") as fh:
        recs = list(parse_oval(fh, "ubuntu", ["jammy"]))
    got = {(r.package, r.cve, r.fixed_version, r.advisory_id) for r in recs}
    for pkg in ("libssl3", "openssl", "libssl-dev"):
        for cve in ("CVE-2024-0727", "CVE-2023-6129"):
            assert (pkg, cve, "0:3.0.2-0ubuntu1.15", "USN-6669-1") in got
    assert len(recs) == 6                       # тест «jammy установлен» пропущен


def test_oval_redhat_skips_signature_and_release_tests():
    with (FIX / "rhel-9.xml").open("rb") as fh:
        recs = list(parse_oval(fh, "rhel", ["9"]))
    ssl = {(r.package, r.cve, r.fixed_version) for r in recs if r.package == "openssl-libs"}
    assert ssl == {("openssl-libs", "CVE-2023-0464", "1:3.0.7-6.el9_2"),
                   ("openssl-libs", "CVE-2023-0465", "1:3.0.7-6.el9_2")}
    assert not any(r.package == "redhat-release" for r in recs)
    node = sorted(r.fixed_version for r in recs if r.package == "nodejs")
    assert node[0].startswith("1:18.") and node[1].startswith("1:20.")
    assert {r.advisory_id for r in recs} == {"RHSA-2023:2523", "RHSA-2024:0001"}
    with pytest.raises(ValueError):
        list(parse_oval((FIX / "rhel-9.xml").open("rb"), "rhel", ["8", "9"]))


def test_release_mapping():
    assert host_release("debian", "12", "bookworm")[1] == "bookworm"
    assert host_release("debian", "11", None)[1] == "bullseye"
    assert host_release("ubuntu", "22.04", None)[1] == "jammy"
    spec, rel = host_release("rocky", "9.3", None)
    assert spec.family == "rhel" and rel == "9"
    assert host_release("alt", "10.1", None)[1] == "p10"
    assert host_release("astra", "1.7_x86-64", None)[1] == "1.7"
    assert host_release("redos", "7.3", None)[1] == "7.3"
    assert host_release("redos", "8.0", None)[1] == "8"
    assert host_release("alpine", "3.19", None) is None
    assert host_release("linux", None, None) is None


# ---------- решение ----------
def test_decide():
    rows = [Advisory("debian", "bookworm", "openssl", "CVE-1", FIXED, "3.0.13-1~deb12u1"),
            Advisory("debian", "bookworm", "openssl", "CVE-2", OPEN),
            Advisory("debian", "bookworm", "openssl", "CVE-3", NOT_AFFECTED)]
    kw = {"package": "libssl3", "manager": "dpkg"}
    assert decide(rows, "CVE-1", installed="3.0.13-1~deb12u1", **kw).verdict is Verdict.FIXED
    assert decide(rows, "CVE-1", installed="3.0.14-1~deb12u2", **kw).verdict is Verdict.FIXED
    d = decide(rows, "CVE-1", installed="3.0.11-1~deb12u2", **kw)
    assert d.verdict is Verdict.VULNERABLE and d.advisory.fixed_version == "3.0.13-1~deb12u1"
    assert decide(rows, "CVE-2", installed="9", **kw).verdict is Verdict.VULNERABLE
    assert decide(rows, "CVE-3", installed="1", **kw).verdict is Verdict.NOT_AFFECTED
    assert decide(rows, "CVE-4", installed="1", **kw).verdict is Verdict.NO_DATA


def test_decide_module_streams_and_conservative_max():
    with (FIX / "rhel-9.xml").open("rb") as fh:
        node = [r for r in parse_oval(fh, "rhel", ["9"]) if r.package == "nodejs"]
    kw = {"package": "nodejs", "manager": "rpm"}
    # поток 18 обновлён — исправлено, хотя исправление потока 20 выше
    assert decide(node, "CVE-2023-46809", installed="1:18.19.1-1.module+el9.3.0+21388+e5a0e3ec",
                  **kw).verdict is Verdict.FIXED
    assert decide(node, "CVE-2023-46809", installed="1:20.10.0-1.module+el9.3.0+1+abc",
                  **kw).verdict is Verdict.VULNERABLE
    # два бюллетеня одной ветки — сравниваем с наибольшей версией
    rows = [Advisory("rhel", "9", "x", "CVE-1", FIXED, "1.0-1.el9"),
            Advisory("rhel", "9", "x", "CVE-1", FIXED, "1.0-3.el9")]
    assert decide(rows, "CVE-1", package="x", installed="1.0-2.el9",
                  manager="rpm").verdict is Verdict.VULNERABLE


def test_combine():
    def d(v):
        return type("D", (), {"verdict": v, "closed": v in (Verdict.FIXED,
                                                              Verdict.NOT_AFFECTED)})()
    assert combine([]) is Verdict.NO_DATA
    assert combine([d(Verdict.FIXED), d(Verdict.VULNERABLE)]) is Verdict.VULNERABLE
    assert combine([d(Verdict.FIXED), d(Verdict.NOT_AFFECTED)]) is Verdict.FIXED
    assert combine([d(Verdict.NOT_AFFECTED)]) is Verdict.NOT_AFFECTED
    assert combine([d(Verdict.FIXED), d(Verdict.NO_DATA)]) is Verdict.NO_DATA


# ---------- хранилище и загрузка ----------
def sqlite_store() -> SqlAdvisoryStore:
    engine = create_engine("sqlite://", poolclass=StaticPool,
                           connect_args={"check_same_thread": False})
    store = SqlAdvisoryStore(engine, batch_size=3)
    store.create_schema()
    return store


def test_sql_store_replace_and_lookup():
    store = sqlite_store()
    assert store.replace_release("debian", "bookworm", debian_records()) == 6
    assert store.releases() == {("debian", "bookworm")}
    got = store.for_packages("debian", "bookworm", ["openssl", "nope"])
    assert set(got) == {"openssl"} and len(got["openssl"]) == 3
    # повторная загрузка заменяет данные выпуска, а не дублирует
    store.replace_release("debian", "bookworm", debian_records()[:2])
    assert sum(len(v) for v in store.for_packages(
        "debian", "bookworm", ["openssl", "openssh", "glibc", "vim"]).values()) == 2
    cached = CachingAdvisoryStore(store)
    assert cached.for_packages("debian", "bookworm", ["openssl"]) == \
        cached.for_packages("debian", "bookworm", ["openssl"])
    with pytest.raises(TypeError):
        cached.replace_release("debian", "bookworm", [])


def test_parse_targets():
    assert parse_targets("debian:bookworm, rhel:9;astra:1.7") == [
        ("debian", "bookworm"), ("rhel", "9"), ("astra", "1.7")]
    with pytest.raises(AdvisoryError):
        parse_targets("debian")
    with pytest.raises(AdvisoryError):
        parse_targets("gentoo:1")


def test_sync_local_dir_compressed_and_download(tmp_path):
    (tmp_path / "debian.json.gz").write_bytes(gzip.compress((FIX / "debian.json").read_bytes()))
    (tmp_path / "ubuntu-jammy.xml.bz2").write_bytes(
        bz2.compress((FIX / "ubuntu-jammy.xml").read_bytes()))
    with zipfile.ZipFile(tmp_path / "alt.zip", "w") as zf:    # ALT отдаёт zip
        zf.write(FIX / "rhel-9.xml", "p10/oval.xml")
    fetched = []

    def fetch(url, dest):
        fetched.append(url)
        dest.write_bytes((FIX / "rhel-9.xml").read_bytes())

    store = InMemoryAdvisoryStore()
    results, fp = sync_releases(
        store, parse_targets("debian:bookworm,debian:bullseye,ubuntu:jammy,rhel:9,"
                             "alt:p10,astra:1.7"),
        directory=tmp_path, urls={}, fetch=fetch)
    by = {(r.family, r.release): r for r in results}
    assert by[("debian", "bookworm")].count == 6 and by[("debian", "bullseye")].count == 2
    assert by[("ubuntu", "jammy")].count == 6
    assert by[("alt", "p10")].count == 4 and by[("alt", "p10")].source == "alt.zip"
    assert by[("rhel", "9")].count == 4
    assert fetched == [("https://security.access.redhat.com/data/oval/v2/RHEL9/"
                        "rhel-9.oval.xml.bz2")]
    assert "ADVISORY_URL_ASTRA" in by[("astra", "1.7")].error    # нет источника
    assert fp and ("astra", "1.7") not in store.releases()


def test_sync_error_of_one_release_does_not_stop_others(tmp_path):
    (tmp_path / "ubuntu-jammy.xml").write_text("<not-closed")
    (tmp_path / "debian.json").write_bytes((FIX / "debian.json").read_bytes())
    results, _ = sync_releases(InMemoryAdvisoryStore(),
                               parse_targets("ubuntu:jammy,debian:bookworm"),
                               directory=tmp_path, urls={})
    by = {(r.family, r.release): r for r in results}
    assert by[("ubuntu", "jammy")].error and by[("debian", "bookworm")].count == 6


def test_feed_source_registered(tmp_path, monkeypatch):
    from scanner.core.config import settings
    from scanner.feeds.sources import FeedContext, FeedError, load_advisories

    assert "advisories" in SOURCES and SOURCES["advisories"].loader is load_advisories
    (tmp_path / "debian.json").write_bytes((FIX / "debian.json").read_bytes())
    monkeypatch.setattr(settings, "advisory_dir", str(tmp_path))
    monkeypatch.setattr(settings, "advisory_releases", "debian:bookworm,astra:1.7")
    store = sqlite_store()
    ctx = FeedContext(engine=store.engine, audit=Audit(), now=None)  # type: ignore[arg-type]
    res = load_advisories(ctx)
    assert res.count == 6 and "debian:bookworm — 6" in res.message
    assert "astra:1.7 — ошибка" in res.message
    monkeypatch.setattr(settings, "advisory_releases", "astra:1.7")
    with pytest.raises(FeedError):
        load_advisories(ctx)


# ---------- инвентаризация: решение по находкам ----------
def dpkg_host(os_release: str) -> str:
    return f"""@@os-release
{os_release}
@@dpkg
install ok installed\topenssh-server\t1:9.2p1-2+deb12u3\tamd64\topenssh\t1:9.2p1-2+deb12u3
install ok installed\tlibssl3\t3.0.11-1~deb12u2\tamd64\topenssl\t3.0.11-1~deb12u2
install ok installed\topenssl\t3.0.11-1~deb12u2\tamd64\t\t
install ok installed\tlibc6\t2.36-9+deb12u4\tamd64\tglibc\t2.36-9+deb12u4
install ok installed\tvim\t2:9.0.1378-2\tamd64\t\t
install ok installed\tlinux-image-6.1.0-18-amd64\t6.1.76-1\tamd64\tlinux-signed-amd64\t6.1.76+1
@@end
"""


DEBIAN_12 = 'PRETTY_NAME="Debian GNU/Linux 12 (bookworm)"\nVERSION_ID="12"\n' \
            'VERSION_CODENAME=bookworm\nID=debian'
ASTRA_17 = 'PRETTY_NAME="Astra Linux"\nVERSION_ID=1.7_x86-64\nID=astra\nID_LIKE=debian'


def store_with_bdu_0727():
    store = reference_store()
    store.upsert_bdu([BduRecord(
        bdu_id="BDU:2024-00727", title="Уязвимость OpenSSL (PKCS12)",
        versions="от 3.0.0 до 3.0.13 (OpenSSL)", cve_ids=["CVE-2024-0727"],
        severity_text="Средний уровень опасности (базовая оценка CVSS 3.1 "
                      "составляет 5,5)")])
    return store


def run_host(output: str, advisories):
    audit = Audit()
    mod = AuthInventoryModule(matcher=VulnMatcher(store_with_bdu_0727()),
                              connector=lambda h, c, o: FakeShell(output),
                              sleep=lambda s: None, advisories=advisories)
    findings = mod.run(ctx_for(["10.0.0.5"], [cred(1)], audit))
    return {f.vuln_id: f for f in findings}, audit


def test_parse_inventory_reads_source_packages():
    inv = parse_inventory(dpkg_host(DEBIAN_12), "10.0.0.5")
    p = {x.name: x for x in inv.packages}
    assert p["libssl3"].source == "openssl" and p["libssl3"].source_version is None
    assert p["openssl"].source is None                      # исходный = бинарный
    assert p["linux-image-6.1.0-18-amd64"].source_version == "6.1.76+1"
    assert inv.os_codename == "bookworm"
    rpm = parse_inventory("@@os-release\nID=rocky\nVERSION_ID=9.3\n@@rpm\n"
                          "openssl-libs\t1:3.0.7-27.el9\tx86_64\topenssl-3.0.7-27.el9.src.rpm\n"
                          "bash\t(none):5.1.8-6.el9\tx86_64\tbash-5.1.8-6.el9.src.rpm\n@@end\n",
                          "10.0.0.6")
    assert [(x.name, x.source) for x in rpm.packages] == [("openssl-libs", "openssl"),
                                                          ("bash", None)]


def test_backported_package_gives_no_finding_and_lower_one_does():
    before, _ = run_host(dpkg_host(DEBIAN_12), None)
    # без бюллетеней — как раньше: regreSSHion и CVE-2023-0464 по версии апстрима
    assert {"CVE-2024-6387", "CVE-2023-0464", "CVE-2024-0727"} <= set(before)
    assert BACKPORT_CAVEAT in before["CVE-2024-6387"].evidence

    adv = InMemoryAdvisoryStore(debian_records())
    found, audit = run_host(dpkg_host(DEBIAN_12), adv)
    # бэкпорт: 1:9.2p1-2+deb12u3 = исправленной версии — находки нет
    assert "CVE-2024-6387" not in found
    # 3.0.11 ≥ 3.0.8-1 — CVE-2023-0464 закрыта в bookworm
    assert "CVE-2023-0464" not in found
    # ниже исправленной — находка остаётся, с БДУ и версией исправления
    f = found["CVE-2024-0727"]
    assert f.bdu_ids == ["BDU:2024-00727"]
    assert "3.0.13-1~deb12u1" in f.evidence and "3.0.11-1~deb12u2" in f.evidence
    assert BACKPORT_CAVEAT not in f.evidence
    # БДУ без CVE — сверить нельзя: остаётся с оговоркой
    glibc = found["BDU:2024-11111"]
    assert BACKPORT_CAVEAT in glibc.evidence and "Нет данных вендора" in glibc.evidence
    # открытая (unfixed) CVE без совпадения по апстриму новую находку не создаёт
    assert "CVE-2099-1111" not in found
    s = found["INFO:auth-inventory"].evidence
    assert "Debian bookworm" in s and "закрыто бэкпортом / не затронуто — 2" in s
    rec = next(r for r in audit.records if r["action"] == "auth_inventory_backport")
    assert rec["result"] == "ok" and set(rec["details"]["closed_ids"]) == {
        "CVE-2024-6387", "CVE-2023-0464"}


def test_advisory_adds_finding_missed_by_upstream_matching():
    recs = [*debian_records(),
            Advisory("debian", "bookworm", "glibc", "CVE-2099-7777", FIXED,
                     "2.36-9+deb12u7", "DSA-9999-1")]
    found, _ = run_host(dpkg_host(DEBIAN_12), InMemoryAdvisoryStore(recs))
    f = found["CVE-2099-7777"]
    assert f.port is None and f.module == "auth_inventory"
    assert "libc6" in f.title and "DSA-9999-1" in f.evidence
    assert "2.36-9+deb12u7" in f.evidence
    assert f.severity.value == "medium" and "принят средний" in f.evidence
    # CVE-2023-4911 исправлена в deb12u3, установлена deb12u4 — находки нет
    assert "CVE-2023-4911" not in found
    # ядро по бюллетеню не сопоставляется
    kernel = [Advisory("debian", "bookworm", "linux-signed-amd64", "CVE-2099-8888",
                       FIXED, "6.1.90+1")]
    found2, _ = run_host(dpkg_host(DEBIAN_12), InMemoryAdvisoryStore([*recs, *kernel]))
    assert "CVE-2099-8888" not in found2


def test_no_vendor_data_behaves_as_before_with_caveat():
    adv = InMemoryAdvisoryStore(debian_records())         # Astra не загружена
    found, audit = run_host(dpkg_host(ASTRA_17), adv)
    f = found["CVE-2024-6387"]
    assert BACKPORT_CAVEAT in f.evidence
    assert "Нет данных вендора: бюллетени Astra Linux 1.7 не загружены" in f.evidence
    assert "CVE-2023-0464" in found and "BDU:2024-04970" in f.bdu_ids
    rec = next(r for r in audit.records if r["action"] == "auth_inventory_backport")
    assert rec["result"] == "no_data"
    # с загруженным файлом Astra решение принимается так же, как для Debian
    astra = [Advisory("astra", "1.7", r.package, r.cve, r.status, r.fixed_version)
             for r in debian_records()]
    found2, _ = run_host(dpkg_host(ASTRA_17), InMemoryAdvisoryStore(astra))
    assert "CVE-2024-6387" not in found2 and "CVE-2024-0727" in found2


def test_rhel_compatible_uses_red_hat_data():
    out = ("@@os-release\nPRETTY_NAME=\"Rocky Linux 9.3\"\nID=rocky\nVERSION_ID=9.3\n@@rpm\n"
           "openssl-libs\t1:3.0.7-5.el9\tx86_64\topenssl-3.0.7-5.el9.src.rpm\n@@end\n")
    with (FIX / "rhel-9.xml").open("rb") as fh:
        adv = InMemoryAdvisoryStore(parse_oval(fh, "rhel", ["9"]))
    found, _ = run_host(out, adv)
    f = found["CVE-2023-0464"]                              # 3.0.7-5 < 3.0.7-6.el9_2
    assert "RHSA-2023:2523" in f.evidence and "(для Rocky Linux)" in f.evidence
    patched = out.replace("1:3.0.7-5.el9", "1:3.0.7-27.el9").replace("5.el9.src", "27.el9.src")
    found2, _ = run_host(patched, adv)
    assert "CVE-2023-0464" not in found2 and "CVE-2023-0465" not in found2


def test_broken_advisory_store_falls_back():
    class Broken:
        def releases(self):
            raise RuntimeError("no table distro_advisory")

    found, audit = run_host(dpkg_host(DEBIAN_12), Broken())
    assert "CVE-2024-6387" in found
    assert any(r["action"] == "auth_inventory_backport" and r["result"] == "error"
               for r in audit.records)


def test_families_registry_is_complete():
    assert set(FAMILIES) == {"debian", "ubuntu", "rhel", "alt", "astra", "redos"}
    assert all(s.manager in ("dpkg", "rpm") for s in FAMILIES.values())
    json.dumps({k: v.default_url for k, v in FAMILIES.items()})
