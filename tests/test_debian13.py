"""Debian 13 (trixie): сценарии из полевых тестов на Kali/Debian 13.

* обновлённый хост + загруженные бюллетени trixie — CVE, исправленные
  бэкпортом (``+deb13uN``), не активны; ниже исправленной — остаётся;
* бюллетеней trixie нет — предупреждение «Бэкпорты не учтены» в прогоне и
  одно действие «загрузить debian:trixie»;
* баннер OpenSSH с хоста, где пакеты проверены по SSH, не дублирует находку
  и не выглядит подтверждённой;
* сравнение версий dpkg: эпоха, ревизия, ``deb13uX``, ``~``;
* CVE ↔ БДУ: несколько БДУ на одну CVE сливаются в одну находку.
"""
from __future__ import annotations

import io
import json

import pytest

from scanner.core.confidence import apply_confidence, supersede_banner, warnings_for
from scanner.core.models import Finding, FindingType, Severity
from scanner.feeds import vercmp
from scanner.feeds.advisories.assess import Verdict, decide
from scanner.feeds.advisories.base import FIXED, Advisory
from scanner.feeds.advisories.debian import parse_tracker, release_of
from scanner.feeds.advisories.store import InMemoryAdvisoryStore
from scanner.feeds.bdu_fstec import BduRecord
from scanner.feeds.matcher import BACKPORT_CAVEAT, VulnMatcher
from scanner.modules.auth_inventory import AuthInventoryModule
from tests.test_advisories import Audit
from tests.test_auth_inventory import FakeShell, cred, ctx_for, reference_store


@pytest.mark.parametrize("a,op,b", [
    ("1:10.0p1-7+deb13u1", ">", "1:10.0p1-7"),
    ("1:10.0p1-7+deb13u10", ">", "1:10.0p1-7+deb13u9"),       # не строковое сравнение
    ("1:10.0p1-7+deb13u1", "<", "1:10.0p1-7+deb13u2"),
    ("1:9.2p1-2", ">", "10.0p1-7"),                           # эпоха важнее апстрима
    ("3.5.1-1~deb13u1", "<", "3.5.1-1"),                      # ~ раньше всего
    ("3.5.1-1~deb13u1", ">", "3.5.0-4"),
    ("2.41-12+deb13u1", ">", "2.41-12"),
    ("0:2.41-12", "=", "2.41-12"),                            # нулевая эпоха = без эпохи
    ("6.12.48-1", ">", "6.12.41-1"),
    ("1.2.3", "<", "1.2.3-1"),                                # нет ревизии < ревизия
])
def test_dpkg_compare_debian13(a, op, b):
    r = vercmp.dpkg_compare(a, b)
    assert {"<": r < 0, ">": r > 0, "=": r == 0}[op], (a, op, b, r)


def test_release_of_debian13():
    assert release_of("13", None) == "trixie"
    assert release_of("13", "trixie") == "trixie"
    assert release_of(None, "Trixie") == "trixie"


TRACKER = {
    "openssh": {
        "CVE-2099-0101": {"releases": {
            "trixie": {"status": "resolved", "fixed_version": "1:10.0p1-7+deb13u1"},
            "bookworm": {"status": "resolved", "fixed_version": "1:9.2p1-2+deb12u7"}}},
        "CVE-2099-0102": {"releases": {
            "trixie": {"status": "resolved", "fixed_version": "1:10.0p1-7+deb13u2"}}},
        "CVE-2099-0103": {"releases": {
            "trixie": {"status": "resolved", "fixed_version": "0"}}},     # не затронут
        "CVE-2099-0104": {"releases": {
            "trixie": {"status": "undetermined"}}},                      # нет данных
    },
}


def trixie_records():
    return list(parse_tracker(io.BytesIO(json.dumps(TRACKER).encode()), "debian",
                              ["trixie"]))


def test_tracker_statuses_for_trixie():
    recs = {r.cve: r for r in trixie_records()}
    assert recs["CVE-2099-0101"].release == "trixie"
    assert recs["CVE-2099-0101"].fixed_version == "1:10.0p1-7+deb13u1"
    assert recs["CVE-2099-0103"].status == "not_affected"
    assert "CVE-2099-0104" not in recs
    inst = "1:10.0p1-7+deb13u1"
    verdicts = {c: decide(trixie_records(), c, package="openssh-server", installed=inst,
                          manager="dpkg").verdict
                for c in ("CVE-2099-0101", "CVE-2099-0102", "CVE-2099-0103",
                          "CVE-2099-0104")}
    assert verdicts == {"CVE-2099-0101": Verdict.FIXED,
                        "CVE-2099-0102": Verdict.VULNERABLE,
                        "CVE-2099-0103": Verdict.NOT_AFFECTED,
                        "CVE-2099-0104": Verdict.NO_DATA}


DEBIAN_13 = ('PRETTY_NAME="Debian GNU/Linux 13 (trixie)"\nVERSION_ID="13"\n'
             'VERSION_CODENAME=trixie\nID=debian')
TRIXIE_HOST = f"""@@os-release
{DEBIAN_13}
@@dpkg
install ok installed\topenssh-server\t1:10.0p1-7+deb13u1\tamd64\topenssh\t1:10.0p1-7+deb13u1
install ok installed\topenssh-client\t1:10.0p1-7+deb13u1\tamd64\topenssh\t1:10.0p1-7+deb13u1
@@end
"""


def store_trixie():
    store = reference_store()
    store.upsert_bdu([
        BduRecord(bdu_id="BDU:2099-00101", title="Уязвимость OpenSSH (A)",
                  versions="от 9.0 до 10.1 (OpenSSH)", cve_ids=["CVE-2099-0101"],
                  severity_text="Высокий уровень опасности (базовая оценка CVSS 3.1 "
                                "составляет 7,5)"),
        BduRecord(bdu_id="BDU:2099-00102", title="Уязвимость OpenSSH (B)",
                  versions="от 9.0 до 10.1 (OpenSSH)", cve_ids=["CVE-2099-0102"],
                  severity_text="Средний уровень опасности (базовая оценка CVSS 3.1 "
                                "составляет 5,3)"),
        # вторая запись БДУ на ту же CVE — должна слиться в ту же находку
        BduRecord(bdu_id="BDU:2099-00199", title="Уязвимость sshd (B, дубль)",
                  versions="от 9.0 до 10.1 (OpenSSH)", cve_ids=["CVE-2099-0102"],
                  severity_text="Средний уровень опасности (базовая оценка CVSS 3.1 "
                                "составляет 5,3)"),
    ])
    return store


def run_trixie(advisories):
    audit = Audit()
    mod = AuthInventoryModule(matcher=VulnMatcher(store_trixie()),
                              connector=lambda h, c, o: FakeShell(TRIXIE_HOST),
                              sleep=lambda s: None, advisories=advisories)
    ctx = ctx_for(["10.0.0.13"], [cred(1)], audit)
    findings = mod.run(ctx)
    return {f.vuln_id: f for f in findings if f.vuln_id}, ctx


def test_updated_debian13_with_bulletins_backport_fixed_not_active():
    found, ctx = run_trixie(InMemoryAdvisoryStore(trixie_records()))
    assert "CVE-2099-0101" not in found          # исправлено в deb13u1 = установлено
    f = found["CVE-2099-0102"]                    # исправлено в deb13u2 > deb13u1
    assert "1:10.0p1-7+deb13u2" in f.evidence and BACKPORT_CAVEAT not in f.evidence
    assert f.source == "vendor_advisory" and f.confidence == "high"
    # две БДУ на одну CVE — одна находка с обеими
    assert set(f.bdu_ids) == {"BDU:2099-00102", "BDU:2099-00199"}
    assert sum(1 for x in found.values() if x.vuln_id == "CVE-2099-0102") == 1
    assert not [n for n in ctx.run_notes if n["kind"] == "advisories_missing"]
    assert ctx.coverage.status("10.0.0.13", "auth_inventory") == "completed"
    assert ctx.assessed_cves["10.0.0.13"]["CVE-2099-0101"] == "closed"


def test_debian13_without_bulletins_warns_and_offers_load():
    found, ctx = run_trixie(InMemoryAdvisoryStore([]))
    # без бюллетеней — находки по апстриму остаются, но с оговоркой
    assert BACKPORT_CAVEAT in found["CVE-2099-0101"].evidence
    notes = [n for n in ctx.run_notes if n["kind"] == "advisories_missing"]
    assert notes and notes[0]["family"] == "debian" and notes[0]["release"] == "trixie"
    assert notes[0]["loadable"] is True
    warns = warnings_for(list(found.values()), ctx.run_notes, ctx.coverage)
    w = next(w for w in warns if w["kind"] == "advisories_missing")
    assert "Бэкпорты не учтены" in w["message"] and "debian:trixie" in w["message"]
    assert w["hosts"] == ["10.0.0.13"]


def test_banner_openssh_superseded_by_package_check_on_debian13():
    found, ctx = run_trixie(InMemoryAdvisoryStore(trixie_records()))
    banner = Finding(host="10.0.0.13", port=22, module="vuln", finding_type=FindingType.VULN,
                     title="OpenSSH 10.0p1",
                     severity=Severity.HIGH, vuln_id="CVE-2099-0101",
                     evidence="banner: SSH-2.0-OpenSSH_10.0p1 Debian-7+deb13u1")
    from scanner.core.models import ServiceInfo
    from scanner.modules.vuln import mark_banner
    svc = ServiceInfo(host="10.0.0.13", port=22, protocol="tcp", service="ssh",
                      product="OpenSSH", version="10.0p1 Debian 7+deb13u1")
    mark_banner(banner, svc)
    assert "сборку дистрибутива" in banner.evidence
    assert banner.source == "banner" and banner.confidence == "low"
    keep, dropped = supersede_banner([banner, *found.values()], ctx.assessed_cves)
    assert banner in dropped and banner not in keep          # закрыто по пакетам
    # на хосте без проверки пакетов баннер остаётся, но низкой уверенности
    other = Finding(host="10.0.0.99", port=22, module="vuln", finding_type=FindingType.VULN,
                    title="OpenSSH 10.0p1",
                    severity=Severity.HIGH, vuln_id="CVE-2099-0101", evidence="banner")
    mark_banner(other, svc)
    keep2, _ = supersede_banner([other], ctx.assessed_cves)
    apply_confidence(keep2)
    assert keep2 == [other] and other.confidence == "low"
    w = warnings_for(keep2, [], ctx.coverage)
    assert any(x["kind"] == "banner_only" for x in w)


def test_advisory_store_replaces_release_without_duplicates():
    from tests.test_advisories import sqlite_store
    store = sqlite_store()
    recs = trixie_records()
    store.replace_release("debian", "trixie", recs)
    store.replace_release("debian", "trixie", recs)        # повторная загрузка
    got = store.for_packages("debian", "trixie", ["openssh"])
    rows = got["openssh"]
    assert len(rows) == len(recs)
    assert [a for a in rows if a.cve == "CVE-2099-0101"] == [
        Advisory("debian", "trixie", "openssh", "CVE-2099-0101", FIXED,
                 "1:10.0p1-7+deb13u1")]
