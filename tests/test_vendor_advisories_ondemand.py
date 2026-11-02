"""Сверка CVE пакетов с бюллетенями вендора в реальном прогоне.

Регресс к жалобе «уязвимости привязаны к Lynis, а не к пакетам»:
  * учётка аудита конфигураций сразу проверяет пакеты (auth_inventory — спутник
    config_audit), даже если движок поиска уязвимостей — «Nuclei»;
  * бюллетени выпуска ОС хоста подгружаются в прогоне (файл оператора — всегда,
    интернет — только с согласия), а плановое обновление их подхватывает;
  * Alpine (secdb, apk) сверяется с учётом ревизий -rN;
  * в сводке хоста видно, сколько уязвимостей привязано к БДУ ФСТЭК.
"""
from __future__ import annotations

import io
import json

from scanner.core.orchestrator import MODULE_ORDER, order_modules, with_companions
from scanner.feeds.advisories import FAMILIES, host_release
from scanner.feeds.advisories.alpine import parse_secdb
from scanner.feeds.advisories.assess import Verdict, decide
from scanner.feeds.advisories.base import FIXED, NOT_AFFECTED, Advisory
from scanner.feeds.advisories.ondemand import (
    NO_CONSENT,
    AdvisoryFetcher,
    local_releases,
    wanted_releases,
)
from scanner.feeds.advisories.store import InMemoryAdvisoryStore
from scanner.feeds.advisories.sync import plan
from scanner.feeds.matcher import VulnMatcher
from scanner.modules.auth_inventory import AuthInventoryModule
from tests.test_advisories import (
    ASTRA_17,
    DEBIAN_12,
    FIX,
    Audit,
    debian_records,
    dpkg_host,
    store_with_bdu_0727,
)
from tests.test_auth_inventory import FakeShell, cred, ctx_for

SECDB = {
    "distroversion": "v3.19", "reponame": "main", "archs": ["x86_64"],
    "packages": [
        {"pkg": {"name": "openssl", "secfixes": {
            "3.1.4-r1": ["CVE-2023-5678"],
            "3.1.4-r5": ["CVE-2024-0727 GHSA-xxxx"],
            "0": ["CVE-2022-9999"]}}},
        {"pkg": {"name": "busybox", "secfixes": {"1.36.1-r15": ["CVE-2023-42363"]}}},
    ]}


def _secdb_bytes(data=SECDB) -> io.BytesIO:
    return io.BytesIO(json.dumps(data).encode())


# ---------- спутник config_audit ----------
def test_config_audit_brings_package_check():
    names = order_modules(with_companions(["discovery", "vuln", "config_audit"]))
    assert names == ["discovery", "vuln", "auth_inventory", "config_audit",
                     "password_policy"]
    # проверка пакетов идёт раньше аудита конфигураций (порядок исполнения)
    assert MODULE_ORDER.index("auth_inventory") < MODULE_ORDER.index("config_audit")


# ---------- Alpine secdb ----------
def test_alpine_secdb_parse_and_decide():
    recs = list(parse_secdb(_secdb_bytes(), "alpine", ["3.19", "3.20"]))
    by = {(r.package, r.cve): r for r in recs}
    assert by[("openssl", "CVE-2023-5678")] == Advisory(
        "alpine", "3.19", "openssl", "CVE-2023-5678", FIXED, "3.1.4-r1")
    assert by[("openssl", "CVE-2024-0727")].fixed_version == "3.1.4-r5"   # мусор отброшен
    assert by[("openssl", "CVE-2022-9999")].status == NOT_AFFECTED
    assert {r.release for r in recs} == {"3.19"}       # distroversion файла
    # ревизия -rN решает: 3.1.4-r3 закрывает r1, но не r5
    d1 = decide(recs, "CVE-2023-5678", package="openssl", installed="3.1.4-r3",
                manager="apk")
    d2 = decide(recs, "CVE-2024-0727", package="openssl", installed="3.1.4-r3",
                manager="apk")
    assert d1.verdict is Verdict.FIXED and d2.verdict is Verdict.VULNERABLE
    assert host_release("alpine", "3.19.1", None)[1] == "3.19"


def test_alpine_main_and_community_are_merged(tmp_path):
    jobs, missing = plan([("alpine", "3.19")], directory=None, urls={})
    assert not missing and jobs[0].urls == (
        "https://secdb.alpinelinux.org/v3.19/main.json",
        "https://secdb.alpinelinux.org/v3.19/community.json")
    community = {"distroversion": "v3.19", "packages": [
        {"pkg": {"name": "nginx", "secfixes": {"1.24.0-r7": ["CVE-2023-44487"]}}}]}
    payload = {"main.json": SECDB, "community.json": community}

    def fetch(url, dest):
        dest.write_bytes(json.dumps(payload[url.rsplit("/", 1)[1]]).encode())

    store = InMemoryAdvisoryStore()
    res = AdvisoryFetcher(store, allow_network=lambda: True, fetch=fetch)(
        [("alpine", "3.19")])
    assert res[0].error is None and res[0].count == 5
    assert set(store.for_packages("alpine", "3.19", {"nginx", "openssl"})) == {
        "nginx", "openssl"}


def test_alpine_host_backport_decision():
    out = ("@@os-release\nPRETTY_NAME=\"Alpine Linux v3.19\"\nID=alpine\n"
           "VERSION_ID=3.19.1\n@@apk\nopenssl-3.1.4-r3\nbusybox-1.36.1-r15\n@@end\n")
    adv = InMemoryAdvisoryStore(parse_secdb(_secdb_bytes(), "alpine", ["3.19"]))
    mod = AuthInventoryModule(matcher=VulnMatcher(store_with_bdu_0727()),
                              connector=lambda h, c, o: FakeShell(out),
                              sleep=lambda s: None, advisories=adv)
    found = {f.vuln_id: f for f in mod.run(ctx_for(["10.0.0.9"], [cred(1)], Audit()))}
    f = found["CVE-2024-0727"]                       # 3.1.4-r3 < 3.1.4-r5
    assert f.bdu_ids == ["BDU:2024-00727"] and "3.1.4-r5" in f.evidence
    assert "CVE-2023-5678" not in found and "CVE-2023-42363" not in found
    assert "Alpine Linux 3.19" in found["INFO:auth-inventory"].evidence


# ---------- подгрузка по требованию ----------
def test_local_and_wanted_releases(tmp_path):
    (tmp_path / "astra-1.7.xml").write_text("<x/>")
    (tmp_path / "redos-7.3.xml.bz2").write_bytes(b"")
    (tmp_path / "debian.json").write_text("{}")            # общий файл — не выпуск
    (tmp_path / "junk-1.txt").write_text("")
    assert local_releases(tmp_path) == {("astra", "1.7"), ("redos", "7.3")}
    store = InMemoryAdvisoryStore([Advisory("alpine", "3.19", "openssl", "CVE-1", FIXED,
                                            "1-r1")])
    got = wanted_releases([("debian", "bookworm")], store, tmp_path)
    assert got == [("debian", "bookworm"), ("alpine", "3.19"), ("astra", "1.7"),
                   ("redos", "7.3")]


def test_fetcher_needs_consent_for_network_but_not_for_local_file(tmp_path):
    (tmp_path / "debian.json").write_bytes((FIX / "debian.json").read_bytes())
    fetched: list[str] = []

    def fetch(url, dest):
        fetched.append(url)
        dest.write_bytes((FIX / "ubuntu-jammy.xml").read_bytes())

    store = InMemoryAdvisoryStore()
    f = AdvisoryFetcher(store, directory=tmp_path, allow_network=lambda: False,
                        fetch=fetch)
    res = {(r.family, r.release): r for r in f([("debian", "bookworm"),
                                               ("ubuntu", "jammy")])}
    assert res[("debian", "bookworm")].error is None           # файл оператора
    assert res[("ubuntu", "jammy")].error == NO_CONSENT and not fetched
    f.allow_network = lambda: True
    res = {(r.family, r.release): r for r in f([("ubuntu", "jammy"), ("astra", "1.7")])}
    assert res[("ubuntu", "jammy")].error is None and fetched
    assert "ADVISORY_URL_ASTRA" in res[("astra", "1.7")].error   # нет открытого источника

    def broken():
        raise RuntimeError("db down")
    f.allow_network = broken                                    # нет ответа = нет согласия
    assert f([("ubuntu", "noble")])[0].error == NO_CONSENT


def _run(output, advisories, fetcher):
    audit = Audit()
    mod = AuthInventoryModule(matcher=VulnMatcher(store_with_bdu_0727()),
                              connector=lambda h, c, o: FakeShell(output),
                              sleep=lambda s: None, advisories=advisories,
                              fetch_advisories=fetcher)
    return {f.vuln_id: f for f in mod.run(ctx_for(["10.0.0.5"], [cred(1)], audit))}, audit


def test_run_fetches_missing_release_and_applies_it():
    store = InMemoryAdvisoryStore()                    # пусто: оператор ничего не грузил
    asked: list[list] = []

    def fetcher(targets):
        asked.append(list(targets))
        store.replace_release("debian", "bookworm", debian_records())
        from scanner.feeds.advisories.sync import ReleaseResult
        return [ReleaseResult("debian", "bookworm", 6, "debian.json")]

    found, audit = _run(dpkg_host(DEBIAN_12), store, fetcher)
    assert asked == [[("debian", "bookworm")]]
    assert "CVE-2024-6387" not in found                # закрыто бэкпортом
    assert found["CVE-2024-0727"].bdu_ids == ["BDU:2024-00727"]
    s = found["INFO:auth-inventory"].evidence
    assert "Debian bookworm" in s and "привязано к БДУ ФСТЭК:" in s
    assert any(r["action"] == "advisory_fetch" and r["result"] == "ok"
               for r in audit.records)
    # выпуск уже загружен — второй прогон ничего не качает
    _run(dpkg_host(DEBIAN_12), store, fetcher)
    assert len(asked) == 1


def test_run_explains_why_vendor_data_is_missing():
    from scanner.feeds.advisories.sync import ReleaseResult
    store = InMemoryAdvisoryStore(debian_records())

    def fetcher(targets):
        return [ReleaseResult(f, r, error="нет источника данных Astra Linux") for f, r
                in targets]

    found, audit = _run(dpkg_host(ASTRA_17), store, fetcher)
    f = found["CVE-2024-6387"]
    assert ("бюллетени Astra Linux 1.7 не загружены (нет источника данных Astra Linux)"
            in f.evidence)
    assert any(r["action"] == "advisory_fetch" and r["result"] == "error"
               for r in audit.records)

    def boom(targets):
        raise OSError("disk full")
    found, _ = _run(dpkg_host(ASTRA_17), store, boom)         # сбой не роняет модуль
    assert "CVE-2024-6387" in found


def test_alpine_registered():
    assert FAMILIES["alpine"].manager == "apk"
    assert "secdb.alpinelinux.org" in FAMILIES["alpine"].default_url


def test_registry_fetcher_follows_operator_consent(sqlite_factory, monkeypatch, tmp_path):
    """auto: интернет — только если включено автообновление бюллетеней."""
    from scanner.core.config import settings
    from scanner.core.db import FeedSync, session_scope
    from scanner.core.orchestrator import _advisory_fetcher
    from scanner.feeds.store import SqlReferenceStore

    engine = sqlite_factory.kw["bind"]
    matcher = VulnMatcher(SqlReferenceStore(engine))
    monkeypatch.setattr(settings, "advisory_dir", str(tmp_path))
    monkeypatch.setattr(settings, "advisory_on_demand", "auto")
    f = _advisory_fetcher(matcher)
    assert f is not None and f.allow_network() is False        # строки ещё нет
    with session_scope(sqlite_factory) as s:
        s.add(FeedSync(source="advisories", kind="weekly", time_of_day="04:30",
                       weekdays=[0], timezone="UTC", enabled=True))
    assert f.allow_network() is True
    monkeypatch.setattr(settings, "advisory_on_demand", "0")
    assert _advisory_fetcher(matcher) is None
    monkeypatch.setattr(settings, "advisory_on_demand", "1")
    assert _advisory_fetcher(matcher).allow_network() is True
    assert _advisory_fetcher(None) is None                       # нет БД — нет подгрузки
