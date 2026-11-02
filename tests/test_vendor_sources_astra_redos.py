"""Открытые источники OVAL Astra Linux (каталог al-oval) и РЕД ОС (redos.xml)."""
from __future__ import annotations

import json
from pathlib import Path

from scanner.feeds.advisories import FAMILIES
from scanner.feeds.advisories.astra import INDEX, discover, select_files
from scanner.feeds.advisories.redos import map_release, parse_redos
from scanner.feeds.advisories.store import InMemoryAdvisoryStore
from scanner.feeds.advisories.sync import plan, sync_releases

FIX = Path(__file__).parent / "fixtures" / "advisories"


def test_defaults_are_public_vendor_sources():
    assert FAMILIES["redos"].default_url == "https://redos.red-soft.ru/support/secure/redos.xml"
    assert FAMILIES["astra"].default_url.startswith("https://dl.astralinux.ru/artifactory/")
    jobs, missing = plan([("redos", "7.3"), ("redos", "8"), ("astra", "1.7")],
                         directory=None, urls={})
    assert not missing
    redos = next(j for j in jobs if j.spec.family == "redos")
    assert redos.releases == ["7.3", "8"] and len(redos.urls) == 1   # один файл на все
    astra = next(j for j in jobs if j.spec.family == "astra")
    assert astra.index == INDEX and not astra.urls
    # свой адрес оператора — прямой файл, без оглавления
    jobs, _ = plan([("astra", "1.7")], directory=None,
                   urls={"astra": "https://mirror.local/astra-{release}.xml"})
    assert jobs[0].urls == ("https://mirror.local/astra-1.7.xml",) and jobs[0].index is None


def test_redos_single_file_split_by_release():
    with (FIX / "redos.xml").open("rb") as fh:
        recs = list(parse_redos(fh, "redos", ["7.3", "8"]))
    by = {(r.release, r.package, r.cve): r.fixed_version for r in recs}
    assert by[("7.3", "openssl-libs", "CVE-2024-0727")] == "1:1.1.1w-3.el7"     # platform
    assert by[("8", "openssl-libs", "CVE-2024-0727")] == "1:3.0.13-1.red80"    # комментарий
    assert by[("8", "curl", "CVE-2024-2398")] == "0:8.7.1-1.red80"             # метка сборки
    assert ("7.3", "curl", "CVE-2024-2398") not in by
    assert ("8", "openssl-libs", "CVE-2024-0727") in by and len(recs) == 3
    assert map_release(["7.3"], [], "1.0-1") == ["7.3"]          # не определился — все
    assert map_release(["7.3", "8"], ["RED OS 7"], "x") == ["7.3"]


def test_redos_sync_from_vendor_url():
    fetched = []

    def fetch(url, dest):
        fetched.append(url)
        dest.write_bytes((FIX / "redos.xml").read_bytes())

    store = InMemoryAdvisoryStore()
    results, _ = sync_releases(store, [("redos", "7.3"), ("redos", "8")], directory=None,
                               urls={}, fetch=fetch)
    assert fetched == ["https://redos.red-soft.ru/support/secure/redos.xml"]
    by = {r.release: r for r in results}
    assert by["7.3"].count == 1 and by["8"].count == 2
    # выпуск без записей в непустом файле не затирается пустотой
    results, _ = sync_releases(store, [("redos", "7.3"), ("redos", "9")], directory=None,
                               urls={}, fetch=fetch)
    by = {r.release: r for r in results}
    assert by["9"].error and "прежние данные" in by["9"].error


def test_astra_discovery_from_artifactory_listing():
    listing = {"files": [{"uri": "/se/1.7/alse-1.7.5.xml"}, {"uri": "/se/1.7/alse-1.7.6.xml"},
                         {"uri": "/se/1.7/readme.txt"}, {"uri": "/se/1.8/alse-1.8.1.xml.bz2"},
                         {"uri": "/se/1.70/x.xml"}]}
    assert select_files([f["uri"].lstrip("/") for f in listing["files"]], "1.7") == [
        "se/1.7/alse-1.7.5.xml", "se/1.7/alse-1.7.6.xml"]
    # файл ровно на выпуск важнее файлов обновлений
    assert select_files(["oval/astra-1.7.xml", "oval/astra-1.7.6.xml"], "1.7") == [
        "oval/astra-1.7.xml"]
    urls = discover("1.8", lambda u: json.dumps(listing).encode())
    assert urls == ["https://dl.astralinux.ru/artifactory/al-oval/se/1.8/alse-1.8.1.xml.bz2"]
    html = b'<a href="../">..</a><a href="astra-1.7.xml">astra-1.7.xml</a>'
    assert discover("1.7", lambda u: html) == [
        "https://dl.astralinux.ru/artifactory/al-oval/astra-1.7.xml"]


def test_astra_sync_through_index():
    oval = (FIX / "ubuntu-jammy.xml").read_bytes()       # dpkginfo OVAL как у Astra
    listing = json.dumps({"files": [{"uri": "/astra-1.7.xml"}]}).encode()
    fetched = []

    def fetch(url, dest):
        fetched.append(url)
        dest.write_bytes(listing if url == INDEX else oval)

    store = InMemoryAdvisoryStore()
    results, _ = sync_releases(store, [("astra", "1.7")], directory=None, urls={},
                               fetch=fetch)
    assert results[0].error is None and results[0].count > 0
    assert fetched == [INDEX, "https://dl.astralinux.ru/artifactory/al-oval/astra-1.7.xml"]
    assert ("astra", "1.7") in store.releases()
