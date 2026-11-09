"""Открытые источники OVAL Astra Linux (каталог al-oval) и РЕД ОС (redos.xml)."""
from __future__ import annotations

import json
from pathlib import Path

from scanner.feeds.advisories import FAMILIES
from scanner.feeds.advisories.astra import INDEX, discover, select_files
from scanner.feeds.advisories.redos import map_release, parse_redos
from scanner.feeds.advisories.store import InMemoryAdvisoryStore
from scanner.feeds.advisories.sync import (
    AdvisoryError,
    check_sources,
    plan,
    sync_releases,
)

FIX = Path(__file__).parent / "fixtures" / "advisories"


def test_defaults_are_public_vendor_sources():
    redos_url = FAMILIES["redos"].default_url
    assert redos_url == ("https://redos.red-soft.ru/support/secure/{release}/redos.xml | "
                         "https://redos.red-soft.ru/support/secure/redos.xml")
    assert FAMILIES["astra"].default_url.startswith("https://dl.astralinux.ru/artifactory/")
    jobs, missing = plan([("redos", "7.3"), ("redos", "8"), ("astra", "1.7")],
                         directory=None, urls={})
    assert not missing
    redos = {j.releases[0]: j for j in jobs if j.spec.family == "redos"}
    # файл выпуска (8 -> 8.0 в адресе), запасной — общий redos.xml
    assert redos["7.3"].urls == ("https://redos.red-soft.ru/support/secure/7.3/redos.xml",)
    assert redos["8"].urls == ("https://redos.red-soft.ru/support/secure/8.0/redos.xml",)
    assert redos["8"].per_release
    assert redos["8"].fallbacks == (
        (("https://redos.red-soft.ru/support/secure/redos.xml",), False),)
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


def test_redos_sync_from_release_file():
    """Файл выпуска относится к нему целиком — даже без платформы/метки сборки."""
    fetched = []

    def fetch(url, dest):
        fetched.append(url)
        dest.write_bytes((FIX / "redos.xml").read_bytes())

    store = InMemoryAdvisoryStore()
    results, _ = sync_releases(store, [("redos", "8")], directory=None, urls={},
                               fetch=fetch)
    assert fetched == ["https://redos.red-soft.ru/support/secure/8.0/redos.xml"]
    assert results[0].error is None and results[0].count == 3
    assert results[0].source == "https://redos.red-soft.ru/support/secure/8.0/redos.xml"


def test_redos_falls_back_to_shared_file():
    """Файла выпуска нет (404) — берётся общий redos.xml и делится по выпускам."""
    fetched = []

    def fetch(url, dest):
        fetched.append(url)
        if url.endswith("/secure/redos.xml"):
            dest.write_bytes((FIX / "redos.xml").read_bytes())
        else:
            raise AdvisoryError(f"не удалось скачать {url}: HTTP 404")

    store = InMemoryAdvisoryStore()
    results, _ = sync_releases(store, [("redos", "7.3"), ("redos", "8")], directory=None,
                               urls={}, fetch=fetch)
    by = {r.release: r for r in results}
    assert by["7.3"].error is None and by["7.3"].count == 1
    assert by["8"].error is None and by["8"].count == 2
    assert by["8"].source == "https://redos.red-soft.ru/support/secure/redos.xml"
    assert "https://redos.red-soft.ru/support/secure/7.3/redos.xml" in fetched
    # выпуск без записей в общем файле не затирается пустотой
    results, _ = sync_releases(store, [("redos", "9")], directory=None, urls={},
                               fetch=fetch)
    assert results[0].error and "прежние данные" in results[0].error


def test_redos_all_sources_fail_reports_each():
    def fetch(url, dest):
        raise AdvisoryError(f"не удалось скачать {url}: HTTP 403 — доступ запрещён")

    results, _ = sync_releases(InMemoryAdvisoryStore(), [("redos", "8")], directory=None,
                               urls={}, fetch=fetch)
    err = results[0].error
    assert "ни один адрес не скачался" in err
    assert "8.0/redos.xml" in err and "secure/redos.xml" in err and "403" in err


def test_html_instead_of_data_keeps_old_records():
    store = InMemoryAdvisoryStore()

    def good(url, dest):
        dest.write_bytes((FIX / "redos.xml").read_bytes())

    sync_releases(store, [("redos", "8")], directory=None, urls={}, fetch=good)
    before = store.releases()

    def page(url, dest):          # «200 OK» со страницей вместо OVAL, но XML-валидной
        dest.write_bytes(b"<?xml version='1.0'?><html><body>Bot check</body></html>")

    results, _ = sync_releases(store, [("redos", "8")], directory=None, urls={}, fetch=page)
    assert results[0].error and "ни одной записи" in results[0].error
    assert store.releases() == before


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


def test_astra_real_layout_and_folder_walk_when_list_api_closed():
    """al-oval/1.8_x86-64/oval-definitions-alse-1.8.xml; API полного списка
    закрыт (403) — файлы находятся обходом папок api/storage."""
    from scanner.feeds.advisories.astra import STORAGE
    root = {"children": [{"uri": "/1.7_x86-64", "folder": True},
                         {"uri": "/1.8_x86-64", "folder": True},
                         {"uri": "/README", "folder": False}]}
    folder = {"children": [{"uri": "/oval-definitions-alse-1.8.xml", "folder": False}]}

    def read(url):
        if url == INDEX:
            raise AdvisoryError("HTTP 403")
        if url == STORAGE:
            return json.dumps(root).encode()
        if url == f"{STORAGE}/1.8_x86-64":
            return json.dumps(folder).encode()
        raise AssertionError(url)

    assert discover("1.8", read) == [
        "https://dl.astralinux.ru/artifactory/al-oval/1.8_x86-64/oval-definitions-alse-1.8.xml"]


def test_astra_html_listing_fallback():
    def read(url):
        if url.endswith("/al-oval/"):
            return b'<a href="../">..</a><a href="1.7_x86-64/">1.7_x86-64/</a>'
        if url.endswith("/al-oval/1.7_x86-64/"):
            return b'<a href="oval-definitions-alse-1.7.xml">x</a>'
        raise AdvisoryError("HTTP 403")

    assert discover("1.7", read) == [
        "https://dl.astralinux.ru/artifactory/al-oval/1.7_x86-64/oval-definitions-alse-1.7.xml"]


def test_check_sources_reports_per_release():
    def probe(url):
        if url.endswith("8.0/redos.xml"):
            return 200, "text/html", b"<!DOCTYPE html><html>blocked"
        if url.endswith("secure/redos.xml"):
            return 404, "text/html", b""
        if url.endswith("7.3/redos.xml"):
            return 200, "application/xml", b"<?xml version='1.0'?><oval_definitions>"
        return 200, "application/x-bzip2", b"BZh91AY"

    def read(url):
        if url == INDEX:
            return json.dumps({"files": [{"uri": "/1.8_x86-64/oval-definitions-alse-1.8.xml"}]
                               }).encode()
        raise AssertionError(url)

    checks = check_sources([("redos", "7.3"), ("redos", "8"), ("astra", "1.8"),
                            ("ubuntu", "jammy"), ("astra", "1.6")],
                           directory=None, urls={}, probe=probe, read=read)
    by = {(c.family, c.release): c for c in checks}
    assert by[("redos", "7.3")].ok
    assert not by[("redos", "8")].ok and "HTML" in by[("redos", "8")].detail
    assert "HTTP 404" in by[("redos", "8")].detail
    assert by[("astra", "1.8")].ok and by[("astra", "1.8")].url.endswith("alse-1.8.xml")
    assert by[("ubuntu", "jammy")].ok
    assert not by[("astra", "1.6")].ok and "нет файла выпуска" in by[("astra", "1.6")].detail
