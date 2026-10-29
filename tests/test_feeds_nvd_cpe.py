"""NVD-загрузчик, разбор CPE/версий, поле «Версия ПО» БДУ, шкала severity."""
import httpx
import pytest

from scanner.core.models import Severity
from scanner.feeds.bdu_fstec import parse_bdu_versions
from scanner.feeds.cpe import clean_version, compare_versions, parse_cpe, service_cpe
from scanner.feeds.nvd import NvdFeed, parse_cve_item
from scanner.feeds.severity import (
    bdu_best_score,
    severity_from_bdu_text,
    severity_from_cvss,
)
from scanner.feeds.store import InMemoryReferenceStore

# ---------- версии и CPE ----------


@pytest.mark.parametrize("a,b,expected", [
    ("2.4.49", "2.4.51", -1),
    ("2.4.10", "2.4.9", 1),
    ("7.4p1", "7.4", 1),
    ("7.4p1", "7.5", -1),
    ("7.4.1", "7.4p1", 1),
    ("2.4.0rc1", "2.4.0", -1),
    ("1.1.1k", "1.1.1j", 1),
    ("1.18.0", "1.18.0", 0),
])
def test_compare_versions(a, b, expected):
    assert compare_versions(a, b) == expected


def test_parse_cpe_22_and_23():
    c22 = parse_cpe("cpe:/a:apache:http_server:2.4.49")
    assert (c22.vendor, c22.product, c22.version) == ("apache", "http_server", "2.4.49")
    c23 = parse_cpe(r"cpe:2.3:a:openbsd:openssh:7.4:p1:*:*:*:*:*:*")
    assert c23.full_version == "7.4p1"
    esc = parse_cpe(r"cpe:2.3:a:foo:bar\:baz:1.0:*:*:*:*:*:*:*")
    assert esc.product == "bar:baz"
    assert parse_cpe("not-a-cpe") is None


def test_service_cpe_from_banner():
    assert clean_version("8.2p1 Ubuntu 4ubuntu0.5") == "8.2p1"
    assert clean_version("unknown") is None
    c = service_cpe(None, "Apache httpd", "2.4.49")
    assert (c.vendor, c.product, c.version) == ("apache", "http_server", "2.4.49")
    c = service_cpe("cpe:/a:openbsd:openssh", "OpenSSH", "7.4p1 Debian")
    assert c.version == "7.4p1"           # версия из баннера, если в CPE её нет
    c = service_cpe(None, "Some Custom Daemon", "1.0")
    assert (c.vendor, c.product) == ("*", "some_custom_daemon")


# ---------- поле «Версия ПО» БДУ ----------

def test_parse_bdu_versions():
    specs = parse_bdu_versions(
        "от 2.4.0 до 2.4.51 включительно (HTTP Server), до 7.7 (OpenSSH), "
        "1.02b11 (DSR-500), - (Альт 8 СП (запись в едином реестре российских программ №4305))")
    assert [s.software for s in specs] == [
        "HTTP Server", "OpenSSH", "DSR-500",
        "Альт 8 СП (запись в едином реестре российских программ №4305)"]
    assert (specs[0].start, specs[0].end, specs[0].end_inclusive) == ("2.4.0", "2.4.51", True)
    assert (specs[1].end, specs[1].end_inclusive) == ("7.7", False)
    assert specs[2].exact == "1.02b11"
    assert specs[3].unknown


def test_parse_bdu_versions_joins_range_split_in_two_items():
    # так в реальной выгрузке (BDU:2019-02100): границы — отдельными позициями
    specs = parse_bdu_versions("от 7.62.0 (Libcurl), до 7.64.1 включительно (Libcurl), "
                               "от 1.0 (Other), до 2.0 (Libcurl)")
    assert [(s.software, s.start, s.end, s.end_inclusive) for s in specs] == [
        ("Libcurl", "7.62.0", "7.64.1", True), ("Other", "1.0", None, False),
        ("Libcurl", None, "2.0", False)]


# ---------- severity ----------

def test_severity_scale():
    assert severity_from_cvss(9.8) == Severity.CRITICAL
    assert severity_from_cvss(7.0) == Severity.HIGH
    assert severity_from_cvss(5.3) == Severity.MEDIUM
    assert severity_from_cvss(0.1) == Severity.LOW
    assert severity_from_cvss(0.0) == Severity.INFO
    assert severity_from_cvss(None) is None


def test_bdu_text_prefers_newest_cvss():
    text = ("Высокий уровень опасности (базовая оценка CVSS 2.0 составляет 7,5)\n"
            "Критический уровень опасности (базовая оценка CVSS 3.0 составляет 9,8)")
    assert bdu_best_score(text) == 9.8
    assert severity_from_bdu_text(text) == Severity.CRITICAL
    assert severity_from_bdu_text("Низкий уровень опасности") == Severity.LOW
    assert severity_from_bdu_text("Нет опасности") == Severity.INFO


# ---------- NVD ----------

ITEM = {"cve": {
    "id": "CVE-2021-41773",
    "vulnStatus": "Analyzed",
    "lastModified": "2024-11-21T06:27:01.000",
    "descriptions": [{"lang": "es", "value": "…"},
                     {"lang": "en", "value": "Path traversal in Apache HTTP Server 2.4.49"}],
    "metrics": {
        "cvssMetricV31": [
            {"type": "Secondary", "cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL",
                                               "vectorString": "CVSS:3.1/sec"}},
            {"type": "Primary", "cvssData": {"baseScore": 7.5, "baseSeverity": "HIGH",
                                             "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N"}}],
        "cvssMetricV2": [{"type": "Primary", "cvssData": {"baseScore": 4.3}}]},
    "references": [{"url": "https://httpd.apache.org/security/vulnerabilities_24.html"}],
    "configurations": [{"operator": "AND", "nodes": [
        {"operator": "OR", "cpeMatch": [
            {"vulnerable": True, "criteria": "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"}]},
        {"operator": "OR", "cpeMatch": [
            {"vulnerable": False, "criteria": "cpe:2.3:o:fedoraproject:fedora:34:*:*:*:*:*:*:*"}]},
    ]}],
}}


def test_parse_cve_item():
    rec = parse_cve_item(ITEM)
    assert rec.cve_id == "CVE-2021-41773"
    assert (rec.cvss_v3, rec.severity) == (7.5, "HIGH")   # Primary-оценка NVD
    assert rec.summary.startswith("Path traversal")
    assert rec.cpe == ["cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"]
    assert len(rec.cpe_matches) == 1                     # платформа (vulnerable=false) — нет
    assert rec.updated_at.year == 2024


def test_rejected_cve_skipped():
    assert parse_cve_item({"cve": {"id": "CVE-2000-0001", "vulnStatus": "Rejected"}}) is None


class _Audit:
    def __init__(self):
        self.events = []

    def record(self, **kw):
        self.events.append(kw)


def test_nvd_api_pagination_rate_limit_and_audit():
    pages = []

    def handler(request: httpx.Request) -> httpx.Response:
        start = int(request.url.params["startIndex"])
        pages.append((start, request.headers.get("apiKey")))
        items = [ITEM] if start == 0 else [
            {"cve": {**ITEM["cve"], "id": "CVE-2021-42013"}}]
        return httpx.Response(200, json={"totalResults": 2, "resultsPerPage": 1,
                                         "startIndex": start, "vulnerabilities": items})

    sleeps, audit = [], _Audit()
    feed = NvdFeed("secret", client=httpx.Client(transport=httpx.MockTransport(handler)),
                   audit=audit, sleep=sleeps.append)
    store = InMemoryReferenceStore()
    assert feed.sync(store) == 2
    assert pages == [(0, "secret"), (1, "secret")]
    assert store.get_nvd("CVE-2021-42013") is not None
    assert [e["action"] for e in audit.events] == ["feed_fetch", "feed_fetch"]
    assert sleeps and all(0 < s <= feed.min_interval for s in sleeps)


def test_nvd_offline_files(tmp_path):
    import gzip
    import json
    path = tmp_path / "nvdcve-2.0-2021.json.gz"
    with gzip.open(path, "wt", encoding="utf-8") as fh:
        json.dump({"vulnerabilities": [ITEM]}, fh)
    store = InMemoryReferenceStore()
    feed = NvdFeed()
    assert feed.sync(store, records=feed.iter_files([path])) == 1
    assert store.cpe_matches("http_server")[0].cve_id == "CVE-2021-41773"
