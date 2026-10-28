"""Сопоставление находок с БДУ ФСТЭК и NVD (feeds/matcher.py).

Справочники — синтетические фикстуры в формате реальной выгрузки БДУ и
CVE JSON 2.0 NVD; каждый тест прогоняется на in-memory и на SQLite-хранилище.
"""
import os

import pytest

from scanner.core.models import Finding, FindingType, ServiceInfo, Severity
from scanner.feeds.bdu_fstec import BduFstecFeed, BduRecord
from scanner.feeds.matcher import SRC_BDU_PRODUCT, SRC_CPE, VulnMatcher
from scanner.feeds.nvd import parse_cve_item
from scanner.feeds.store import InMemoryReferenceStore, SqlReferenceStore


def nvd_item(cve_id, score, matches, severity="HIGH"):
    return {"cve": {
        "id": cve_id,
        "lastModified": "2024-11-21T06:27:01.000",
        "descriptions": [{"lang": "en", "value": f"{cve_id} summary"}],
        "metrics": {"cvssMetricV31": [{"type": "Primary", "cvssData": {
            "baseScore": score, "baseSeverity": severity,
            "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"}}]},
        "references": [{"url": f"https://example.org/{cve_id}"}],
        "configurations": [{"nodes": [{"operator": "OR", "negate": False,
                                       "cpeMatch": matches}]}],
    }}


NVD_ITEMS = [
    # Точная версия
    nvd_item("CVE-2021-41773", 7.5, [{"vulnerable": True,
        "criteria": "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"}]),
    # Диапазон версий
    nvd_item("CVE-2021-44790", 9.8, [{"vulnerable": True,
        "criteria": "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*",
        "versionEndIncluding": "2.4.51"}], severity="CRITICAL"),
    # Тот же продукт у другого вендора — не должен совпасть с Apache
    nvd_item("CVE-2099-0001", 5.0, [{"vulnerable": True,
        "criteria": "cpe:2.3:a:oracle:http_server:*:*:*:*:*:*:*:*"}]),
    # OpenSSH: версия 7.4 + update p1
    nvd_item("CVE-2018-15473", 5.3, [{"vulnerable": True,
        "criteria": "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*",
        "versionEndIncluding": "7.7"}], severity="MEDIUM"),
    nvd_item("CVE-2016-0000", 5.0, [{"vulnerable": True,
        "criteria": "cpe:2.3:a:openbsd:openssh:7.4:p2:*:*:*:*:*:*"}]),
]


BDU_RECORDS = [
    BduRecord(bdu_id="BDU:2014-00002", title="Уязвимость маршрутизаторов D-Link DSR",
              vendor="D-Link Corp.", software="DSR-500", versions="1.08b51 (DSR-500)",
              severity_text="Критический уровень опасности (базовая оценка CVSS 2.0 составляет 10)",
              other_ids="CVE-2013-5946, OSVDB ID:100840", cve_ids=["CVE-2013-5946"],
              remediation="Обновить микропрограмму"),
    BduRecord(bdu_id="BDU:2015-00091", title="Ещё одна запись по тому же CVE",
              cve_ids=["CVE-2013-5946"]),
    BduRecord(bdu_id="BDU:2021-04903", title="Уязвимость веб-сервера Apache HTTP Server",
              vendor="Fedora Project, Apache Software Foundation",
              software="Fedora, HTTP Server", versions="34 (Fedora), 2.4.49 (HTTP Server)",
              severity_text=("Высокий уровень опасности (базовая оценка CVSS 2.0 составляет 9,3)\n"
                             "Высокий уровень опасности (базовая оценка CVSS 3.0 составляет 8,1)"),
              cve_ids=["CVE-2021-41773"], remediation="Обновить Apache HTTP Server до 2.4.51"),
    BduRecord(bdu_id="BDU:2021-06392", title="Уязвимость модуля mod_lua Apache HTTP Server",
              vendor="Apache Software Foundation", software="HTTP Server",
              versions="до 2.4.51 включительно (HTTP Server)",
              severity_text="Критический уровень опасности (базовая оценка CVSS 3.0 составляет 9,8)",
              cve_ids=["CVE-2021-44790"]),
    # Только в БДУ, без CVE (так бывает с отечественным ПО) — находится прямым поиском
    BduRecord(bdu_id="BDU:2023-09999", title="Уязвимость без CVE в Apache HTTP Server",
              vendor="Apache Software Foundation", software="HTTP Server",
              versions="от 2.4.0 до 2.4.50 (HTTP Server)",
              severity_text="Средний уровень опасности (базовая оценка CVSS 3.0 составляет 5,3)"),
    # «HTTP Server» другого вендора — отсекается проверкой вендора
    BduRecord(bdu_id="BDU:2022-11111", title="Уязвимость Oracle HTTP Server",
              vendor="Oracle Corp.", software="HTTP Server",
              versions="до 12.2.1.4 включительно (HTTP Server)",
              severity_text="Высокий уровень опасности (базовая оценка CVSS 3.0 составляет 7,5)"),
    BduRecord(bdu_id="BDU:2018-01037", title="Уязвимость OpenSSH (перечисление пользователей)",
              vendor="The OpenBSD Project", software="OpenSSH",
              versions="до 7.7 включительно (OpenSSH)",
              severity_text="Средний уровень опасности (базовая оценка CVSS 3.0 составляет 5,3)",
              cve_ids=["CVE-2018-15473"]),
]


def _fill(store):
    store.upsert_nvd(filter(None, (parse_cve_item(i) for i in NVD_ITEMS)))
    store.upsert_bdu(BDU_RECORDS)
    return store


@pytest.fixture(params=["memory", "sqlite"])
def store(request):
    if request.param == "memory":
        return _fill(InMemoryReferenceStore())
    return _fill(SqlReferenceStore.from_url("sqlite://", create=True))


@pytest.fixture
def matcher(store):
    return VulnMatcher(store)


def _finding(**kw):
    kw.setdefault("module", "vuln")
    kw.setdefault("host", "10.0.0.5")
    kw.setdefault("finding_type", FindingType.VULN)
    kw.setdefault("title", "test")
    return Finding(**kw)


APACHE_2449 = ServiceInfo("10.0.0.5", 80, "tcp", "http", "Apache httpd", "2.4.49",
                          cpe="cpe:/a:apache:http_server:2.4.49")


# ---------- цепочка 1: CVE -> NVD + все БДУ ----------

def test_cve_gets_all_linked_bdu(matcher):
    f = matcher.enrich(_finding(vuln_id="CVE-2013-5946"))
    assert f.cve_ids == ["CVE-2013-5946"]
    assert f.bdu_ids == ["BDU:2014-00002", "BDU:2015-00091"]
    assert f.cvss == 10.0                      # NVD нет -> базовая оценка из БДУ
    assert f.severity == Severity.CRITICAL


def test_cve_from_list_and_nvd_score(matcher):
    f = matcher.enrich(_finding(cve_ids=["cve-2021-41773"]))
    assert f.cve_ids == ["CVE-2021-41773"]
    assert f.bdu_ids == ["BDU:2021-04903"]
    assert f.cvss == 7.5                       # оценка NVD приоритетнее БДУ
    assert f.severity == Severity.HIGH


def test_severity_never_lowered(matcher):
    f = matcher.enrich(_finding(vuln_id="CVE-2021-41773", severity=Severity.CRITICAL))
    assert f.severity == Severity.CRITICAL


def test_match_exposes_remediation(matcher):
    res = matcher.match(_finding(vuln_id="CVE-2021-41773"))
    assert res.remediation == ["Обновить Apache HTTP Server до 2.4.51"]
    assert res.nvd["CVE-2021-41773"].summary == "CVE-2021-41773 summary"


# ---------- цепочка 2: BDU -> CVE ----------

def test_bdu_id_gets_cve(matcher):
    f = matcher.enrich(_finding(vuln_id="BDU:2021-06392"))
    assert f.cve_ids == ["CVE-2021-44790"]
    assert f.bdu_ids == ["BDU:2021-06392"]
    assert f.cvss == 9.8


def test_unknown_ids_kept(matcher):
    f = matcher.enrich(_finding(vuln_id="CVE-2000-0001", bdu_ids=["BDU:2000-00001"]))
    assert f.cve_ids == ["CVE-2000-0001"]
    assert f.bdu_ids == ["BDU:2000-00001"]
    assert f.severity == Severity.INFO


# ---------- цепочка 3: сервис+версия -> CPE -> CVE -> БДУ ----------

def test_service_only_gets_cve_and_bdu_by_cpe(matcher):
    f = matcher.enrich(_finding(port=80), service=APACHE_2449)
    assert "CVE-2021-41773" in f.cve_ids        # точная версия
    assert "CVE-2021-44790" in f.cve_ids        # диапазон <= 2.4.51
    assert "CVE-2099-0001" not in f.cve_ids     # другой вендор
    assert {"BDU:2021-04903", "BDU:2021-06392"} <= set(f.bdu_ids)
    assert f.severity == Severity.CRITICAL


def test_service_without_cpe_uses_nmap_alias(matcher):
    svc = ServiceInfo("10.0.0.5", 80, "tcp", "http", "Apache httpd", "2.4.51")
    res = matcher.match(_finding(port=80), service=svc)
    assert res.cve_ids == ["CVE-2021-44790"]    # 2.4.49 точная — мимо, диапазон — да
    assert "BDU:2021-06392" in res.bdu_ids
    assert any(e.source == SRC_CPE for e in res.evidence)


def test_openssh_banner_version(matcher):
    svc = ServiceInfo("10.0.0.5", 22, "tcp", "ssh", "OpenSSH", "7.4p1 Debian 10+deb9u7")
    res = matcher.match(_finding(port=22), service=svc)
    assert res.cve_ids == ["CVE-2018-15473"]    # 7.4p1 <= 7.7; 7.4p2 (точная) — нет
    assert res.bdu_ids == ["BDU:2018-01037"]


def test_service_without_version_not_matched(matcher):
    svc = ServiceInfo("10.0.0.5", 80, "tcp", "http", "Apache httpd", None)
    assert not matcher.match(_finding(port=80), service=svc).matched


def test_ids_take_precedence_over_service(matcher):
    res = matcher.match(_finding(vuln_id="CVE-2013-5946"), service=APACHE_2449)
    assert res.cve_ids == ["CVE-2013-5946"]


# ---------- цепочка 4: прямой поиск в БДУ по ПО+версии ----------

def test_bdu_product_match_without_nvd():
    store = InMemoryReferenceStore()
    store.upsert_bdu(BDU_RECORDS)                # NVD не загружен
    res = VulnMatcher(store).match(_finding(port=80), service=APACHE_2449)
    assert {"BDU:2021-04903", "BDU:2021-06392", "BDU:2023-09999"} <= set(res.bdu_ids)
    assert "BDU:2022-11111" not in res.bdu_ids   # Oracle HTTP Server
    # CVE подтянулись из записей БДУ
    assert {"CVE-2021-41773", "CVE-2021-44790"} <= set(res.cve_ids)
    assert any(e.source == SRC_BDU_PRODUCT for e in res.evidence)


def test_bdu_product_match_can_be_disabled(store):
    m = VulnMatcher(store, bdu_product_match=False)
    res = m.match(_finding(port=80), service=APACHE_2449)
    assert "BDU:2023-09999" not in res.bdu_ids


# ---------- находки по сервису для модуля vuln ----------

def test_findings_for_service_one_per_identifier(matcher):
    fs = matcher.findings_for_service(APACHE_2449)
    by_id = {f.vuln_id: f for f in fs}
    assert set(by_id) == {"CVE-2021-41773", "CVE-2021-44790", "BDU:2023-09999"}
    f = by_id["CVE-2021-41773"]
    assert f.bdu_ids == ["BDU:2021-04903"] and f.port == 80
    assert f.title == "Уязвимость веб-сервера Apache HTTP Server"
    assert "2.4.49" in f.evidence and "бэкпорт" in f.evidence
    assert by_id["BDU:2023-09999"].cve_ids == []
    # Ключ сравнения прогонов стабилен
    again = {f.vuln_id: f.dedup_key() for f in matcher.findings_for_service(APACHE_2449)}
    assert again == {k: v.dedup_key() for k, v in by_id.items()}


# ---------- загрузка справочников ----------

def test_bdu_reupsert_replaces_cve_links(store):
    rec = BduRecord(bdu_id="BDU:2015-00091", cve_ids=["CVE-2020-1111"])
    store.upsert_bdu([rec])
    assert [r.bdu_id for r in store.bdu_by_cve("CVE-2013-5946")] == ["BDU:2014-00002"]
    assert [r.bdu_id for r in store.bdu_by_cve("CVE-2020-1111")] == ["BDU:2015-00091"]


def test_store_roundtrip(store):
    rec = store.get_bdu("bdu:2021-04903")
    assert rec.cve_ids == ["CVE-2021-41773"] and rec.vendor.endswith("Foundation")
    nvd = store.get_nvd("CVE-2021-44790")
    assert nvd.cvss_v3 == 9.8 and nvd.severity == "CRITICAL"
    assert nvd.cpe_matches[0].version_end_incl == "2.4.51"


def test_bdu_sync_upserts_into_store(monkeypatch):
    feed = BduFstecFeed("unused.xlsx")
    monkeypatch.setattr(feed, "iter_records", lambda: iter(BDU_RECORDS))
    store = SqlReferenceStore.from_url("sqlite://", create=True)
    assert feed.sync(store, batch_size=3) == len(BDU_RECORDS)
    assert [r.bdu_id for r in store.bdu_by_cve("CVE-2013-5946")] == [
        "BDU:2014-00002", "BDU:2015-00091"]


@pytest.mark.skipif(not os.path.isfile(os.environ.get("BDU_FSTEC_FEED_PATH", "")),
                    reason="реальная выгрузка БДУ не задана (BDU_FSTEC_FEED_PATH)")
def test_real_bdu_export_cve_2013_5946():
    store = InMemoryReferenceStore()
    assert BduFstecFeed(os.environ["BDU_FSTEC_FEED_PATH"]).sync(store) > 90_000
    f = VulnMatcher(store).enrich(_finding(vuln_id="CVE-2013-5946"))
    assert "BDU:2014-00002" in f.bdu_ids
