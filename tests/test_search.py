"""Быстрый поиск по проекту (Ctrl+K): хосты, ПО, CVE/БДУ, действия и команды."""
from __future__ import annotations

from scanner.core import assets
from scanner.core import repository as repo
from scanner.core.db import session_scope
from scanner.core.models import (
    Finding,
    FindingType,
    HostInventory,
    InstalledPackage,
    ServiceInfo,
    Severity,
)
from tests.test_fixplan import _pkg
from tests.test_pagination import _admin_can_view, _client, _login


def _seed(factory):
    with session_scope(factory) as s:
        eid = repo.create_engagement(s, name="Ромашка")
        other = repo.create_engagement(s, name="Чужой")
        rid = repo.create_scan_run(s, engagement_id=eid, modules=["auth_inventory"],
                                   targets=["10.0.0.0/24"], name="Плановый")
        repo.save_inventory(s, scan_run_id=rid, inventories=[
            HostInventory(host=h, os_id="debian", os_name="Debian GNU/Linux 12 (bookworm)",
                          os_version="12", os_codename="bookworm", packages=[
                              InstalledPackage("openssl", "3.0.11-1~deb12u1", "dpkg"),
                              InstalledPackage("openssh-server", "1:9.2p1-2", "dpkg")])
            for h in ("10.0.0.1", "10.0.0.2")])
        repo.save_services(s, scan_run_id=rid, services=[
            ServiceInfo(host="10.0.0.3", port=80, protocol="tcp", service="http",
                        product="nginx", version="1.18.0")])
        repo.save_findings(s, engagement_id=eid, scan_run_id=rid, findings=[
            _pkg("10.0.0.1", "CVE-2023-5678"), _pkg("10.0.0.2", "CVE-2023-5678"),
            Finding(module="vuln", host="10.0.0.3", port=80, finding_type=FindingType.VULN,
                    vuln_id="CVE-2021-23017", cve_ids=["CVE-2021-23017"],
                    bdu_ids=["BDU:2021-03016"], severity=Severity.CRITICAL,
                    title="nginx: переполнение в резолвере")])
        repo.set_scan_run_status(s, rid, "done")
        assets.record_seen(s, eid, ["10.0.0.1", "10.0.0.2", "10.0.0.3"], source="discovery",
                           hostnames={"10.0.0.3": "web-front"})
        # данные другого проекта в поиск не попадают
        assets.create_asset(s, other, address="10.9.9.9", hostname="web-front-other")
    return eid, other, rid


def test_search_groups_by_kind(sqlite_factory):
    eid, other, rid = _seed(sqlite_factory)
    with _client(sqlite_factory) as c:
        h = _admin_can_view(c, _login(c))
        get = lambda q, **kw: c.get(f"/engagements/{eid}/search", headers=h,
                                    params={"q": q, **kw})

        r = get("web-front")
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["run_id"] == rid and body["assets"] == 3 and body["findings"] == 3
        assert [x["host"] for x in body["hosts"]] == ["10.0.0.3"]
        assert body["hosts"][0]["hostname"] == "web-front"
        assert body["hosts"][0]["max_severity"] == "critical" and body["hosts"][0]["vulns"] == 1

        # пакет: ПО с числом хостов и уязвимых, хосты с этим ПО, действие и команда
        b = get("openssl").json()
        sw = b["software"][0]
        assert sw["name"] == "openssl" and sw["host_count"] == 2
        assert sw["vulnerable_hosts"] == 2 and sw["vulns"] == 2
        assert [x["host"] for x in b["hosts"]] == ["10.0.0.1", "10.0.0.2"]
        assert b["hosts"][0]["match"] == "openssl 3.0.11-1~deb12u1"
        assert b["hosts"][0]["os"] == "Debian GNU/Linux 12 (bookworm)"
        assert b["counts"]["actions"] == 1 and b["actions"][0]["host_count"] == 2
        assert b["commands"][0]["command"] == "sudo apt-get install --only-upgrade -y libssl3 openssl"
        assert b["commands"][0]["commands"][0] == "sudo apt-get update"
        assert [v["id"] for v in b["vulns"]] == ["CVE-2023-5678"]

        # CVE и БДУ: группировка по уязвимости, поиск по номеру БДУ без учёта регистра
        v = get("bdu:2021-03016").json()["vulns"]
        assert len(v) == 1 and v[0]["id"] == "CVE-2021-23017" and v[0]["severity"] == "critical"
        assert v[0]["bdu_ids"] == ["BDU:2021-03016"] and v[0]["hosts"] == ["10.0.0.3"]

        # ПО сервиса из баннера; адрес хоста не считается совпадением уязвимости
        n = get("nginx").json()
        assert n["software"][0]["source"] == "service" and n["software"][0]["versions"] == ["1.18.0"]
        assert get("10.0.0.3").json()["vulns"] == []

        # команда по тексту команды
        assert get("only-upgrade").json()["counts"]["commands"] == 1

        assert get("ничего-такого").json()["counts"] == {
            "hosts": 0, "software": 0, "vulns": 0, "actions": 0, "commands": 0}
        assert c.get(f"/engagements/{eid}/search", headers=h, params={"q": ""}).status_code == 422
        assert get("x", run_id=999).status_code == 404
        # чужой проект — свои данные
        o = c.get(f"/engagements/{other}/search", headers=h, params={"q": "web-front"}).json()
        assert [x["host"] for x in o["hosts"]] == ["10.9.9.9"] and o["run_id"] is None


def test_search_needs_view_report(sqlite_factory):
    from tests.test_pagination import PASSWORD
    eid, _, _ = _seed(sqlite_factory)
    with _client(sqlite_factory) as c:
        c.post("/users", headers=_login(c), json={"username": "nobody", "password": PASSWORD,
                                                  "roles": []})
        tok = c.post("/auth/token", json={"username": "nobody", "password": PASSWORD})
        h = {"Authorization": "Bearer " + tok.json()["access_token"]}
        assert c.get(f"/engagements/{eid}/search", headers=h,
                     params={"q": "a"}).status_code == 403
