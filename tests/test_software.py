"""ПО находки (для группировки уязвимостей хоста по ПО)."""
from __future__ import annotations

from scanner.core.models import Finding, FindingType, ServiceInfo
from scanner.core.software import Software, from_evidence, software_of
from scanner.feeds.matcher import VulnMatcher
from tests.test_api import _run
from tests.test_auth_inventory import reference_store
from tests.test_false_positives import api  # noqa: F401 — фикстура


def _f(port=None, evidence=None, module="vuln"):
    return Finding(module=module, host="10.0.0.5", port=port,
                   finding_type=FindingType.VULN, title="x", evidence=evidence)


def test_service_finding_takes_product_and_version_from_port():
    services = {("10.0.0.5", 22): ServiceInfo("10.0.0.5", 22, "tcp", "ssh", "OpenSSH", "9.2p1"),
                ("10.0.0.5", 8080): ServiceInfo("10.0.0.5", 8080, "tcp", "http-proxy")}
    assert software_of(_f(22), services) == Software("OpenSSH", "9.2p1")
    # без баннера — хотя бы имя сервиса
    assert software_of(_f(8080), services) == Software("http-proxy")
    assert software_of(_f(443), services) is None
    assert software_of(_f(22)) is None


def test_package_finding_takes_software_from_matcher_evidence():
    m = VulnMatcher(reference_store())
    found = m.findings_for_package("10.0.0.5", product="OpenSSH", version="9.2p1",
                                   cpe="cpe:/a:openbsd:openssh",
                                   distro_version="1:9.2p1-2+deb12u2",
                                   packages=["openssh-server", "openssh-client"])
    assert found
    for f in found:
        assert software_of(f) == Software("OpenSSH", "9.2p1", "package")
    # без CPE (только БДУ по названию), название из нескольких слов
    glibc = m.findings_for_package("10.0.0.5", product="GNU C Library", version="2.36",
                                   bdu_names=["glibc"], distro_version="2.36-9+deb12u4",
                                   packages=["libc6"])
    assert glibc and all(software_of(f) == Software("GNU C Library", "2.36", "package") for f in glibc)


def test_unknown_software():
    assert from_evidence(None) is None
    assert from_evidence("Конфигурация: PermitRootLogin yes") is None
    assert software_of(_f(evidence="Пароль подобран", module="cred_audit")) is None


def test_api_findings_carry_software(api):  # noqa: F811
    eid = api.engagement("10.0.0.0/24")
    op = api.user("op", "operator")
    run_id = _run(api, eid, op, ["10.0.0.1"]).json()["id"]
    findings = api.c.get(f"/runs/{run_id}/findings", headers=op).json()
    vulns = [f for f in findings if f["port"] == 22]
    assert vulns
    assert {(f["software"], f["software_version"], f["software_source"])
            for f in vulns} == {("OpenSSH", "7.4", "service")}
    # и в ответе на отметку ложного срабатывания
    r = api.c.put(f"/findings/{vulns[0]['id']}/false-positive", headers=op, json={})
    assert r.json()["software"] == "OpenSSH"
