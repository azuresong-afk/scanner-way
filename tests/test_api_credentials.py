"""API: учётные записи активов, выбор движка поиска уязвимостей, пакеты хостов."""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from scanner.api.main import create_app
from scanner.api.settings import ApiSettings
from scanner.core.db import AuditLogRow, HostCredentialRow
from scanner.core.models import (
    Finding,
    FindingType,
    HostInventory,
    InstalledPackage,
    Severity,
)
from scanner.core.orchestrator import inline_executor
from scanner.modules.base import ScanContext, ScanModule
from scanner.reporting.remediation import RemediationResolver
from tests.test_api import PASSWORD, SECRET, Api, FakeDiscovery, FakeVuln, Recorder
from tests.test_credentials import make_key

HOST_PASSWORD = "Host-Pa55-do-not-leak"


class FakeInventory(ScanModule):
    name = "auth_inventory"

    def __init__(self, rec: Recorder):
        self.rec = rec

    def run(self, ctx: ScanContext) -> list[Finding]:
        self.rec.seen[self.name] = list(ctx.targets)
        self.rec.creds = list(ctx.credentials)
        out = []
        for t in ctx.targets:
            ctx.inventory[t] = HostInventory(
                host=t, os_id="debian", os_name="Debian GNU/Linux 12 (bookworm)",
                packages=[InstalledPackage("openssh-server", "1:9.2p1-2+deb12u3", "dpkg",
                                           "amd64"),
                          InstalledPackage("bash", "5.2.15-2+b2", "dpkg", "amd64")],
                credential_id=ctx.credentials[0].id)
            out.append(Finding(module=self.name, host=t, finding_type=FindingType.VULN,
                               title="regreSSHion", severity=Severity.HIGH,
                               vuln_id="CVE-2024-6387", cve_ids=["CVE-2024-6387"],
                               bdu_ids=["BDU:2024-04970"]))
        return out


@pytest.fixture
def rec():
    return Recorder()


@pytest.fixture
def api(sqlite_factory, rec):
    registry = {"discovery": lambda: FakeDiscovery(rec),
                "vuln": lambda: FakeVuln(rec, ["CVE-2016-6210"]),
                "auth_inventory": lambda: FakeInventory(rec)}
    settings = ApiSettings(secret=SECRET, bootstrap_admin="root",
                           bootstrap_password=PASSWORD)
    app = create_app(session_factory=sqlite_factory, settings=settings, registry=registry,
                     executor=inline_executor(),
                     resolver_factory=lambda findings: RemediationResolver())
    with TestClient(app) as c:
        yield Api(c)


def _cred(api, eid, headers, **kw):
    body = {"name": "аудит", "username": "audit", "auth": "password",
            "password": HOST_PASSWORD, **kw}
    return api.c.post(f"/engagements/{eid}/credentials", headers=headers, json=body)


def test_credentials_need_explicit_permission(api):
    eid = api.engagement("10.0.0.0/24")
    op = api.user("op", "operator")
    for headers in (api.admin, op):
        assert _cred(api, eid, headers).status_code == 403
        assert api.c.get(f"/engagements/{eid}/credentials", headers=headers).status_code == 403


def test_create_list_delete_never_exposes_secrets(api, sqlite_factory):
    eid = api.engagement("10.0.0.0/24")
    holder = api.user("keeper", "operator", "host_credentials")
    r = _cred(api, eid, holder, targets=["10.0.0.5"])
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["targets"] == ["10.0.0.5/32"] and body["auth"] == "password"
    assert "password" not in body and "secret_enc" not in body
    key = make_key()
    r = _cred(api, eid, holder, name="ключ", auth="key", private_key=key, password=None)
    assert r.status_code == 201, r.text
    assert r.json()["key_fingerprint"].startswith("SHA256:")
    listed = api.c.get(f"/engagements/{eid}/credentials", headers=holder)
    assert [c["name"] for c in listed.json()] == ["аудит", "ключ"]
    assert HOST_PASSWORD not in listed.text and "PRIVATE KEY" not in listed.text

    cid = body["id"]
    assert api.c.delete(f"/engagements/{eid}/credentials/{cid}",
                        headers=holder).status_code == 204
    assert api.c.delete(f"/engagements/{eid}/credentials/{cid}",
                        headers=holder).status_code == 404
    with sqlite_factory() as s:
        audit = [(a, r, d) for a, r, d in s.execute(
            select(AuditLogRow.action, AuditLogRow.result, AuditLogRow.details))]
        rows = list(s.scalars(select(HostCredentialRow)))
    assert ("credential_create", "ok") in [(a, r) for a, r, _ in audit]
    assert ("credential_delete", "ok") in [(a, r) for a, r, _ in audit]
    assert HOST_PASSWORD not in repr(audit) and "PRIVATE KEY" not in repr(audit)
    assert all(HOST_PASSWORD not in r.secret_enc for r in rows)


def test_create_validates_scope_and_key(api):
    eid = api.engagement("10.0.0.0/24")
    holder = api.user("keeper", "operator", "host_credentials")
    r = _cred(api, eid, holder, targets=["192.168.0.0/24"])
    assert r.status_code == 422 and "allowlist" in r.json()["detail"]
    r = _cred(api, eid, holder, auth="key", private_key="not a key", password=None)
    assert r.status_code == 422
    r = _cred(api, eid, holder, auth="token")
    assert r.status_code == 422


def test_create_without_vault_key(sqlite_factory, rec, monkeypatch):
    monkeypatch.setenv("SCANNER_CREDENTIALS_KEY", "")
    monkeypatch.setenv("SCANNER_API_SECRET", "")
    settings = ApiSettings(secret="", bootstrap_admin="root", bootstrap_password=PASSWORD)
    app = create_app(session_factory=sqlite_factory, settings=settings,
                     registry={"auth_inventory": lambda: FakeInventory(rec)},
                     executor=inline_executor(),
                     resolver_factory=lambda findings: RemediationResolver())
    with TestClient(app) as c:
        api = Api(c)
        eid = api.engagement("10.0.0.0/24")
        holder = api.user("keeper", "operator", "host_credentials")
        r = _cred(api, eid, holder)
        assert r.status_code == 503
        assert r.json()["detail"]["code"] == "credentials_key_missing"


def test_run_with_credentialed_engine(api, rec):
    eid = api.engagement("10.0.0.0/24")
    holder = api.user("keeper", "operator", "host_credentials")
    cid = _cred(api, eid, holder).json()["id"]
    body = {"targets": ["10.0.0.5"], "modules": ["discovery", "vuln"],
            "vuln_engine": "credentialed", "credential_ids": [cid]}
    r = api.c.post(f"/engagements/{eid}/runs", headers=holder, json=body)
    assert r.status_code == 202, r.text
    run = r.json()
    assert run["modules"] == ["discovery", "auth_inventory"]     # vuln заменён движком
    assert run["credential_ids"] == [cid] and run["status"] == "done"
    assert "vuln" not in rec.seen
    assert [c.password for c in rec.creds] == [HOST_PASSWORD]    # расшифровано для модуля

    pk = api.c.get(f"/runs/{run['id']}/packages", headers=holder).json()
    assert [(p["host"], p["name"]) for p in pk] == [("10.0.0.5", "bash"),
                                                    ("10.0.0.5", "openssh-server")]
    hosts = api.c.get(f"/engagements/{eid}/hosts", headers=holder).json()
    assert hosts[0]["os_guess"] == "Debian GNU/Linux 12 (bookworm)"
    assert hosts[0]["packages_run_id"] == run["id"] and hosts[0]["package_count"] == 2
    findings = api.c.get(f"/runs/{run['id']}/findings", headers=holder).json()
    assert {f["module"] for f in findings} == {"discovery", "auth_inventory"}
    assert HOST_PASSWORD not in r.text


def test_run_engine_both_and_nuclei(api, rec):
    eid = api.engagement("10.0.0.0/24")
    holder = api.user("keeper", "operator", "host_credentials")
    cid = _cred(api, eid, holder).json()["id"]
    r = api.c.post(f"/engagements/{eid}/runs", headers=holder,
                   json={"targets": ["10.0.0.5"], "modules": ["discovery"],
                         "vuln_engine": "both", "credential_ids": [cid]})
    assert r.json()["modules"] == ["discovery", "vuln", "auth_inventory"]
    op = api.user("op", "operator")
    r = api.c.post(f"/engagements/{eid}/runs", headers=op,
                   json={"targets": ["10.0.0.5"], "modules": ["discovery", "auth_inventory"],
                         "vuln_engine": "nuclei"})
    assert r.status_code == 202 and r.json()["modules"] == ["discovery", "vuln"]


def test_run_credential_checks(api):
    eid = api.engagement("10.0.0.0/24")
    other = api.engagement("10.1.0.0/24")
    holder = api.user("keeper", "operator", "host_credentials")
    op = api.user("op", "operator")
    cid = _cred(api, eid, holder).json()["id"]
    foreign = _cred(api, other, holder).json()["id"]

    def run(headers, **kw):
        return api.c.post(f"/engagements/{eid}/runs", headers=headers,
                          json={"targets": ["10.0.0.5"], "modules": ["discovery"], **kw})

    # без права host_credentials — ни движок, ни учётки
    assert run(op, vuln_engine="credentialed", credential_ids=[cid]).status_code == 403
    assert run(op, credential_ids=[cid]).status_code == 403
    # движку нужна учётка
    r = run(holder, vuln_engine="credentialed")
    assert r.status_code == 422 and "учётная запись" in r.json()["detail"]
    # учётка чужого договора
    r = run(holder, vuln_engine="credentialed", credential_ids=[foreign])
    assert r.status_code == 422 and str(foreign) in r.json()["detail"]
    # учётка без модуля, который её использует
    assert run(holder, credential_ids=[cid]).status_code == 422
