"""API: наборы проверки учёток (аудит паролей). Только с правом cred_audit;
секреты не возвращаются и не попадают в журнал."""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from scanner.api.main import create_app
from scanner.api.settings import ApiSettings
from scanner.core.db import AuditLogRow, CredAuditSetRow
from scanner.core.orchestrator import inline_executor
from scanner.modules.cred_audit import AuthOutcome, AuthResult, CredentialAuditModule
from scanner.reporting.remediation import RemediationResolver
from tests.test_api import PASSWORD, SECRET, Api, FakeDiscovery, Recorder

SET_SECRET = "Set-Pa55-do-not-leak"


class _NoNetworkAuth:
    """Фейковый бэкенд: любую учётку отклоняет — без сети (для тестов API)."""

    def authenticate(self, host, port, service, credential, timeout):
        return AuthResult(AuthOutcome.FAILURE)


@pytest.fixture
def api(sqlite_factory):
    rec = Recorder()
    registry = {
        "discovery": lambda: FakeDiscovery(rec),
        "cred_audit": lambda: CredentialAuditModule(authenticator=_NoNetworkAuth(),
                                                    sleep=lambda s: None),
    }
    settings = ApiSettings(secret=SECRET, bootstrap_admin="root",
                           bootstrap_password=PASSWORD)
    app = create_app(session_factory=sqlite_factory, settings=settings, registry=registry,
                     executor=inline_executor(),
                     resolver_factory=lambda findings: RemediationResolver())
    with TestClient(app) as c:
        yield Api(c)


def _set(api, eid, headers, **kw):
    body = {"name": "дефолтные учётки",
            "services": ["ssh"],
            "entries": [{"username": "root", "secret": ""},
                        {"username": "admin", "secret": SET_SECRET}], **kw}
    return api.c.post(f"/engagements/{eid}/cred-sets", headers=headers, json=body)


def test_cred_sets_require_cred_audit_permission(api):
    eid = api.engagement("10.0.0.0/24")
    op = api.user("op", "operator")
    for headers in (api.admin, op):
        assert _set(api, eid, headers).status_code == 403
        assert api.c.get(f"/engagements/{eid}/cred-sets",
                         headers=headers).status_code == 403


def test_create_list_delete_never_exposes_secret(api, sqlite_factory):
    eid = api.engagement("10.0.0.0/24")
    auditor = api.user("ca", "operator", "cred_audit")
    r = _set(api, eid, auditor)
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["entry_count"] == 2 and body["services"] == ["ssh"]
    assert "entries" not in body and "secret" not in r.text and SET_SECRET not in r.text
    # наружу — только маскированные логины
    assert body["masked_usernames"] == ["ro**", "ad***"]

    listed = api.c.get(f"/engagements/{eid}/cred-sets", headers=auditor)
    assert [s["name"] for s in listed.json()] == ["дефолтные учётки"]
    assert SET_SECRET not in listed.text

    sid = body["id"]
    assert api.c.delete(f"/engagements/{eid}/cred-sets/{sid}",
                        headers=auditor).status_code == 204
    assert api.c.delete(f"/engagements/{eid}/cred-sets/{sid}",
                        headers=auditor).status_code == 404
    with sqlite_factory() as s:
        audit = [(a, r, repr(d)) for a, r, d in s.execute(
            select(AuditLogRow.action, AuditLogRow.result, AuditLogRow.details))]
        rows = list(s.scalars(select(CredAuditSetRow)))
    actions = {(a, r) for a, r, _ in audit}
    assert ("cred_set_create", "ok") in actions and ("cred_set_delete", "ok") in actions
    assert SET_SECRET not in repr(audit)
    assert all(SET_SECRET not in r.secret_enc for r in rows)


def test_empty_entries_rejected(api):
    eid = api.engagement("10.0.0.0/24")
    auditor = api.user("ca", "operator", "cred_audit")
    r = api.c.post(f"/engagements/{eid}/cred-sets", headers=auditor,
                   json={"name": "x", "entries": []})
    assert r.status_code == 422  # min_length=1 на entries


def test_run_with_cred_set_requires_permission_and_membership(api):
    eid = api.engagement("10.0.0.0/24")
    other = api.engagement("10.1.0.0/24")
    auditor = api.user("ca", "operator", "cred_audit")
    op = api.user("op", "operator")
    sid = _set(api, eid, auditor).json()["id"]
    foreign = _set(api, other, auditor).json()["id"]

    def run(headers, **kw):
        return api.c.post(f"/engagements/{eid}/runs", headers=headers,
                          json={"targets": ["10.0.0.5"],
                                "modules": ["discovery", "cred_audit"], **kw})

    # оператор без cred_audit не может ни модуль, ни набор
    assert run(op, cred_set_ids=[sid]).status_code == 403
    # набор чужого договора
    r = run(auditor, cred_set_ids=[foreign])
    assert r.status_code == 422 and str(foreign) in r.json()["detail"]
    # корректный запуск: модуль поставлен, набор привязан
    r = run(auditor, cred_set_ids=[sid])
    assert r.status_code == 202, r.text
    assert r.json()["cred_set_ids"] == [sid]


def test_run_cred_audit_without_set_starts_but_module_skips(api, sqlite_factory):
    """Без набора прогон стартует, а cred_audit пишет осознанный пропуск."""
    eid = api.engagement("10.0.0.0/24")
    auditor = api.user("ca", "operator", "cred_audit")
    r = api.c.post(f"/engagements/{eid}/runs", headers=auditor,
                   json={"targets": ["10.0.0.5"], "modules": ["discovery", "cred_audit"]})
    assert r.status_code == 202, r.text
    assert r.json()["cred_set_ids"] == []
    with sqlite_factory() as s:
        results = {r for (r,) in s.execute(
            select(AuditLogRow.result).where(AuditLogRow.action == "cred_audit_skip"))}
    assert "no_credentials" in results
