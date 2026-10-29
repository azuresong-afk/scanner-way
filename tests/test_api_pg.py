"""Сквозной путь API на реальном PostgreSQL (схема из миграций Alembic).

Проверяет, что ORM-отображение RBAC-таблиц совпадает со схемой 0001, засев ролей
работает на PG и прогон/отчёт проходят с типами INET/CIDR/ARRAY/JSONB.
"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text

from scanner.api.main import create_app
from scanner.api.settings import ApiSettings
from scanner.core.models import Finding, FindingType
from scanner.core.orchestrator import inline_executor
from scanner.modules.base import ScanModule
from scanner.reporting.remediation import RemediationResolver
from tests.conftest import PG_URL
from tests.test_migrations_pg import pg_factory  # noqa: F401 — фикстура

pytestmark = pytest.mark.skipif(not PG_URL, reason="SCANNER_TEST_DATABASE_URL not set")

PASSWORD = "correct-horse-battery"


class Echo(ScanModule):
    name = "discovery"

    def run(self, ctx):
        return [Finding(module=self.name, host=t, finding_type=FindingType.INFO,
                        title="host up", vuln_id="INFO:host-up") for t in ctx.targets]


def test_api_end_to_end_on_postgres(pg_factory):  # noqa: F811
    app = create_app(session_factory=pg_factory,
                     settings=ApiSettings(secret="z" * 40, bootstrap_admin="root",
                                          bootstrap_password=PASSWORD),
                     registry={"discovery": Echo}, executor=inline_executor(),
                     resolver_factory=lambda f: RemediationResolver())
    with TestClient(app) as c:
        def login(u):
            r = c.post("/auth/token", json={"username": u, "password": PASSWORD})
            return {"Authorization": f"Bearer {r.json()['access_token']}"}
        admin = login("root")
        r = c.post("/users", headers=admin,
                   json={"username": "op", "password": PASSWORD, "roles": ["operator"]})
        assert r.status_code == 201, r.text
        op = login("op")
        eid = c.post("/engagements", headers=admin, json={"name": "pg"}).json()["id"]
        r = c.post(f"/engagements/{eid}/allowlist", headers=admin,
                   json={"cidr": "10.2.0.0/30"})
        assert r.status_code == 201 and r.json()["cidr"] == "10.2.0.0/30"
        assert c.get(f"/engagements/{eid}/allowlist", headers=op).status_code == 200

        r = c.post(f"/engagements/{eid}/runs", headers=op,
                   json={"targets": ["10.2.0.0/29", "8.8.8.8"], "modules": ["discovery"]})
        assert r.status_code == 202, r.text
        assert r.json()["status"] == "done" and r.json()["accepted_targets"] == 3
        run_id = r.json()["id"]
        hosts = sorted(f["host"] for f in
                       c.get(f"/runs/{run_id}/findings", headers=op).json())
        assert hosts == ["10.2.0.1", "10.2.0.2", "10.2.0.3"]
        assert c.get(f"/runs/{run_id}/report", headers=op,
                     params={"format": "json"}).status_code == 200
        assert c.post("/engagements", headers=op, json={"name": "x"}).status_code == 403

    with pg_factory() as s:
        roles = set(s.scalars(text("SELECT name FROM roles")))
        assert roles == {"admin", "operator", "auditor", "cred_audit", "host_credentials"}
        actions = set(s.scalars(text("SELECT action FROM audit_log")))
        assert {"login", "user_create", "allowlist_add", "scan_queue", "deny",
                "scan_finish", "export", "access_denied"} <= actions
