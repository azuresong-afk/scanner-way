"""CORS для веб-интерфейса: выключен по умолчанию, только явные origin'ы."""
from __future__ import annotations

from fastapi.testclient import TestClient

from scanner.api.main import create_app
from scanner.api.settings import ApiSettings
from scanner.core.orchestrator import inline_executor
from scanner.reporting.remediation import RemediationResolver

ORIGIN = "https://scanner.example.local"


def _client(sqlite_factory, **kw) -> TestClient:
    app = create_app(session_factory=sqlite_factory,
                     settings=ApiSettings(secret="x" * 40, **kw), registry={},
                     executor=inline_executor(),
                     resolver_factory=lambda findings: RemediationResolver())
    return TestClient(app)


def _preflight(c: TestClient, origin: str):
    return c.options("/me", headers={"Origin": origin,
                                     "Access-Control-Request-Method": "GET",
                                     "Access-Control-Request-Headers": "authorization"})


def test_cors_disabled_by_default(sqlite_factory):
    with _client(sqlite_factory) as c:
        r = c.get("/health", headers={"Origin": ORIGIN})
        assert "access-control-allow-origin" not in r.headers


def test_cors_allows_only_listed_origins(sqlite_factory):
    with _client(sqlite_factory, cors_origins=f" {ORIGIN}/ , http://localhost:5173") as c:
        ok = _preflight(c, ORIGIN)
        assert ok.status_code == 200
        assert ok.headers["access-control-allow-origin"] == ORIGIN
        assert "authorization" in ok.headers["access-control-allow-headers"].lower()
        assert "access-control-allow-credentials" not in ok.headers

        bad = _preflight(c, "https://evil.example")
        assert "access-control-allow-origin" not in bad.headers
