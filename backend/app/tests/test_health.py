"""Health probes."""

from __future__ import annotations

from fastapi.testclient import TestClient


def test_root_reports_service_metadata(client: TestClient) -> None:
    response = client.get("/")
    assert response.status_code == 200
    assert response.json()["api"] == "/api/v1"


def test_health_is_public(client: TestClient) -> None:
    """The SPA needs an unauthenticated probe to distinguish 'backend down'
    from 'not logged in'."""
    response = client.get("/api/v1/health")
    assert response.status_code == 200
    assert response.json()["status"] == "healthy"


def test_readiness_reports_database(client: TestClient) -> None:
    body = client.get("/api/v1/health/ready").json()
    assert body["status"] in {"healthy", "degraded"}
    assert body["components"]["database"] == "healthy"


def test_component_health_requires_a_session(client: TestClient) -> None:
    """Public probes stay thin; internals need authentication."""
    assert client.get("/api/v1/health/database").status_code == 401
    assert client.get("/api/v1/health/telemetry").status_code == 401
    assert client.get("/api/v1/health/system").status_code == 401


def test_system_health_reports_every_component(client: TestClient, auth_headers: dict) -> None:
    body = client.get("/api/v1/health/system", headers=auth_headers).json()

    assert body["status"] in {"healthy", "degraded", "unavailable"}
    assert body["database"]["status"] == "healthy"
    assert "latencyMs" in body["database"]
    # Telemetry is switched off in tests, which is degraded rather than healthy.
    assert body["telemetry"]["status"] == "degraded"
    assert body["realtime"]["connectedClients"] >= 0
    assert "error" not in body["database"] or "://" not in str(body["database"].get("error"))


def test_requests_carry_a_request_id(client: TestClient) -> None:
    response = client.get("/api/v1/health")
    assert response.headers.get("X-Request-ID")


def test_inbound_request_id_is_echoed(client: TestClient) -> None:
    response = client.get("/api/v1/health", headers={"X-Request-ID": "trace-abc-123"})
    assert response.headers["X-Request-ID"] == "trace-abc-123"
