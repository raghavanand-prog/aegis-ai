"""Security behaviour: RBAC, session revocation, headers, limits, safe errors."""

from __future__ import annotations

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from starlette.responses import PlainTextResponse

from app.core.middleware import RateLimitMiddleware
from app.core.rbac import (
    ADMIN_PERMISSIONS,
    ANALYST_PERMISSIONS,
    VIEWER_PERMISSIONS,
    Permission,
    has_permission,
    permission_matrix,
)
from app.tests.conftest import DEMO_EMAIL, DEMO_PASSWORD

ANALYST_CREDENTIALS = {"email": "analyst.rbac@aegisx.dev", "password": "AnalystPassw0rd!"}
VIEWER_CREDENTIALS = {"email": "viewer.rbac@aegisx.dev", "password": "ViewerPassw0rd!"}


def _ensure_user(client: TestClient, admin_headers: dict, credentials: dict, role: str) -> None:
    response = client.post(
        "/api/v1/auth/users",
        json={
            "email": credentials["email"],
            "password": credentials["password"],
            "fullName": role.title(),
            "role": role,
        },
        headers=admin_headers,
    )
    assert response.status_code in (201, 409), response.text


def _headers_for(client: TestClient, credentials: dict) -> dict:
    response = client.post("/api/v1/auth/login", json=credentials)
    assert response.status_code == 200, response.text
    return {"Authorization": f"Bearer {response.json()['accessToken']}"}


@pytest.fixture()
def analyst_headers(client: TestClient, auth_headers: dict) -> dict:
    _ensure_user(client, auth_headers, ANALYST_CREDENTIALS, "analyst")
    return _headers_for(client, ANALYST_CREDENTIALS)


@pytest.fixture()
def viewer_headers(client: TestClient, auth_headers: dict) -> dict:
    _ensure_user(client, auth_headers, VIEWER_CREDENTIALS, "viewer")
    return _headers_for(client, VIEWER_CREDENTIALS)


# ------------------------------------------------------------------ RBAC model
def test_roles_are_nested_not_arbitrary() -> None:
    assert VIEWER_PERMISSIONS < ANALYST_PERMISSIONS < ADMIN_PERMISSIONS


def test_viewer_holds_no_write_permission() -> None:
    for permission in VIEWER_PERMISSIONS:
        assert permission.value.endswith(":read"), f"{permission} is not read-only"


def test_permission_matrix_is_serializable() -> None:
    matrix = permission_matrix()
    assert set(matrix) == {"admin", "analyst", "viewer"}
    assert Permission.EVENTS_PROMOTE.value in matrix["analyst"]
    assert Permission.EVENTS_PROMOTE.value not in matrix["viewer"]
    assert Permission.USERS_MANAGE.value in matrix["admin"]


def test_unknown_role_gets_nothing() -> None:
    assert has_permission("superuser", Permission.EVENTS_READ) is False


# ------------------------------------------------------------ RBAC enforcement
def test_viewer_can_read_but_not_promote(
    client: TestClient, auth_headers: dict, viewer_headers: dict
) -> None:
    from app.tests.test_events import ingest

    event = ingest(client, auth_headers)

    assert client.get("/api/v1/events", headers=viewer_headers).status_code == 200
    assert client.get("/api/v1/incidents", headers=viewer_headers).status_code == 200

    denied = client.post(f"/api/v1/events/{event['id']}/promote", headers=viewer_headers)
    assert denied.status_code == 403
    assert "events:promote" in denied.json()["detail"]


def test_viewer_cannot_ingest_or_update(
    client: TestClient, auth_headers: dict, viewer_headers: dict
) -> None:
    from app.tests.test_events import ingest

    event = ingest(client, auth_headers)

    assert (
        client.patch(
            f"/api/v1/events/{event['id']}/status",
            json={"status": "Investigating"},
            headers=viewer_headers,
        ).status_code
        == 403
    )
    assert (
        client.post(
            "/api/v1/incidents",
            json={"title": "nope"},
            headers=viewer_headers,
        ).status_code
        == 403
    )


def test_analyst_can_work_incidents_but_not_administer(
    client: TestClient, auth_headers: dict, analyst_headers: dict
) -> None:
    from app.tests.test_events import ingest

    event = ingest(client, auth_headers)

    promoted = client.post(f"/api/v1/events/{event['id']}/promote", headers=analyst_headers)
    assert promoted.status_code == 201

    assert client.get("/api/v1/audit", headers=analyst_headers).status_code == 403
    assert client.post("/api/v1/telemetry/tick", headers=analyst_headers).status_code == 403
    assert (
        client.post("/api/v1/detection/quality/run", headers=analyst_headers).status_code == 403
    )
    assert (
        client.post(
            "/api/v1/auth/users",
            json={"email": "x@aegisx.dev", "password": "Passw0rdPassw0rd", "role": "viewer"},
            headers=analyst_headers,
        ).status_code
        == 403
    )


def test_denied_access_is_audited(
    client: TestClient, auth_headers: dict, viewer_headers: dict
) -> None:
    client.get("/api/v1/audit", headers=viewer_headers)

    audit = client.get("/api/v1/audit?action=auth.access_denied", headers=auth_headers).json()
    assert audit["total"] >= 1
    entry = audit["items"][0]
    assert entry["targetId"].endswith("/audit")
    assert "audit:read" in entry["details"]["required"]


def test_me_reports_the_callers_permissions(client: TestClient, viewer_headers: dict) -> None:
    body = client.get("/api/v1/auth/me", headers=viewer_headers).json()
    assert body["role"] == "viewer"
    assert "events:read" in body["permissions"]
    assert "events:promote" not in body["permissions"]


# ------------------------------------------------------------ session security
def test_logout_all_revokes_existing_tokens(client: TestClient) -> None:
    headers = _headers_for(client, {"email": DEMO_EMAIL, "password": DEMO_PASSWORD})
    assert client.get("/api/v1/auth/me", headers=headers).status_code == 200

    assert client.post("/api/v1/auth/logout-all", headers=headers).status_code == 200

    revoked = client.get("/api/v1/auth/me", headers=headers)
    assert revoked.status_code == 401
    assert "revoked" in revoked.json()["detail"].lower()


def test_password_change_requires_the_current_password(
    client: TestClient, auth_headers: dict
) -> None:
    response = client.post(
        "/api/v1/auth/change-password",
        json={"currentPassword": "not-the-password", "newPassword": "BrandNewPassw0rd!"},
        headers=auth_headers,
    )
    assert response.status_code == 400
    assert "incorrect" in response.json()["detail"].lower()


def test_password_change_signs_every_session_out(client: TestClient) -> None:
    """A password change that leaves old sessions alive is not a password change."""
    credentials = {"email": "rotate.me@aegisx.dev", "password": "InitialPassw0rd!"}
    admin = _headers_for(client, {"email": DEMO_EMAIL, "password": DEMO_PASSWORD})
    _ensure_user(client, admin, credentials, "analyst")

    headers = _headers_for(client, credentials)
    changed = client.post(
        "/api/v1/auth/change-password",
        json={"currentPassword": credentials["password"], "newPassword": "RotatedPassw0rd!"},
        headers=headers,
    )
    assert changed.status_code == 200

    assert client.get("/api/v1/auth/me", headers=headers).status_code == 401
    assert (
        client.post(
            "/api/v1/auth/login",
            json={"email": credentials["email"], "password": "RotatedPassw0rd!"},
        ).status_code
        == 200
    )


# --------------------------------------------------------------------- headers
def test_security_headers_are_present(client: TestClient) -> None:
    headers = client.get("/api/v1/health").headers
    assert headers["X-Content-Type-Options"] == "nosniff"
    assert headers["X-Frame-Options"] == "DENY"
    assert headers["Referrer-Policy"] == "no-referrer"
    assert "frame-ancestors 'none'" in headers["Content-Security-Policy"]
    assert headers["Cache-Control"] == "no-store"


# ----------------------------------------------------------------- safe errors
def test_validation_errors_do_not_echo_the_submitted_password(client: TestClient) -> None:
    response = client.post(
        "/api/v1/auth/login", json={"email": "not-an-email", "password": "hunter2-secret"}
    )
    assert response.status_code == 422
    assert "hunter2-secret" not in response.text
    assert response.json()["errors"][0]["field"] == "email"


def test_unknown_routes_return_json_not_a_stack_trace(client: TestClient) -> None:
    response = client.get("/api/v1/does-not-exist")
    assert response.status_code == 404
    assert "Traceback" not in response.text


def test_oversized_bodies_are_rejected_before_parsing(client: TestClient, auth_headers: dict) -> None:
    payload = {"source": "Sysmon", "rawLog": "A" * 2_000_000}
    response = client.post("/api/v1/events", json=payload, headers=auth_headers)
    assert response.status_code == 413


# ----------------------------------------------------------------- rate limits
def _limited_app(limit: int) -> TestClient:
    """Small app with only the limiter, so the suite's own traffic is unaffected."""
    app = FastAPI()

    @app.get("/ping")
    def ping() -> PlainTextResponse:  # pragma: no cover - trivial
        return PlainTextResponse("pong")

    app.add_middleware(RateLimitMiddleware)
    return TestClient(app)


def test_rate_limiter_blocks_a_burst(monkeypatch) -> None:
    from app.core import middleware as middleware_module

    monkeypatch.setattr(middleware_module.settings, "rate_limit_enabled", True)
    monkeypatch.setattr(middleware_module.settings, "rate_limit_requests", 3)
    monkeypatch.setattr(middleware_module.settings, "rate_limit_window_seconds", 60)

    client = _limited_app(3)
    statuses = [client.get("/ping").status_code for _ in range(5)]

    assert statuses[:3] == [200, 200, 200]
    assert statuses[3:] == [429, 429]

    blocked = client.get("/ping")
    assert blocked.headers["Retry-After"]
    assert "Too many requests" in blocked.json()["detail"]


def test_rate_limiter_can_be_disabled(monkeypatch) -> None:
    from app.core import middleware as middleware_module

    monkeypatch.setattr(middleware_module.settings, "rate_limit_enabled", False)
    client = _limited_app(1)
    assert all(client.get("/ping").status_code == 200 for _ in range(5))
