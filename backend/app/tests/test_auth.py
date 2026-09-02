"""Authentication behaviour."""

from __future__ import annotations

from fastapi.testclient import TestClient

from app.core.security import hash_password, verify_password
from app.tests.conftest import DEMO_EMAIL, DEMO_PASSWORD


def test_password_hash_is_not_reversible() -> None:
    encoded = hash_password("CorrectHorse1!")
    assert "CorrectHorse1!" not in encoded
    assert encoded.startswith("pbkdf2_sha256$")
    assert verify_password("CorrectHorse1!", encoded)
    assert not verify_password("wrong", encoded)


def test_hashes_are_salted() -> None:
    assert hash_password("SamePassword1") != hash_password("SamePassword1")


def test_login_returns_token_and_user(client: TestClient) -> None:
    response = client.post(
        "/api/v1/auth/login", json={"email": DEMO_EMAIL, "password": DEMO_PASSWORD}
    )
    assert response.status_code == 200
    body = response.json()
    assert body["tokenType"] == "bearer"
    assert body["user"]["email"] == DEMO_EMAIL
    assert "password" not in response.text.lower().replace("passwordexpired", "")


def test_login_rejects_bad_credentials(client: TestClient) -> None:
    response = client.post(
        "/api/v1/auth/login", json={"email": DEMO_EMAIL, "password": "not-the-password"}
    )
    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid email or password."


def test_login_does_not_disclose_unknown_accounts(client: TestClient) -> None:
    """Unknown user and wrong password must be indistinguishable."""
    unknown = client.post(
        "/api/v1/auth/login", json={"email": "nobody@aegisx.dev", "password": "whatever12"}
    )
    assert unknown.status_code == 401
    assert unknown.json()["detail"] == "Invalid email or password."


def test_protected_endpoints_require_a_token(client: TestClient) -> None:
    assert client.get("/api/v1/events").status_code == 401
    assert client.get("/api/v1/incidents").status_code == 401
    assert client.get("/api/v1/analytics/summary").status_code == 401


def test_me_returns_the_authenticated_user(client: TestClient, auth_headers: dict) -> None:
    body = client.get("/api/v1/auth/me", headers=auth_headers).json()
    assert body["email"] == DEMO_EMAIL
    assert "hashedPassword" not in body
