"""Test fixtures.

The suite runs against a throwaway SQLite database and with the telemetry
collector disabled, so tests are deterministic and never touch PostgreSQL.
Environment variables are set before the application is imported because
settings are read once at import time.
"""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

import pytest

TEST_DB = Path(tempfile.gettempdir()) / "aegisx_test.db"
if TEST_DB.exists():
    TEST_DB.unlink()

os.environ.update(
    {
        "ENVIRONMENT": "test",
        "DEBUG": "false",
        "DATABASE_URL": f"sqlite:///{TEST_DB}",
        "JWT_SECRET_KEY": "test-secret-key-not-used-anywhere-else-0123456789",
        "TELEMETRY_ENABLED": "false",
        "WS_REQUIRE_AUTH": "true",
        # Rate limiting is verified deliberately in test_security.py; leaving it
        # on here would throttle the suite's own login calls.
        "RATE_LIMIT_ENABLED": "false",
        "EVALUATION_REPORTS_DIR": str(Path(tempfile.gettempdir()) / "aegisx_test_reports"),
        "LOG_FORMAT": "console",
        "LOG_LEVEL": "WARNING",
        "SEED_DEMO_USER": "true",
        "DEMO_USER_EMAIL": "analyst@aegisx.dev",
        "DEMO_USER_PASSWORD": "TestPassw0rd!",
        "DEMO_USER_NAME": "Test Analyst",
    }
)

from fastapi.testclient import TestClient  # noqa: E402

from app.core.database import SessionLocal, get_engine  # noqa: E402
from app.main import app  # noqa: E402
from app.models.base import Base  # noqa: E402

DEMO_EMAIL = os.environ["DEMO_USER_EMAIL"]
DEMO_PASSWORD = os.environ["DEMO_USER_PASSWORD"]


@pytest.fixture(scope="session", autouse=True)
def _database() -> None:
    engine = get_engine()
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    yield
    Base.metadata.drop_all(bind=engine)


@pytest.fixture()
def client() -> TestClient:
    """Test client with the application lifespan running (binds the WS loop)."""
    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture()
def db():
    session = SessionLocal()
    try:
        yield session
    finally:
        session.rollback()
        session.close()


@pytest.fixture()
def token(client: TestClient) -> str:
    response = client.post(
        "/api/v1/auth/login", json={"email": DEMO_EMAIL, "password": DEMO_PASSWORD}
    )
    assert response.status_code == 200, response.text
    return response.json()["accessToken"]


@pytest.fixture()
def auth_headers(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}
