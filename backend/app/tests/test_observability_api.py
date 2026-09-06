"""The metrics endpoint, and what it must not give away.

A scrape target is usually less protected than the API it measures, and the
counters here describe how much security work an organisation is doing. Three
properties matter:

1. It requires a session. An open ``/metrics`` publishes request rates and
   incident volumes to anyone who can reach the port.
2. No series is keyed by a user, an incident, an account or an indicator. A
   metric is permanent; a counter per user would be a slow leak of who works
   here and what they touch.
3. Cardinality survives contact with hostile input. A flood of random paths
   must cost one series, not one apiece.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.tests.test_events import ingest

VIEWER_CREDENTIALS = {"email": "viewer.metrics@aegisx.dev", "password": "ViewerPassw0rd!"}


def _ensure_user(client: TestClient, admin_headers: dict, credentials: dict, role: str) -> None:
    response = client.post(
        "/api/v1/auth/users",
        json={
            "email": credentials["email"],
            "password": credentials["password"],
            "fullName": "Metrics Viewer",
            "role": role,
        },
        headers=admin_headers,
    )
    assert response.status_code in (201, 409), response.text


@pytest.fixture()
def viewer_headers(client: TestClient, auth_headers: dict) -> dict:
    _ensure_user(client, auth_headers, VIEWER_CREDENTIALS, "viewer")
    response = client.post("/api/v1/auth/login", json=VIEWER_CREDENTIALS)
    assert response.status_code == 200, response.text
    return {"Authorization": f"Bearer {response.json()['accessToken']}"}


def _scrape(client: TestClient, headers: dict) -> str:
    response = client.get("/api/v1/metrics", headers=headers)
    assert response.status_code == 200, response.text
    return response.text


class TestAccess:
    def test_it_is_not_public(self, client: TestClient) -> None:
        """Request rates and incident volumes describe an organisation's
        security posture to anyone who can reach the port."""
        assert client.get("/api/v1/metrics").status_code == 401

    def test_a_viewer_may_scrape(self, client: TestClient, viewer_headers: dict) -> None:
        assert client.get("/api/v1/metrics", headers=viewer_headers).status_code == 200

    def test_it_is_served_as_prometheus_text(
        self, client: TestClient, auth_headers: dict
    ) -> None:
        response = client.get("/api/v1/metrics", headers=auth_headers)
        assert response.headers["content-type"].startswith("text/plain")
        assert "version=0.0.4" in response.headers["content-type"]


class TestWhatIsMeasured:
    def test_requests_are_counted_by_route_template(
        self, client: TestClient, auth_headers: dict
    ) -> None:
        client.get("/api/v1/incidents", headers=auth_headers)
        body = _scrape(client, auth_headers)

        assert "# TYPE aegisx_http_requests_total counter" in body
        assert 'route="/api/v1/incidents"' in body

    def test_a_path_parameter_does_not_become_its_own_series(
        self, client: TestClient, auth_headers: dict
    ) -> None:
        """The cardinality bug this whole design is arranged against."""
        event = ingest(client, auth_headers)
        incident = client.post(
            f"/api/v1/events/{event['id']}/promote", headers=auth_headers
        ).json()
        client.get(f"/api/v1/incidents/{incident['id']}", headers=auth_headers)

        body = _scrape(client, auth_headers)
        assert 'route="/api/v1/incidents/{incident_id}"' in body
        assert incident["id"] not in body

    def test_latency_is_recorded_as_a_histogram(
        self, client: TestClient, auth_headers: dict
    ) -> None:
        client.get("/api/v1/incidents", headers=auth_headers)
        body = _scrape(client, auth_headers)

        assert "# TYPE aegisx_http_request_duration_seconds histogram" in body
        assert "aegisx_http_request_duration_seconds_bucket" in body
        assert 'le="+Inf"' in body

    def test_ingestion_is_counted(self, client: TestClient, auth_headers: dict) -> None:
        ingest(client, auth_headers)
        body = _scrape(client, auth_headers)
        assert "aegisx_events_ingested_total" in body
        assert 'source_type="endpoint"' in body

    def test_a_lifecycle_transition_is_counted(
        self, client: TestClient, auth_headers: dict
    ) -> None:
        event = ingest(client, auth_headers)
        incident = client.post(
            f"/api/v1/events/{event['id']}/promote", headers=auth_headers
        ).json()
        client.patch(
            f"/api/v1/incidents/{incident['id']}",
            json={"status": "Investigating"},
            headers=auth_headers,
        )

        body = _scrape(client, auth_headers)
        assert 'aegisx_incident_transitions_total{target="Investigating"}' in body

    def test_the_status_class_is_recorded_rather_than_the_code(
        self, client: TestClient, auth_headers: dict
    ) -> None:
        """404 and 403 differ in the logs, which expire. A metric is forever
        and the distinction has never been worth a permanent series."""
        client.get("/api/v1/incidents/INC-NOPE", headers=auth_headers)
        body = _scrape(client, auth_headers)

        assert 'status="4xx"' in body
        assert 'status="404"' not in body


class TestWhatIsNotMeasured:
    def test_no_series_is_keyed_by_a_user(
        self, client: TestClient, auth_headers: dict
    ) -> None:
        body = _scrape(client, auth_headers)
        assert "admin@aegisx.dev" not in body
        assert "username" not in body
        assert 'user="' not in body

    def test_no_series_is_keyed_by_an_incident_or_event(
        self, client: TestClient, auth_headers: dict
    ) -> None:
        event = ingest(client, auth_headers)
        incident = client.post(
            f"/api/v1/events/{event['id']}/promote", headers=auth_headers
        ).json()
        client.get(f"/api/v1/incidents/{incident['id']}", headers=auth_headers)

        body = _scrape(client, auth_headers)
        assert incident["id"] not in body
        assert event["id"] not in body

    def test_the_scrape_carries_no_secret(
        self, client: TestClient, auth_headers: dict
    ) -> None:
        """Secret-shaped *values*, not words.

        A first cut of this forbade the substring "password", which fails the
        moment anything exercises `/api/v1/auth/change-password` - a route
        template containing that word is not a leak, and a test that cannot
        tell the difference would be removed by the first person it annoyed.
        """
        body = _scrape(client, auth_headers)

        assert "eyJ" not in body, "a JWT reached a label"
        assert "://" not in body, "a connection string or URL reached a label"
        assert "@" not in body, "an email address reached a label"
        # Every label name is one of the declared few.
        import re

        names = set(re.findall(r'([a-z_]+)="', body))
        assert names <= {"route", "method", "status", "source_type", "target",
                         "outcome", "verdict", "le"}, names


class TestCardinalityUnderAbuse:
    def test_a_flood_of_unmatched_paths_costs_one_series(
        self, client: TestClient, auth_headers: dict
    ) -> None:
        """The cheapest denial of service against a metrics endpoint is to
        request a thousand paths that match nothing. They must all collapse
        into a single `unmatched` series."""
        for index in range(60):
            client.get(f"/api/v1/no-such-route-{index}", headers=auth_headers)

        body = _scrape(client, auth_headers)
        assert 'route="unmatched"' in body
        assert "no-such-route-7" not in body

        routes = [line for line in body.splitlines() if line.startswith("aegisx_http_requests_total{")]
        unmatched = [line for line in routes if 'route="unmatched"' in line]
        # One series per method/status class, not one per path.
        assert len(unmatched) <= 4, unmatched

    def test_the_registry_reports_its_own_ceiling(
        self, client: TestClient, auth_headers: dict
    ) -> None:
        """If an unbounded label ever does reach an instrument, the drop is
        visible in the scrape rather than silent."""
        body = _scrape(client, auth_headers)
        assert "aegisx_metrics_series_dropped" in body


class TestTheScrapeIsQuiet:
    def test_scraping_does_not_log_a_line_per_scrape(
        self, client: TestClient, auth_headers: dict, caplog
    ) -> None:
        """A scrape every fifteen seconds would otherwise be a log line every
        fifteen seconds, forever."""
        import logging

        with caplog.at_level(logging.INFO, logger="app.core.middleware"):
            client.get("/api/v1/metrics", headers=auth_headers)

        assert not [
            record
            for record in caplog.records
            if record.getMessage() == "request completed"
        ]
