"""Analytics aggregation reflects persisted data."""

from __future__ import annotations

from fastapi.testclient import TestClient

from app.tests.test_events import ingest


def test_summary_counts_match_the_event_list(client: TestClient, auth_headers: dict) -> None:
    ingest(client, auth_headers)

    summary = client.get("/api/v1/analytics/summary", headers=auth_headers).json()
    events = client.get("/api/v1/events?limit=1", headers=auth_headers).json()

    assert summary["totalEvents"] == events["total"]
    assert summary["highEvents"] >= 1
    assert summary["windowHours"] == 24


def test_severity_distribution_covers_every_level(client: TestClient, auth_headers: dict) -> None:
    summary = client.get("/api/v1/analytics/summary", headers=auth_headers).json()
    keys = [bucket["key"] for bucket in summary["eventsBySeverity"]]
    assert keys == ["Low", "Medium", "High", "Critical"]


def test_incident_counters_track_promotions(client: TestClient, auth_headers: dict) -> None:
    before = client.get("/api/v1/analytics/summary", headers=auth_headers).json()
    event = ingest(client, auth_headers)
    client.post(f"/api/v1/events/{event['id']}/promote", headers=auth_headers)
    after = client.get("/api/v1/analytics/summary", headers=auth_headers).json()

    assert after["totalIncidents"] == before["totalIncidents"] + 1
    assert after["openIncidents"] >= before["openIncidents"] + 1


def test_time_series_and_mitre_coverage_are_present(client: TestClient, auth_headers: dict) -> None:
    ingest(client, auth_headers)
    summary = client.get("/api/v1/analytics/summary?windowHours=6", headers=auth_headers).json()

    assert summary["windowHours"] == 6
    assert len(summary["eventsOverTime"]) == 7  # 6 hourly buckets plus the current hour
    assert sum(bucket["count"] for bucket in summary["eventsOverTime"]) >= 1
    assert any(bucket["key"].startswith("T1") for bucket in summary["mitreCoverage"])


def test_analyst_workload_is_reported(client: TestClient, auth_headers: dict) -> None:
    event = ingest(client, auth_headers)
    client.post(
        f"/api/v1/events/{event['id']}/promote",
        json={"analyst": "R. Anand"},
        headers=auth_headers,
    )
    summary = client.get("/api/v1/analytics/summary", headers=auth_headers).json()
    assert any(row["analyst"] == "R. Anand" for row in summary["analystWorkload"])
