"""Incident creation and the event -> incident promotion flow."""

from __future__ import annotations

from fastapi.testclient import TestClient

from app.tests.test_events import ingest


def test_promotion_creates_a_linked_incident(client: TestClient, auth_headers: dict) -> None:
    """The core V1 flow: event -> promote -> incident -> link -> audit -> notification."""
    event = ingest(client, auth_headers)

    response = client.post(f"/api/v1/events/{event['id']}/promote", headers=auth_headers)
    assert response.status_code == 201, response.text
    incident = response.json()

    assert incident["id"].startswith("INC-")
    assert incident["status"] == "Open"
    assert event["id"] in incident["eventIds"]
    assert incident["eventCount"] == 1
    assert incident["severity"] == event["severity"]

    # the event now points back at the incident
    refreshed = client.get(f"/api/v1/events/{event['id']}", headers=auth_headers).json()
    assert refreshed["incidentId"] == incident["id"]

    # and it shows up in the incident list the UI reads
    listed = client.get("/api/v1/incidents", headers=auth_headers).json()
    assert incident["id"] in [item["id"] for item in listed["items"]]


def test_promotion_is_audited(client: TestClient, auth_headers: dict) -> None:
    event = ingest(client, auth_headers)
    client.post(f"/api/v1/events/{event['id']}/promote", headers=auth_headers)

    audit = client.get(
        f"/api/v1/audit?action=event.promoted&targetId={event['id']}", headers=auth_headers
    ).json()
    assert audit["total"] == 1
    assert audit["items"][0]["details"]["incidentId"].startswith("INC-")


def test_promotion_raises_a_notification(client: TestClient, auth_headers: dict) -> None:
    event = ingest(client, auth_headers)
    incident = client.post(
        f"/api/v1/events/{event['id']}/promote", headers=auth_headers
    ).json()

    notifications = client.get("/api/v1/notifications?limit=10", headers=auth_headers).json()
    assert any(
        item["incidentId"] == incident["id"] and item["category"] == "incident"
        for item in notifications["items"]
    )


def test_an_event_cannot_be_promoted_twice(client: TestClient, auth_headers: dict) -> None:
    event = ingest(client, auth_headers)
    assert client.post(f"/api/v1/events/{event['id']}/promote", headers=auth_headers).status_code == 201

    second = client.post(f"/api/v1/events/{event['id']}/promote", headers=auth_headers)
    assert second.status_code == 409
    assert "already linked" in second.json()["detail"]


def test_promote_accepts_overrides(client: TestClient, auth_headers: dict) -> None:
    event = ingest(client, auth_headers)
    incident = client.post(
        f"/api/v1/events/{event['id']}/promote",
        json={"title": "Suspected hands-on-keyboard activity", "severity": "Critical",
              "analyst": "E. Davis"},
        headers=auth_headers,
    ).json()

    assert incident["title"] == "Suspected hands-on-keyboard activity"
    assert incident["severity"] == "Critical"
    assert incident["analyst"] == "E. Davis"


def test_incident_can_be_created_from_several_events(client: TestClient, auth_headers: dict) -> None:
    first = ingest(client, auth_headers)
    second = ingest(client, auth_headers, title="Second stage")

    incident = client.post(
        "/api/v1/incidents",
        json={
            "title": "Multi-stage intrusion",
            "description": "Two related detections on the same host.",
            "severity": "High",
            "eventIds": [first["id"], second["id"]],
        },
        headers=auth_headers,
    )
    assert incident.status_code == 201
    assert incident.json()["eventCount"] == 2


def test_creating_an_incident_with_unknown_events_fails(client: TestClient, auth_headers: dict) -> None:
    response = client.post(
        "/api/v1/incidents",
        json={"title": "Bogus", "eventIds": ["EVT-999999"]},
        headers=auth_headers,
    )
    assert response.status_code == 400


def test_status_change_is_recorded_on_the_timeline(client: TestClient, auth_headers: dict) -> None:
    event = ingest(client, auth_headers)
    incident = client.post(f"/api/v1/events/{event['id']}/promote", headers=auth_headers).json()

    # V9: this used to go straight to "Contained", which the lifecycle now
    # refuses - containment cannot be declared on an incident nobody has looked
    # at. The assertion is unchanged in substance: one status change, recorded
    # on the timeline and in the audit trail. The legal one-step move from
    # "Open" is "Investigating".
    updated = client.patch(
        f"/api/v1/incidents/{incident['id']}",
        json={"status": "Investigating"},
        headers=auth_headers,
    ).json()

    assert updated["status"] == "Investigating"
    assert any(entry["action"] == "status_changed" for entry in updated["timeline"])

    audit = client.get(
        f"/api/v1/audit?action=incident.status_changed&targetId={incident['id']}",
        headers=auth_headers,
    ).json()
    assert audit["total"] == 1


def test_response_action_is_recorded_but_not_executed(client: TestClient, auth_headers: dict) -> None:
    event = ingest(client, auth_headers)
    incident = client.post(f"/api/v1/events/{event['id']}/promote", headers=auth_headers).json()

    updated = client.post(
        f"/api/v1/incidents/{incident['id']}/response",
        json={"action": "Isolate host SYN-WIN-001"},
        headers=auth_headers,
    ).json()

    assert any(entry["action"] == "response_action" for entry in updated["timeline"])
