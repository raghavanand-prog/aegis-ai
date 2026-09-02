"""Event API behaviour."""

from __future__ import annotations

from fastapi.testclient import TestClient


def ingest(client: TestClient, headers: dict, **overrides) -> dict:
    payload = {
        "source": "Sysmon",
        "sourceType": "endpoint",
        "eventType": "process_creation",
        "title": "Process created: powershell.exe",
        "description": "Encoded PowerShell launched from Word.",
        "severity": "Low",
        "hostname": "SYN-WIN-001",
        "username": "j.smith",
        "process": "powershell.exe",
        "commandLine": "powershell.exe -nop -w hidden -enc " + "Q" * 64,
        "rawLog": "[Sysmon:1] SYN-WIN-001 encoded PowerShell",
        "normalizedData": {"parent_image": "winword.exe"},
    }
    payload.update(overrides)
    response = client.post("/api/v1/events", json=payload, headers=headers)
    assert response.status_code == 201, response.text
    return response.json()


def test_ingested_event_gets_a_readable_id(client: TestClient, auth_headers: dict) -> None:
    event = ingest(client, auth_headers)
    assert event["id"].startswith("EVT-")
    assert event["status"] == "New"


def test_detection_runs_on_ingest(client: TestClient, auth_headers: dict) -> None:
    """Severity is decided by the detection engine, not by the submitter."""
    event = ingest(client, auth_headers, severity="Low")
    assert event["severity"] == "High"
    assert event["riskScore"] > 0
    assert "DET-PS-001" in event["detectionRules"]
    assert "T1059.001" in event["mitreTechniques"]

    # V2: the stored event carries the explanation, not just the rule id.
    detection = next(d for d in event["detections"] if d["ruleId"] == "DET-PS-001")
    assert detection["ruleVersion"] == "1.0"
    assert detection["ruleName"] == "Suspicious PowerShell"
    assert "encoded" in detection["reason"].lower()
    assert detection["riskContribution"] == 50


def test_events_can_be_filtered_and_searched(client: TestClient, auth_headers: dict) -> None:
    ingest(client, auth_headers, title="Firewall deny burst", source="Perimeter Firewall",
           sourceType="firewall", eventType="firewall_deny", commandLine=None,
           normalizedData={"distinct_ports": 44})

    by_severity = client.get("/api/v1/events?severity=Medium", headers=auth_headers).json()
    assert all(item["severity"] == "Medium" for item in by_severity["items"])

    searched = client.get("/api/v1/events?search=firewall", headers=auth_headers).json()
    assert searched["total"] >= 1
    assert any("Firewall" in item["title"] or item["source"] == "Perimeter Firewall"
               for item in searched["items"])


def test_pagination_envelope(client: TestClient, auth_headers: dict) -> None:
    body = client.get("/api/v1/events?limit=2&offset=0", headers=auth_headers).json()
    assert set(body) == {"items", "total", "limit", "offset"}
    assert len(body["items"]) <= 2


def test_get_event_by_id_and_missing_event(client: TestClient, auth_headers: dict) -> None:
    event = ingest(client, auth_headers)
    found = client.get(f"/api/v1/events/{event['id']}", headers=auth_headers)
    assert found.status_code == 200
    assert found.json()["id"] == event["id"]

    assert client.get("/api/v1/events/EVT-999999", headers=auth_headers).status_code == 404


def test_viewing_an_event_is_audited(client: TestClient, auth_headers: dict) -> None:
    event = ingest(client, auth_headers)
    client.get(f"/api/v1/events/{event['id']}", headers=auth_headers)

    audit = client.get(
        f"/api/v1/audit?action=event.viewed&targetId={event['id']}", headers=auth_headers
    ).json()
    assert audit["total"] >= 1
    assert audit["items"][0]["targetId"] == event["id"]


def test_event_status_can_be_updated(client: TestClient, auth_headers: dict) -> None:
    event = ingest(client, auth_headers)
    updated = client.patch(
        f"/api/v1/events/{event['id']}/status",
        json={"status": "Investigating"},
        headers=auth_headers,
    )
    assert updated.status_code == 200
    assert updated.json()["status"] == "Investigating"


def test_high_severity_event_raises_a_notification(client: TestClient, auth_headers: dict) -> None:
    before = client.get("/api/v1/notifications/counts", headers=auth_headers).json()["total"]
    ingest(client, auth_headers)
    after = client.get("/api/v1/notifications/counts", headers=auth_headers).json()["total"]
    assert after > before


def test_iocs_are_extracted_from_telemetry(client: TestClient, auth_headers: dict) -> None:
    ingest(
        client,
        auth_headers,
        source="Entra ID",
        sourceType="identity",
        eventType="auth_failure",
        title="Failed sign-ins",
        commandLine=None,
        normalizedData={"failure_count": 30},
        iocs=["203.0.113.55"],
    )
    body = client.get("/api/v1/iocs?search=203.0.113.55", headers=auth_headers).json()
    assert body["total"] >= 1
