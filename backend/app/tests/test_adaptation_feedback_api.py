"""The analyst feedback API (V5 Phase B).

Feedback is the first V5 surface that *writes*, so the access rules matter more
than the payload shape: a viewer may read what analysts concluded and may not
add to it, and every submission leaves an audit row naming who made the claim.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

VIEWER_CREDENTIALS = {"email": "viewer.feedback@aegisx.dev", "password": "ViewerPassw0rd!"}


def _ensure_user(client: TestClient, admin_headers: dict, credentials: dict, role: str) -> None:
    client.post(
        "/api/v1/auth/users",
        json={
            "email": credentials["email"],
            "password": credentials["password"],
            "fullName": role.title(),
            "role": role,
        },
        headers=admin_headers,
    )


@pytest.fixture()
def viewer_headers(client: TestClient, auth_headers: dict) -> dict:
    _ensure_user(client, auth_headers, VIEWER_CREDENTIALS, "viewer")
    response = client.post("/api/v1/auth/login", json=VIEWER_CREDENTIALS)
    assert response.status_code == 200, response.text
    return {"Authorization": f"Bearer {response.json()['accessToken']}"}


def _an_event(client: TestClient, auth_headers: dict) -> str:
    """Ingest an event and return its public identifier.

    Feedback addresses events the way the rest of the API does - by the
    ``EVT-`` identifier an analyst can actually see - and resolves to the
    primary key internally.
    """
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
    response = client.post("/api/v1/events", json=payload, headers=auth_headers)
    assert response.status_code == 201, response.text
    return response.json()["id"]


class TestFeedbackPermissions:
    def test_an_analyst_may_submit_feedback(self, client: TestClient, auth_headers: dict) -> None:
        event_id = _an_event(client, auth_headers)

        response = client.post(
            "/api/v1/adaptation/feedback",
            json={
                "targetType": "event",
                "targetId": event_id,
                "label": "false_positive",
                "confidence": 0.9,
                "comment": "Scheduled backup.",
            },
            headers=auth_headers,
        )

        assert response.status_code == 201, response.text
        body = response.json()
        assert body["label"] == "false_positive"
        assert body["analyst"]
        assert body["supersededById"] is None

    def test_a_viewer_may_read_feedback_but_not_submit_it(
        self, client: TestClient, auth_headers: dict, viewer_headers: dict
    ) -> None:
        event_id = _an_event(client, auth_headers)

        assert client.get("/api/v1/adaptation/feedback", headers=viewer_headers).status_code == 200

        denied = client.post(
            "/api/v1/adaptation/feedback",
            json={"targetType": "event", "targetId": event_id, "label": "benign"},
            headers=viewer_headers,
        )
        assert denied.status_code == 403

    def test_feedback_requires_authentication(self, client: TestClient) -> None:
        response = client.post(
            "/api/v1/adaptation/feedback",
            json={"targetType": "event", "targetId": "EVT-000001", "label": "benign"},
        )
        assert response.status_code == 401


class TestFeedbackValidation:
    def test_an_unknown_label_is_refused(self, client: TestClient, auth_headers: dict) -> None:
        event_id = _an_event(client, auth_headers)
        response = client.post(
            "/api/v1/adaptation/feedback",
            json={"targetType": "event", "targetId": event_id, "label": "probably_bad"},
            headers=auth_headers,
        )
        assert response.status_code == 422

    def test_feedback_on_a_nonexistent_event_is_refused(
        self, client: TestClient, auth_headers: dict
    ) -> None:
        """Otherwise the feedback table accumulates claims about nothing."""
        response = client.post(
            "/api/v1/adaptation/feedback",
            json={"targetType": "event", "targetId": "EVT-999999999", "label": "benign"},
            headers=auth_headers,
        )
        assert response.status_code == 404

    def test_a_malformed_mitre_technique_is_refused(
        self, client: TestClient, auth_headers: dict
    ) -> None:
        event_id = _an_event(client, auth_headers)
        response = client.post(
            "/api/v1/adaptation/feedback",
            json={
                "targetType": "event",
                "targetId": event_id,
                "label": "true_positive",
                "mitreTechniques": ["definitely-not-a-technique"],
            },
            headers=auth_headers,
        )
        assert response.status_code == 422


class TestFeedbackIsAudited:
    def test_submitting_feedback_writes_an_audit_row(
        self, client: TestClient, auth_headers: dict
    ) -> None:
        event_id = _an_event(client, auth_headers)

        created = client.post(
            "/api/v1/adaptation/feedback",
            json={"targetType": "event", "targetId": event_id, "label": "suspicious"},
            headers=auth_headers,
        )
        assert created.status_code == 201, created.text

        audit = client.get(
            "/api/v1/audit", params={"action": "adaptation.feedback_submitted"}, headers=auth_headers
        )
        assert audit.status_code == 200, audit.text
        actions = [entry["action"] for entry in audit.json()["items"]]
        assert "adaptation.feedback_submitted" in actions


class TestFeedbackCorrection:
    def test_a_correction_creates_a_new_row_and_keeps_the_original(
        self, client: TestClient, auth_headers: dict
    ) -> None:
        event_id = _an_event(client, auth_headers)
        original = client.post(
            "/api/v1/adaptation/feedback",
            json={"targetType": "event", "targetId": event_id, "label": "false_positive"},
            headers=auth_headers,
        ).json()

        correction = client.post(
            f"/api/v1/adaptation/feedback/{original['id']}/correct",
            json={"label": "true_positive", "reason": "Confirmed on host."},
            headers=auth_headers,
        )

        assert correction.status_code == 201, correction.text
        assert correction.json()["supersedesId"] == original["id"]

        refetched = client.get(
            f"/api/v1/adaptation/feedback/{original['id']}", headers=auth_headers
        )
        assert refetched.status_code == 200
        # The original claim is unchanged; only its currency pointer moved.
        assert refetched.json()["label"] == "false_positive"
        assert refetched.json()["supersededById"] == correction.json()["id"]


class TestNoTrainingOverHttp:
    def test_the_adaptation_router_exposes_no_training_endpoint(self) -> None:
        """Training is minutes of CPU. Over HTTP that is a denial-of-service
        primitive, which is why V4 refused to expose experiments and V5 refuses
        to expose training."""
        from app.main import app

        schema = app.openapi()
        adaptation_paths = [path for path in schema["paths"] if "/adaptation" in path]
        assert adaptation_paths, "the adaptation API should be mounted"
        forbidden = [
            path
            for path in adaptation_paths
            if "train" in path or "retrain" in path or "deploy" in path
        ]
        assert forbidden == [], f"adaptation exposes training/deployment over HTTP: {forbidden}"
