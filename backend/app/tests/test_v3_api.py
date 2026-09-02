"""V3 API surface: routes, RBAC and degraded behaviour.

The recurring assertion in this module is that an unavailable subsystem is
*reported*, not hidden. An empty ML panel, an empty threat-intelligence panel
and an unavailable AI analyst must each carry a reason, because "no anomalies
found" and "no model is running" look identical to a user otherwise.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from app.core.database import SessionLocal
from app.core.rbac import Permission, permissions_for
from app.models.enums import UserRole
from app.models.user import User
from app.schemas.user import UserCreate
from app.services import auth_service

VIEWER = {"email": "v3.viewer@aegisx.dev", "password": "ViewerPassw0rd!", "role": "viewer"}
ANALYST = {"email": "v3.analyst@aegisx.dev", "password": "AnalystPassw0rd!", "role": "analyst"}
ADMIN = {"email": "v3.admin@aegisx.dev", "password": "AdminPassw0rd!", "role": "admin"}


def _ensure_user(spec: dict) -> None:
    with SessionLocal() as db:
        existing = db.scalar(select(User).where(User.email == spec["email"]))
        if existing is None:
            auth_service.create_user(
                db,
                UserCreate(
                    email=spec["email"],
                    password=spec["password"],
                    full_name=spec["email"],
                    role=UserRole(spec["role"]),
                ),
            )
            db.commit()


def headers_for(client: TestClient, spec: dict) -> dict[str, str]:
    _ensure_user(spec)
    response = client.post(
        "/api/v1/auth/login", json={"email": spec["email"], "password": spec["password"]}
    )
    assert response.status_code == 200, response.text
    return {"Authorization": f"Bearer {response.json()['accessToken']}"}


@pytest.fixture()
def viewer(client: TestClient) -> dict[str, str]:
    return headers_for(client, VIEWER)


@pytest.fixture()
def analyst(client: TestClient) -> dict[str, str]:
    return headers_for(client, ANALYST)


@pytest.fixture()
def admin(client: TestClient) -> dict[str, str]:
    return headers_for(client, ADMIN)


# ------------------------------------------------------------------- ML routes
def test_ml_status_explains_why_no_model_is_running(client, auth_headers) -> None:
    response = client.get("/api/v1/ml/status", headers=auth_headers)
    assert response.status_code == 200

    body = response.json()
    assert body["available"] is False
    # The central honesty requirement: an empty ML panel always says why.
    assert body["reason"]
    assert "train" in body["reason"].lower()


def test_feature_schema_is_published(client, auth_headers) -> None:
    body = client.get("/api/v1/ml/features", headers=auth_headers).json()
    assert body["featureCount"] == len(body["features"])
    assert body["featureSchemaVersion"]
    assert any("training/serving skew" in note for note in body["notes"])


def test_scoring_weights_are_published(client, auth_headers) -> None:
    """A risk score whose weights are private is not explainable."""
    body = client.get("/api/v1/ml/scoring", headers=auth_headers).json()
    assert body["weights"]["mlMaxContribution"] < body["bands"]["high"]
    assert body["version"]


def test_ml_findings_for_an_event_distinguish_unscored_from_normal(
    client, auth_headers
) -> None:
    ingest = client.post(
        "/api/v1/events",
        headers=auth_headers,
        json={
            "source": "Sysmon",
            "sourceType": "endpoint",
            "eventType": "process_creation",
            "title": "ML lookup event",
            "severity": "Low",
        },
    )
    assert ingest.status_code == 201
    event_id = ingest.json()["id"]

    body = client.get(f"/api/v1/ml/events/{event_id}", headers=auth_headers).json()
    assert body["eventId"] == event_id
    assert body["modelAvailable"] is False
    assert body["reason"]
    assert body["findings"] == []
    assert "riskSignals" in body


def test_ml_routes_reject_an_unknown_event(client, auth_headers) -> None:
    assert client.get("/api/v1/ml/events/EVT-999999", headers=auth_headers).status_code == 404


def test_registry_summary_hints_at_the_training_command(client, auth_headers) -> None:
    body = client.get("/api/v1/ml/registry/summary", headers=auth_headers).json()
    assert body["trainingCommand"].startswith("python -m app.ml.training")


# ---------------------------------------------------------------- ML RBAC
def test_viewer_can_read_ml_but_not_manage_models(client, viewer) -> None:
    assert client.get("/api/v1/ml/status", headers=viewer).status_code == 200
    assert client.get("/api/v1/ml/models", headers=viewer).status_code == 200
    # Deploying a model changes what the whole platform detects.
    assert client.post("/api/v1/ml/models/1/activate", headers=viewer).status_code == 403


def test_analyst_cannot_deploy_a_model(client, analyst) -> None:
    """Explicitly required: ordinary analysts must not deploy models."""
    assert client.post("/api/v1/ml/models/1/activate", headers=analyst).status_code == 403
    assert client.post("/api/v1/ml/models/rollback", headers=analyst).status_code == 403


def test_admin_reaches_model_management_and_gets_a_real_404(client, admin) -> None:
    """403 would mean 'not allowed'; 404 means 'allowed, but no such model'."""
    assert client.post("/api/v1/ml/models/999999/activate", headers=admin).status_code == 404


def test_permission_matrix_advertises_the_v3_permissions(client, auth_headers) -> None:
    matrix = client.get("/api/v1/auth/permissions", headers=auth_headers).json()
    assert "ml:read" in matrix["viewer"]
    assert "ml:manage" not in matrix["viewer"]
    assert "ml:manage" not in matrix["analyst"]
    assert "ml:manage" in matrix["admin"]
    assert "ai:request" in matrix["analyst"]
    assert "ai:request" not in matrix["viewer"]
    assert "threatintel:enrich" not in matrix["viewer"]


def test_role_permissions_are_strictly_nested() -> None:
    assert permissions_for("viewer") < permissions_for("analyst")
    assert permissions_for("analyst") < permissions_for("admin")
    assert Permission.ML_MANAGE in permissions_for("admin")
    assert Permission.ML_MANAGE not in permissions_for("analyst")


# ------------------------------------------------------------ threat intel
def test_threat_intel_status_reports_configuration_and_no_key(client, auth_headers) -> None:
    body = client.get("/api/v1/threat-intel/status", headers=auth_headers).json()
    assert body["provider"] == "none"
    assert body["configured"] is False
    assert "apiKey" not in body
    assert "budget" in body


def test_threat_intel_refuses_an_internal_address(client, analyst) -> None:
    response = client.post(
        "/api/v1/threat-intel/ioc/10.0.0.5/enrich", headers=analyst, params={"type": "ip"}
    )
    assert response.status_code == 400
    assert "private" in response.json()["detail"].lower()


def test_threat_intel_refuses_the_cloud_metadata_address(client, analyst) -> None:
    """The SSRF case worth naming explicitly."""
    response = client.post(
        "/api/v1/threat-intel/ioc/169.254.169.254/enrich",
        headers=analyst,
        params={"type": "ip"},
    )
    assert response.status_code == 400


def test_viewer_cannot_trigger_an_outbound_lookup(client, viewer) -> None:
    response = client.post(
        "/api/v1/threat-intel/ioc/8.8.8.8/enrich", headers=viewer, params={"type": "ip"}
    )
    assert response.status_code == 403


def test_unknown_indicator_returns_404_not_a_clean_verdict(client, auth_headers) -> None:
    response = client.get("/api/v1/threat-intel/ioc/8.8.4.4", headers=auth_headers,
                          params={"type": "ip"})
    assert response.status_code == 404
    assert "Trigger enrichment" in response.json()["detail"]


def test_reading_an_out_of_scope_indicator_explains_rather_than_erroring(
    client, auth_headers
) -> None:
    """Reading is not an action. An indicator AEGISX will never send externally
    is an answer, not a client error - and returning 400 made the investigation
    UI fire a request per indicator that it knew would be refused."""
    response = client.get(
        "/api/v1/threat-intel/ioc/203.0.113.9", headers=auth_headers, params={"type": "ip"}
    )
    assert response.status_code == 200
    body = response.json()
    assert body["results"] == []
    assert "documentation range" in body["notLookedUp"]


def test_enriching_an_out_of_scope_indicator_is_still_refused(client, analyst) -> None:
    """Actively asking to send one outward is a different matter."""
    response = client.post(
        "/api/v1/threat-intel/ioc/203.0.113.9/enrich", headers=analyst, params={"type": "ip"}
    )
    assert response.status_code == 400


# ---------------------------------------------------------------- sequences
def test_sequences_list_is_empty_but_well_formed(client, auth_headers) -> None:
    body = client.get("/api/v1/sequences", headers=auth_headers).json()
    assert body["items"] == [] or isinstance(body["items"], list)
    assert set(body) >= {"items", "total", "limit", "offset"}


def test_correlation_patterns_declare_inferred_techniques(client, auth_headers) -> None:
    body = client.get("/api/v1/sequences/patterns", headers=auth_headers).json()
    assert len(body["patterns"]) >= 4
    lateral = next(p for p in body["patterns"] if p["id"] == "COR-LAT-001")
    assert "T1021" in lateral["inferredTechniques"]
    assert body["engine"]["windowMinutes"] > 0


def test_unknown_sequence_is_404(client, auth_headers) -> None:
    assert client.get("/api/v1/sequences/SEQ-999999", headers=auth_headers).status_code == 404


# ----------------------------------------------------------------------- AI
def test_ai_status_reports_the_provider_and_whether_data_leaves(client, auth_headers) -> None:
    body = client.get("/api/v1/ai/status", headers=auth_headers).json()
    assert body["provider"] == "mock"
    assert body["available"] is True
    # The UI must be able to tell a template answer from a model answer.
    assert body["isTemplateProvider"] is True
    assert body["sendsDataExternally"] is False
    assert body["promptVersion"]


def test_ai_analysis_runs_end_to_end_and_is_grounded(client, auth_headers) -> None:
    ingest = client.post(
        "/api/v1/events",
        headers=auth_headers,
        json={
            "source": "Sysmon",
            "sourceType": "endpoint",
            "eventType": "process_creation",
            "title": "Encoded PowerShell",
            "severity": "High",
            "hostname": "SYN-WIN-900",
            "username": "ai.user",
            "process": "powershell.exe",
            "commandLine": "powershell.exe -enc SQBuAHYAbwBrAGUALQBXAGUAYgBSAGUAcQB1AGUAcwB0AA==",
        },
    )
    assert ingest.status_code == 201
    event_id = ingest.json()["id"]

    promoted = client.post(f"/api/v1/events/{event_id}/promote", headers=auth_headers)
    assert promoted.status_code == 201
    incident_id = promoted.json()["id"]

    response = client.post(
        f"/api/v1/ai/incidents/{incident_id}/analyze", headers=auth_headers, json={}
    )
    assert response.status_code == 200, response.text

    analysis = response.json()
    assert analysis["generatedBy"] == "ai"
    assert analysis["grounded"] is True
    assert analysis["groundingWarnings"] == []
    assert analysis["summary"]
    assert "AI-generated" in analysis["disclaimer"]
    # Every citation resolves to something in the incident.
    for entry in analysis["supportingEvidence"]:
        assert entry["evidenceRef"]

    # And it is retrievable afterwards.
    stored = client.get(
        f"/api/v1/ai/incidents/{incident_id}/analyses", headers=auth_headers
    ).json()
    assert stored["total"] >= 1


def test_ai_evidence_preview_shows_what_the_model_would_see(client, auth_headers) -> None:
    """An AI answer whose inputs are hidden is not reviewable."""
    incidents = client.get("/api/v1/incidents", headers=auth_headers).json()["items"]
    assert incidents, "the previous test should have created an incident"
    incident_id = incidents[0]["id"]

    body = client.get(
        f"/api/v1/ai/incidents/{incident_id}/evidence", headers=auth_headers
    ).json()
    assert body["fingerprint"]
    assert "package" in body
    assert "injectionAttemptsDetected" in body


def test_viewer_can_read_ai_analyses_but_not_request_one(client, viewer) -> None:
    incidents = client.get("/api/v1/incidents", headers=viewer).json()["items"]
    incident_id = incidents[0]["id"]

    assert (
        client.get(f"/api/v1/ai/incidents/{incident_id}/analyses", headers=viewer).status_code
        == 200
    )
    # Requesting spends money and, with a hosted provider, sends data outward.
    assert (
        client.post(f"/api/v1/ai/incidents/{incident_id}/analyze", headers=viewer, json={}).status_code
        == 403
    )


def test_ai_on_an_unknown_incident_is_404(client, auth_headers) -> None:
    response = client.post(
        "/api/v1/ai/incidents/INC-999999/analyze", headers=auth_headers, json={}
    )
    assert response.status_code == 404


def test_an_over_long_question_is_rejected_by_validation(client, auth_headers) -> None:
    incidents = client.get("/api/v1/incidents", headers=auth_headers).json()["items"]
    incident_id = incidents[0]["id"]
    response = client.post(
        f"/api/v1/ai/incidents/{incident_id}/analyze",
        headers=auth_headers,
        json={"question": "Q" * 5_000},
    )
    assert response.status_code == 422


# ---------------------------------------------------------------- analytics
def test_analytics_reports_ml_state_rather_than_omitting_it(client, auth_headers) -> None:
    body = client.get("/api/v1/analytics/summary", headers=auth_headers).json()

    assert body["ml"] is not None
    assert body["ml"]["modelAvailable"] is False
    assert body["ml"]["reason"]
    # Zero anomalies with no model is "not measured", never "nothing found".
    assert body["ml"]["anomaliesDetected"] == 0
    assert body["ml"]["anomalyRate"] is None

    assert body["correlation"] is not None
    assert body["threatIntel"]["provider"] == "none"

    # V2 analytics keep working unchanged.
    assert "totalEvents" in body
    assert body["eventsBySeverity"]


# ------------------------------------------------------------------- health
def test_health_treats_ml_and_ai_as_optional(client, auth_headers) -> None:
    """The SOC is ready without a model, without an AI provider and without
    threat intelligence."""
    ready = client.get("/api/v1/health/ready")
    assert ready.status_code == 200
    assert ready.json()["status"] in {"healthy", "degraded"}

    system = client.get("/api/v1/health/system", headers=auth_headers).json()
    assert system["ml"]["status"] == "degraded"
    assert system["ml"]["reason"]
    assert system["threatIntel"]["status"] == "degraded"
    # Overall status ignores the optional subsystems.
    assert system["status"] != "unavailable"


def test_ml_health_endpoint_is_never_unavailable_without_a_model(client, auth_headers) -> None:
    body = client.get("/api/v1/health/ml", headers=auth_headers).json()
    assert body["status"] == "degraded"
    assert body["available"] is False


def test_enrichment_health_reports_queue_state(client, auth_headers) -> None:
    body = client.get("/api/v1/health/enrichment", headers=auth_headers).json()
    assert "queueDepth" in body
    assert "dropped" in body


# ------------------------------------------------------- events carry V3 fields
def test_events_expose_the_risk_breakdown(client, auth_headers) -> None:
    body = client.get("/api/v1/events", headers=auth_headers, params={"limit": 5}).json()
    assert body["items"]
    event = body["items"][0]
    assert "riskSignals" in event
    assert "riskLevel" in event
    assert "mlFindings" in event
    # V2 fields are untouched.
    assert "detections" in event
    assert "detectionRules" in event


def test_events_can_be_filtered_to_anomalies(client, auth_headers) -> None:
    response = client.get(
        "/api/v1/events", headers=auth_headers, params={"isAnomaly": True, "limit": 5}
    )
    assert response.status_code == 200
    assert response.json()["items"] == []  # no model has scored anything yet


def test_incidents_expose_sequences_and_analyses(client, auth_headers) -> None:
    incidents = client.get("/api/v1/incidents", headers=auth_headers).json()["items"]
    assert incidents
    incident = incidents[0]
    assert "sequences" in incident
    assert "aiAnalyses" in incident
    assert "riskSignals" in incident
    assert "mlAnomalyCount" in incident


def test_incident_risk_score_agrees_with_its_own_breakdown(client, auth_headers) -> None:
    """The number and the reasons underneath it must add up.

    Before this was enforced, an incident promoted from a sequence took its
    score from the highest member event and its signal list from the sequence,
    so the panel showed a score the breakdown could not explain.
    """
    ingest = client.post(
        "/api/v1/events",
        headers=auth_headers,
        json={
            "source": "Entra ID",
            "sourceType": "identity",
            "eventType": "auth_failure",
            "title": "Risk agreement event",
            "severity": "Medium",
            "username": "risk.agreement",
            "sourceIp": "203.0.113.99",
        },
    )
    assert ingest.status_code == 201
    promoted = client.post(
        f"/api/v1/events/{ingest.json()['id']}/promote", headers=auth_headers
    )
    assert promoted.status_code == 201

    incident = promoted.json()
    total = sum(signal["contribution"] for signal in incident["riskSignals"])
    if incident["riskSignals"]:
        assert incident["riskScore"] == min(total, 100)
