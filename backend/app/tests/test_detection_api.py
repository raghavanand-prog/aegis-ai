"""Detection transparency API: rule catalogue and measured quality."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.evaluation.reports import store


@pytest.fixture()
def empty_reports(tmp_path, monkeypatch):
    """Point the report store at an empty directory for this test."""
    monkeypatch.setattr(store.settings, "evaluation_reports_dir", str(tmp_path))
    return tmp_path


def test_rule_catalogue_requires_authentication(client: TestClient) -> None:
    assert client.get("/api/v1/detection/rules").status_code == 401


def test_rule_catalogue_exposes_ids_versions_and_mitre(
    client: TestClient, auth_headers: dict
) -> None:
    body = client.get("/api/v1/detection/rules", headers=auth_headers).json()

    assert body["engine"] == "deterministic-rules"
    assert body["usesMachineLearning"] is False
    assert body["ruleCount"] == len(body["rules"]) == 12
    assert body["rulesetFingerprint"]

    powershell = next(rule for rule in body["rules"] if rule["id"] == "DET-PS-001")
    assert powershell["version"] == "1.0"
    assert powershell["legacyId"] == "AEGIS-R002"
    assert powershell["severity"] == "High"
    assert powershell["riskContribution"] == 50
    assert "T1059.001" in powershell["mitreTechniques"]


def test_quality_endpoint_is_honest_when_nothing_has_been_measured(
    client: TestClient, auth_headers: dict, empty_reports
) -> None:
    """No evaluation run means no numbers - not zeros, not last week's."""
    response = client.get("/api/v1/detection/quality", headers=auth_headers)

    assert response.status_code == 404
    assert "run_detection_eval" in response.json()["detail"]


def test_running_an_evaluation_produces_measurable_metrics(
    client: TestClient, auth_headers: dict, empty_reports
) -> None:
    response = client.post(
        "/api/v1/detection/quality/run?samplesPerClass=10", headers=auth_headers
    )
    assert response.status_code == 200
    report = response.json()

    overall = report["overall"]
    for metric in (
        "precision",
        "recall",
        "f1",
        "falsePositiveRate",
        "falseNegativeRate",
        "truePositives",
        "falsePositives",
        "trueNegatives",
        "falseNegatives",
    ):
        assert overall[metric] is not None, f"{metric} must be measurable"

    assert 0.0 <= overall["precision"] <= 1.0
    assert 0.0 <= overall["recall"] <= 1.0
    assert report["engine"]["type"] == "deterministic-rules"
    assert report["latency"]["meanMs"] >= 0
    assert report["volume"]["eventsProcessed"] > 0
    assert report["stale"] is False


def test_quality_report_is_served_after_a_run(
    client: TestClient, auth_headers: dict, empty_reports
) -> None:
    client.post("/api/v1/detection/quality/run?samplesPerClass=5", headers=auth_headers)

    body = client.get("/api/v1/detection/quality", headers=auth_headers).json()
    assert body["schemaVersion"] == "1.0"
    assert body["perClass"]
    assert body["perRule"]
    assert body["coverage"]["uncoveredLabels"] == ["LATERAL_MOVEMENT"]


def test_running_an_evaluation_is_audited(
    client: TestClient, auth_headers: dict, empty_reports
) -> None:
    client.post("/api/v1/detection/quality/run?samplesPerClass=5", headers=auth_headers)

    audit = client.get(
        "/api/v1/audit?action=detection.evaluation_run", headers=auth_headers
    ).json()
    assert audit["total"] >= 1
    assert audit["items"][0]["details"]["eventsEvaluated"] > 0
