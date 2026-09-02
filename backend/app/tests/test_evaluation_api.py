"""The V4 evaluation API: persistence, provenance, RBAC and honest emptiness."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from app.evaluation.datasets.base import (
    DatasetProvenance,
    EvaluationDataset,
    EvaluationSample,
    LabelSchema,
)
from app.evaluation.experiments.detectors import AnomalyDetector, DetectorSpec, RulesDetector
from app.evaluation.experiments.runner import extract_features, run_experiment
from app.evaluation.splits import STRATIFIED_GROUP, build_split
from app.ml.features.extractor import FEATURE_NAMES
from app.models.enums import SourceType
from app.services import evaluation_service
from app.telemetry.base import RawTelemetry
from app.telemetry.normalizer import normalize

BASE_TIME = datetime(2015, 1, 22, 12, 0, tzinfo=timezone.utc)


def _dataset(name: str = "api-fixture", samples: int = 400) -> EvaluationDataset:
    built: list[EvaluationSample] = []
    for index in range(samples):
        malicious = index % 4 == 0
        record = RawTelemetry(
            source="Perimeter Firewall",
            source_type=SourceType.FIREWALL,
            raw={
                "action": "allow",
                "src_ip": f"10.0.{index % 5}.{index % 200 + 1}",
                "dst_ip": f"203.0.113.{index % 40 + 1}",
                "dst_port": 4444 if malicious else 443,
                "protocol": "tcp",
                "bytes_out": (800_000 + index * 17) if malicious else (1_200 + index),
                "rule": "observed-flow",
            },
            raw_log=f"[FLOW] tcp flow {index}",
            received_at=BASE_TIME + timedelta(seconds=index * 11),
            is_synthetic=False,
        )
        built.append(
            EvaluationSample(
                id=f"A-{index:05d}",
                category="attack" if malicious else "benign",
                is_malicious=malicious,
                candidate=normalize(record),
                timestamp=record.received_at,
                group_key=f"gk-{index}",
            )
        )
    return EvaluationDataset(
        name=name,
        version="1.0",
        provenance=DatasetProvenance(
            source="unit-test",
            license="n/a",
            citation="n/a",
            description="fixture corpus",
        ),
        label_schema=LabelSchema(
            name="fixture",
            version="1.0",
            mapping={"": "benign", "Attack": "attack"},
            malicious_categories=("attack",),
            benign_category="benign",
        ),
        samples=built,
    )


@pytest.fixture(scope="module")
def stored(request) -> dict:
    """Run two real experiments and index them, once for the whole module."""
    from app.core.database import SessionLocal

    dataset = _dataset()
    features = extract_features(dataset)
    plan = build_split(dataset, strategy=STRATIFIED_GROUP, seed=23)

    rules = run_experiment(
        dataset=dataset,
        plan=plan,
        spec=DetectorSpec(detector=RulesDetector(), fixed_threshold=0.5),
        features=features,
        seed=23,
    )
    anomaly = run_experiment(
        dataset=dataset,
        plan=plan,
        spec=DetectorSpec(
            detector=AnomalyDetector(feature_names=FEATURE_NAMES, random_state=23),
            threshold_grid=(0.5, 0.6, 0.7, 0.8),
            fixed_threshold=0.65,
        ),
        features=features,
        seed=23,
    )

    session = SessionLocal()
    try:
        evaluation_service.store_report(
            session,
            [(rules, 23), (anomaly, 23)],
            # A path string only; nothing is written here.
            report_path="fixture-report.json",  # noqa: S108 - not a filesystem path in use
            leakage={"splits": {}, "concerning": False},
        )
        session.commit()
    finally:
        session.close()
    return {"rules": rules.experiment_id, "anomaly": anomaly.experiment_id}


# ------------------------------------------------------------------ read API


def test_status_reports_what_exists(
    client: TestClient, auth_headers: dict, stored: dict
) -> None:
    response = client.get("/api/v1/evaluation/status", headers=auth_headers)
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["available"] is True
    assert body["reason"] is None
    assert body["experimentCount"] >= 2
    assert "rules" in body["detectors"]
    # The corpus availability block must always answer, present or not.
    assert "unsw-nb15" in body["corpora"]
    assert "onDisk" in body["corpora"]["unsw-nb15"]


def test_experiment_carries_full_provenance(
    client: TestClient, auth_headers: dict, stored: dict
) -> None:
    """A metric without its provenance is not a result."""
    response = client.get(
        f"/api/v1/evaluation/experiments/{stored['anomaly']}", headers=auth_headers
    )
    assert response.status_code == 200, response.text
    body = response.json()

    assert body["dataset"]["fingerprint"]
    assert body["split"]["strategy"] == STRATIFIED_GROUP
    assert body["split"]["fingerprint"]
    assert body["provenance"]["featureSchemaVersion"]
    assert body["detector"]["scoreKind"]
    assert body["latestRun"]["threshold"] is not None


def test_anomaly_score_is_never_labelled_a_probability(
    client: TestClient, auth_headers: dict, stored: dict
) -> None:
    response = client.get(
        f"/api/v1/evaluation/experiments/{stored['anomaly']}", headers=auth_headers
    )
    score_kind = response.json()["detector"]["scoreKind"]
    assert "anomaly_score" in score_kind
    assert "NOT a probability" in score_kind


def test_confusion_matrix_returns_machine_readable_counts(
    client: TestClient, auth_headers: dict, stored: dict
) -> None:
    response = client.get(
        f"/api/v1/evaluation/experiments/{stored['rules']}/confusion-matrix",
        headers=auth_headers,
    )
    assert response.status_code == 200, response.text
    body = response.json()
    counts = body["counts"]
    assert set(counts) == {
        "truePositives",
        "trueNegatives",
        "falsePositives",
        "falseNegatives",
    }
    assert all(isinstance(value, int) for value in counts.values())
    assert body["normalized"]["normalization"].startswith("row")


def test_threshold_sweep_is_measured_on_validation(
    client: TestClient, auth_headers: dict, stored: dict
) -> None:
    response = client.get(
        f"/api/v1/evaluation/experiments/{stored['anomaly']}/threshold-sweep",
        headers=auth_headers,
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["measuredOn"] == "validation split"
    assert body["points"], "an anomaly detector must have a sweep"
    assert body["chosenThreshold"] in [point["threshold"] for point in body["points"]]


def test_a_rule_detector_reports_an_empty_sweep_with_a_reason(
    client: TestClient, auth_headers: dict, stored: dict
) -> None:
    response = client.get(
        f"/api/v1/evaluation/experiments/{stored['rules']}/threshold-sweep",
        headers=auth_headers,
    )
    body = response.json()
    assert body["points"] == []
    assert "either match or they do not" in body["note"]


def test_unknown_experiment_is_a_404(client: TestClient, auth_headers: dict) -> None:
    response = client.get(
        "/api/v1/evaluation/experiments/EXP-doesnotexist", headers=auth_headers
    )
    assert response.status_code == 404


# ------------------------------------------------------------------- compare


def test_compare_accepts_experiments_on_the_same_data(
    client: TestClient, auth_headers: dict, stored: dict
) -> None:
    response = client.get(
        "/api/v1/evaluation/compare",
        params={"ids": [stored["rules"], stored["anomaly"]]},
        headers=auth_headers,
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["comparable"] is True
    assert len(body["items"]) == 2


def test_compare_refuses_to_pool_different_datasets(
    client: TestClient, auth_headers: dict, stored: dict
) -> None:
    """Two results from different data are not a comparison."""
    from app.core.database import SessionLocal

    other = _dataset(name="api-fixture-other", samples=320)
    features = extract_features(other)
    plan = build_split(other, strategy=STRATIFIED_GROUP, seed=29)
    result = run_experiment(
        dataset=other,
        plan=plan,
        spec=DetectorSpec(detector=RulesDetector(), fixed_threshold=0.5),
        features=features,
        seed=29,
    )
    session = SessionLocal()
    try:
        evaluation_service.store_result(session, result, seed=29)
        session.commit()
    finally:
        session.close()

    response = client.get(
        "/api/v1/evaluation/compare",
        params={"ids": [stored["rules"], result.experiment_id]},
        headers=auth_headers,
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["comparable"] is False
    assert any("not comparable" in warning for warning in body["warnings"])


def test_compare_needs_at_least_two_ids(
    client: TestClient, auth_headers: dict, stored: dict
) -> None:
    response = client.get(
        "/api/v1/evaluation/compare", params={"ids": [stored["rules"]]}, headers=auth_headers
    )
    assert response.status_code == 400


# ---------------------------------------------------------------- idempotence


def test_rerunning_a_configuration_appends_a_run_not_an_experiment(
    stored: dict,
) -> None:
    """The experiment id is the configuration; runs are the executions."""
    from app.core.database import SessionLocal
    from app.repositories.evaluation_repository import experiments as experiment_repo

    dataset = _dataset()
    features = extract_features(dataset)
    plan = build_split(dataset, strategy=STRATIFIED_GROUP, seed=23)
    result = run_experiment(
        dataset=dataset,
        plan=plan,
        spec=DetectorSpec(detector=RulesDetector(), fixed_threshold=0.5),
        features=features,
        seed=23,
    )
    assert result.experiment_id == stored["rules"]

    # Sessions are configured with expire_on_commit=False, so a collection read
    # before the write stays cached. Each observation therefore uses its own
    # session - otherwise this test would be reading its own stale snapshot.
    def run_count() -> int:
        session = SessionLocal()
        try:
            experiment = experiment_repo.get_by_experiment_id(session, stored["rules"])
            return len(experiment.runs)
        finally:
            session.close()

    def experiment_count() -> int:
        session = SessionLocal()
        try:
            _, total = experiment_repo.list_paginated(session, detector_name="rules")
            return total
        finally:
            session.close()

    runs_before = run_count()
    experiments_before = experiment_count()

    session = SessionLocal()
    try:
        evaluation_service.store_result(session, result, seed=23)
        session.commit()
    finally:
        session.close()

    assert run_count() == runs_before + 1
    assert experiment_count() == experiments_before, (
        "an identical configuration must not create a second experiment row"
    )


# ---------------------------------------------------------------------- RBAC


def test_evaluation_requires_authentication(client: TestClient) -> None:
    for path in ("/status", "/experiments", "/datasets"):
        response = client.get(f"/api/v1/evaluation{path}")
        assert response.status_code in (401, 403), path


def test_a_viewer_may_read_evaluation_results(
    client: TestClient, auth_headers: dict
) -> None:
    """Measured quality is transparency, not privilege."""
    credentials = {"email": "viewer.eval@aegisx.dev", "password": "ViewerPassw0rd!"}
    client.post(
        "/api/v1/auth/users",
        json={
            "email": credentials["email"],
            "password": credentials["password"],
            "fullName": "Eval Viewer",
            "role": "viewer",
        },
        headers=auth_headers,
    )
    login = client.post("/api/v1/auth/login", json=credentials)
    assert login.status_code == 200, login.text
    viewer_headers = {"Authorization": f"Bearer {login.json()['accessToken']}"}

    response = client.get("/api/v1/evaluation/status", headers=viewer_headers)
    assert response.status_code == 200


def test_no_endpoint_can_start_an_experiment() -> None:
    """Running an experiment is minutes of CPU; HTTP must not be able to.

    This asserts the absence of a route rather than the behaviour of one,
    because the security property is that no such route exists.
    """
    from app.main import app

    schema = app.openapi()
    evaluation_paths = {
        path: methods
        for path, methods in schema["paths"].items()
        if "/evaluation" in path
    }
    assert evaluation_paths, "the evaluation API should be mounted"
    for path, methods in evaluation_paths.items():
        assert set(methods) <= {"get"}, f"{path} exposes a write method: {sorted(methods)}"
