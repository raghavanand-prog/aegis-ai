"""Model, registry, inference and risk-scoring tests.

The theme throughout: the platform must never be *confidently wrong*. Every
test below is either "does the honest thing" or "degrades instead of lying".
"""

from __future__ import annotations

import random
from pathlib import Path

import pytest

from app.ml.features import FEATURE_NAMES
from app.ml.inference.engine import InferenceEngine
from app.ml.models.isolation_forest import (
    MODEL_NAME,
    MODEL_TYPE,
    IsolationForestDetector,
    ModelUnavailable,
    sha256_file,
)
from app.ml.registry import RegistryError, registry
from app.ml.schemas import FEATURE_SCHEMA_VERSION, InferenceResult
from app.models.enums import MLModelStatus, SignalType
from app.scoring import describe_strategy, risk_level, score_event
from app.scoring.risk import HIGH_THRESHOLD, ML_MAX_CONTRIBUTION


def _training_matrix(count: int = 300) -> list[tuple[float, ...]]:
    """Ordinary-looking vectors with a stable shape."""
    rng = random.Random(7)  # noqa: S311 - synthetic test vectors, not a secret
    return [
        tuple(rng.gauss(0.5, 0.05) for _ in FEATURE_NAMES) for _ in range(count)
    ]


@pytest.fixture(scope="module")
def detector() -> IsolationForestDetector:
    model = IsolationForestDetector(
        feature_names=FEATURE_NAMES, contamination=0.05, random_state=1337, n_estimators=50
    )
    model.fit(_training_matrix())
    return model


# --------------------------------------------------------------------- model
def test_fit_refuses_a_corpus_too_small_to_describe_normal() -> None:
    model = IsolationForestDetector(feature_names=FEATURE_NAMES)
    with pytest.raises(ValueError, match="Refusing to fit"):
        model.fit(_training_matrix(10))


def test_fit_refuses_a_width_mismatch() -> None:
    model = IsolationForestDetector(feature_names=FEATURE_NAMES)
    with pytest.raises(ValueError, match="width mismatch"):
        model.fit([(0.1, 0.2, 0.3)] * 100)


def test_scoring_is_deterministic(detector: IsolationForestDetector) -> None:
    vector = tuple(0.5 for _ in FEATURE_NAMES)
    assert detector.anomaly_score(vector) == detector.anomaly_score(vector)


def test_anomaly_score_is_bounded_and_ranks_outliers_higher(
    detector: IsolationForestDetector,
) -> None:
    typical = tuple(0.5 for _ in FEATURE_NAMES)
    extreme = tuple(9.0 for _ in FEATURE_NAMES)

    typical_score = detector.anomaly_score(typical)
    extreme_score = detector.anomaly_score(extreme)

    assert 0.0 <= typical_score <= 1.0
    assert 0.0 <= extreme_score <= 1.0
    assert extreme_score > typical_score


def test_explain_names_the_features_furthest_from_normal(
    detector: IsolationForestDetector,
) -> None:
    vector = [0.5 for _ in FEATURE_NAMES]
    vector[3] = 25.0  # one wildly out-of-range feature
    contributions = detector.explain(tuple(vector))

    assert contributions
    assert contributions[0].name == FEATURE_NAMES[3]
    assert contributions[0].direction == "above"
    assert abs(contributions[0].deviation) > 1


def test_unfitted_model_raises_rather_than_returning_a_number() -> None:
    model = IsolationForestDetector(feature_names=FEATURE_NAMES)
    assert not model.is_fitted
    with pytest.raises(ModelUnavailable):
        model.raw_score(tuple(0.5 for _ in FEATURE_NAMES))


# ---------------------------------------------------------------- artifacts
def test_artifact_round_trips_and_reproduces_scores(
    detector: IsolationForestDetector, tmp_path: Path
) -> None:
    path = tmp_path / "model.joblib"
    digest = detector.save(path)

    reloaded = IsolationForestDetector.load(path, expected_sha256=digest)
    vector = tuple(0.5 for _ in FEATURE_NAMES)
    assert reloaded.anomaly_score(vector) == detector.anomaly_score(vector)
    assert reloaded.feature_names == detector.feature_names
    assert reloaded.feature_schema_version == FEATURE_SCHEMA_VERSION


def test_tampered_artifact_is_refused(
    detector: IsolationForestDetector, tmp_path: Path
) -> None:
    """A model whose bytes changed is a detection engine that lies."""
    path = tmp_path / "model.joblib"
    digest = detector.save(path)
    path.write_bytes(path.read_bytes() + b"tampered")

    assert sha256_file(path) != digest
    with pytest.raises(ModelUnavailable, match="digest mismatch"):
        IsolationForestDetector.load(path, expected_sha256=digest)


def test_missing_artifact_is_refused(tmp_path: Path) -> None:
    with pytest.raises(ModelUnavailable, match="not found"):
        IsolationForestDetector.load(tmp_path / "nothing.joblib")


def test_unreadable_artifact_is_refused(tmp_path: Path) -> None:
    path = tmp_path / "garbage.joblib"
    path.write_bytes(b"this is not a joblib payload")
    with pytest.raises(ModelUnavailable):
        IsolationForestDetector.load(path)


# ----------------------------------------------------------------- registry
def _register(db, version: str, path: Path, digest: str, activate: bool = False):
    return registry.register(
        db,
        name=MODEL_NAME,
        version=version,
        model_type=MODEL_TYPE,
        feature_schema_version=FEATURE_SCHEMA_VERSION,
        dataset_version="test-1.0",
        dataset_fingerprint="abc123",
        training_samples=300,
        parameters={"contamination": 0.05},
        metrics={"trainingAnomalyRate": 0.05},
        feature_names=list(FEATURE_NAMES),
        artifact_path_str=str(path),
        artifact_sha256=digest,
        created_by="test",
        activate=activate,
    )


def test_registry_records_and_activates(db, detector, tmp_path: Path) -> None:
    path = tmp_path / "reg.joblib"
    digest = detector.save(path)

    model = _register(db, "9.0", path, digest, activate=True)
    assert model.status == MLModelStatus.ACTIVE.value
    assert model.identity == f"{MODEL_NAME}@9.0"
    assert registry.get_active(db, MODEL_NAME).id == model.id

    payload = registry.to_dict(model)
    # The API must never publish a filesystem path.
    assert "artifactPath" not in payload
    assert payload["artifactName"] == "reg.joblib"
    db.rollback()


def test_registry_refuses_to_overwrite_a_version(db, detector, tmp_path: Path) -> None:
    """Versions are immutable: stored inference rows point at them by version."""
    path = tmp_path / "dup.joblib"
    digest = detector.save(path)
    _register(db, "9.1", path, digest)

    with pytest.raises(RegistryError, match="already registered"):
        _register(db, "9.1", path, digest)
    db.rollback()


def test_activating_archives_the_incumbent_and_enables_rollback(
    db, detector, tmp_path: Path
) -> None:
    path = tmp_path / "roll.joblib"
    digest = detector.save(path)

    first = _register(db, "9.2", path, digest, activate=True)
    second = _register(db, "9.3", path, digest, activate=True)

    assert registry.get_active(db, MODEL_NAME).id == second.id
    db.refresh(first)
    assert first.status == MLModelStatus.ARCHIVED.value
    assert registry.get_previous(db, MODEL_NAME).id == first.id

    registry.activate_model(db, first)
    assert registry.get_active(db, MODEL_NAME).id == first.id
    db.rollback()


def test_registry_rejects_a_path_traversing_version() -> None:
    with pytest.raises(RegistryError):
        registry.artifact_path("isolation_forest", "../../etc/passwd")


def test_next_version_increments_the_major(db, detector, tmp_path: Path) -> None:
    path = tmp_path / "v.joblib"
    digest = detector.save(path)
    _register(db, "1.0", path, digest)
    # Scoped to this test's own artifact directory. Since V5, next_version
    # takes the maximum of the database and the filesystem, so an unscoped call
    # would depend on whatever artifacts happen to exist in the shared
    # directory. The behaviour under test is the increment itself.
    assert registry.next_version(db, MODEL_NAME, directory=tmp_path) == "2.0"
    db.rollback()


# ---------------------------------------------------------------- inference
def test_engine_without_a_model_returns_none_and_says_why(db) -> None:
    """The central degradation guarantee: no model means no verdict, not a crash
    and not a fabricated score."""
    engine = InferenceEngine()
    assert engine.load_active(db) is False
    assert engine.available is False
    assert "No active model" in engine.status()["reason"]

    candidate = {"event_type": "auth_failure", "hostname": "H1", "normalized_data": {}}
    assert engine.score(candidate) is None

    # The context is still updated, so an outage leaves no hole in the history
    # that later features depend on.
    assert engine.status()["context"]["observations"] > 0


def test_engine_rejects_a_model_from_a_different_feature_schema(
    db, detector, tmp_path: Path
) -> None:
    """Scoring a vector the model was never fitted on would produce a confident
    number that means nothing."""
    path = tmp_path / "stale.joblib"
    payload = detector.to_payload()
    payload["featureSchemaVersion"] = "0.1-ancient"

    import joblib

    joblib.dump(payload, path)
    digest = sha256_file(path)
    _register(db, "8.0", path, digest, activate=True)
    db.flush()

    engine = InferenceEngine()
    assert engine.load_active(db) is False
    assert "feature schema" in engine.status()["reason"]
    db.rollback()


def test_engine_scores_and_counts_once_loaded(db, detector, tmp_path: Path) -> None:
    path = tmp_path / "live.joblib"
    digest = detector.save(path)
    _register(db, "7.0", path, digest, activate=True)
    db.flush()

    engine = InferenceEngine()
    assert engine.load_active(db) is True

    result = engine.score(
        {
            "event_type": "auth_failure",
            "hostname": "SYN-WIN-001",
            "username": "a.sharma",
            "source_ip": "203.0.113.5",
            "normalized_data": {"failure_count": 9},
        }
    )
    assert isinstance(result, InferenceResult)
    assert 0.0 <= result.anomaly_score <= 1.0
    assert result.model_version == "7.0"
    assert result.feature_schema_version == FEATURE_SCHEMA_VERSION
    assert len(result.features) == len(FEATURE_NAMES)

    status = engine.status()
    assert status["available"] is True
    assert status["eventsScored"] == 1
    db.rollback()


def test_inference_result_never_calls_its_score_a_probability() -> None:
    result = InferenceResult(
        model_name="isolation_forest",
        model_version="1.0",
        feature_schema_version="1.0",
        anomaly_score=0.9,
        is_anomaly=True,
        threshold=0.65,
    )
    payload = result.to_dict()
    assert "anomalyScore" in payload
    assert "probability" not in payload
    assert "confidence" not in payload


# ------------------------------------------------------------ risk scoring
def test_no_signals_means_no_score() -> None:
    assessment = score_event()
    assert assessment.risk_score == 0
    assert assessment.signals == []


def test_ml_alone_cannot_reach_high_risk() -> None:
    """The architectural guarantee that stops the anomaly detector becoming an
    alert cannon."""
    inference = InferenceResult(
        model_name="isolation_forest",
        model_version="1.0",
        feature_schema_version="1.0",
        anomaly_score=1.0,
        is_anomaly=True,
        threshold=0.65,
    )
    assessment = score_event(inference=inference)

    assert assessment.risk_score <= ML_MAX_CONTRIBUTION
    assert assessment.risk_score < HIGH_THRESHOLD
    assert assessment.risk_level != "High"
    assert assessment.has(SignalType.ML)


def test_ml_below_its_floor_contributes_nothing() -> None:
    inference = InferenceResult(
        model_name="isolation_forest",
        model_version="1.0",
        feature_schema_version="1.0",
        anomaly_score=0.2,
        is_anomaly=False,
        threshold=0.65,
    )
    assert score_event(inference=inference).risk_score == 0


def test_ml_signal_is_labelled_as_an_anomaly_score_not_a_probability() -> None:
    inference = InferenceResult(
        model_name="isolation_forest",
        model_version="1.0",
        feature_schema_version="1.0",
        anomaly_score=0.9,
        is_anomaly=True,
        threshold=0.65,
    )
    signal = score_event(inference=inference).signals[0]
    assert signal.metadata["scoreKind"] == "anomaly_score"
    assert "probability" not in signal.detail.lower()


def test_the_band_never_lowers_a_severity_a_rule_assigned() -> None:
    """A rule saying 'this is a credential dump' is a categorical statement.
    Arithmetic does not get to overrule it."""
    assert risk_level(10, "Critical") == "Critical"
    assert risk_level(95, "Low") == "Critical"
    assert risk_level(10) == "Low"


def test_every_contribution_is_attributed_to_a_named_source() -> None:
    from app.detection import evaluate

    detection = evaluate(
        {
            "event_type": "auth_failure",
            "username": "a.sharma",
            "source_ip": "203.0.113.9",
            "normalized_data": {"failure_count": 12},
        }
    )
    assessment = score_event(
        detection_result=detection,
        context={"off_hours": True, "external_source": True},
        base_severity=detection.severity,
    )

    assert assessment.risk_score == sum(s.contribution for s in assessment.signals)
    assert {s.type for s in assessment.signals} == {SignalType.RULE, SignalType.CONTEXT}
    for signal in assessment.signals:
        assert signal.source
        assert signal.detail


def test_scoring_strategy_is_published() -> None:
    """The weights must be inspectable at runtime, or the score is not
    explainable in any meaningful sense."""
    strategy = describe_strategy()
    assert strategy["version"]
    assert strategy["weights"]["mlMaxContribution"] < strategy["bands"]["high"]
    assert any("anomaly score" in note for note in strategy["notes"])


def test_status_always_explains_why_it_is_unavailable(monkeypatch) -> None:
    """`available: false` with `reason: null` is a blank panel with no
    explanation, which is the one thing this layer must never produce.

    Found by the degraded-mode verification rather than by a unit test: the
    reason was only recorded by `load_active`, which never runs when ML is
    disabled at startup.
    """
    from app.core.config import settings

    engine = InferenceEngine()

    # Never loaded.
    assert engine.status()["available"] is False
    assert engine.status()["reason"]

    # Disabled by configuration.
    monkeypatch.setattr(settings, "ml_enabled", False)
    state = engine.status()
    assert state["available"] is False
    assert "ML_ENABLED" in state["reason"]
