"""Experiment framework: reproducibility, protocol and honesty guarantees.

The claims under test are the ones V4 exists to make:

* the same configuration produces the same experiment id and the same numbers
* the threshold is chosen on validation and frozen before test is evaluated
* a detector with no ordering is not given ranking metrics
* a configuration that cannot run is reported, not silently dropped
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from app.evaluation.datasets.base import (
    DatasetProvenance,
    EvaluationDataset,
    EvaluationSample,
    LabelSchema,
)
from app.evaluation.experiments.detectors import (
    AnomalyDetector,
    DetectorSpec,
    RulesDetector,
    SupervisedDetector,
    UnionHybridDetector,
)
from app.evaluation.experiments.runner import (
    ThresholdSweepPoint,
    extract_features,
    leakage_audit,
    run_experiment,
    select_threshold,
)
from app.evaluation.experiments.suite import run_suite
from app.evaluation.splits import STRATIFIED_GROUP, build_split
from app.ml.features.extractor import FEATURE_NAMES
from app.models.enums import SourceType
from app.telemetry.base import RawTelemetry
from app.telemetry.normalizer import normalize

BASE_TIME = datetime(2015, 1, 22, 12, 0, tzinfo=timezone.utc)


def _dataset(samples: int = 600) -> EvaluationDataset:
    """A separable-but-not-trivial corpus, big enough for ranking metrics."""
    built: list[EvaluationSample] = []
    for index in range(samples):
        malicious = index % 4 == 0
        record = RawTelemetry(
            source="Perimeter Firewall",
            source_type=SourceType.FIREWALL,
            raw={
                "action": "allow",
                "src_ip": f"10.0.{index % 7}.{index % 200 + 1}",
                "dst_ip": f"203.0.113.{index % 50 + 1}",
                "dst_port": 4444 if malicious else 443,
                "protocol": "tcp",
                "bytes_out": (900_000 + index * 13) if malicious else (1_000 + index),
                "rule": "observed-flow",
            },
            raw_log=f"[FLOW] tcp flow {index} malicious={malicious}",
            received_at=BASE_TIME + timedelta(seconds=index * 7),
            is_synthetic=False,
        )
        built.append(
            EvaluationSample(
                id=f"S-{index:05d}",
                category="attack" if malicious else "benign",
                is_malicious=malicious,
                candidate=normalize(record),
                timestamp=record.received_at,
                group_key=f"g-{index}",
            )
        )
    return EvaluationDataset(
        name="experiment-fixture",
        version="1.0",
        provenance=DatasetProvenance(
            source="test", license="n/a", citation="n/a", description="fixture"
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
def fixture_dataset() -> EvaluationDataset:
    return _dataset()


@pytest.fixture(scope="module")
def fixture_features(fixture_dataset: EvaluationDataset) -> dict[str, tuple[float, ...]]:
    return extract_features(fixture_dataset)


# ------------------------------------------------------------ reproducibility


def test_feature_extraction_is_reproducible(fixture_dataset: EvaluationDataset) -> None:
    assert extract_features(fixture_dataset) == extract_features(fixture_dataset)


def test_the_same_configuration_reproduces_the_same_result(
    fixture_dataset: EvaluationDataset, fixture_features: dict[str, tuple[float, ...]]
) -> None:
    plan = build_split(fixture_dataset, strategy=STRATIFIED_GROUP, seed=7)

    def once():
        spec = DetectorSpec(
            detector=AnomalyDetector(feature_names=FEATURE_NAMES, random_state=7),
            threshold_grid=(0.5, 0.6, 0.7, 0.8),
            fixed_threshold=0.65,
        )
        return run_experiment(
            dataset=fixture_dataset, plan=plan, spec=spec, features=fixture_features, seed=7
        )

    first, second = once(), once()
    assert first.experiment_id == second.experiment_id
    assert first.threshold == second.threshold
    assert first.test.confusion.to_dict() == second.test.confusion.to_dict()


def test_a_different_seed_changes_the_experiment_id(
    fixture_dataset: EvaluationDataset, fixture_features: dict[str, tuple[float, ...]]
) -> None:
    plan = build_split(fixture_dataset, strategy=STRATIFIED_GROUP, seed=7)
    spec = DetectorSpec(detector=RulesDetector(), fixed_threshold=0.5)
    first = run_experiment(
        dataset=fixture_dataset, plan=plan, spec=spec, features=fixture_features, seed=1
    )
    second = run_experiment(
        dataset=fixture_dataset,
        plan=plan,
        spec=DetectorSpec(detector=RulesDetector(), fixed_threshold=0.5),
        features=fixture_features,
        seed=2,
    )
    assert first.experiment_id != second.experiment_id


# ------------------------------------------------------------------ protocol


def test_threshold_is_chosen_on_validation_not_test(
    fixture_dataset: EvaluationDataset, fixture_features: dict[str, tuple[float, ...]]
) -> None:
    """The frozen threshold must be the validation optimum, whatever test says."""
    plan = build_split(fixture_dataset, strategy=STRATIFIED_GROUP, seed=11)
    grid = (0.45, 0.55, 0.65, 0.75, 0.85)
    spec = DetectorSpec(
        detector=AnomalyDetector(feature_names=FEATURE_NAMES, random_state=11),
        threshold_grid=grid,
        fixed_threshold=0.65,
    )
    result = run_experiment(
        dataset=fixture_dataset, plan=plan, spec=spec, features=fixture_features, seed=11
    )

    assert result.threshold in grid
    assert result.validation is not None
    assert result.validation.threshold == result.threshold
    assert result.threshold_selection["chosenThreshold"] == result.threshold
    # The sweep is over validation only, and the winner is its maximum.
    best = max(point.f1 or -1 for point in result.sweep)
    chosen = next(point for point in result.sweep if point.threshold == result.threshold)
    assert (chosen.f1 or -1) == best


def test_select_threshold_flags_a_grid_boundary_choice() -> None:
    """A threshold at the edge of the grid may not be the real optimum."""
    points = [
        ThresholdSweepPoint(0.4, 0.5, 1.0, 0.9, 0.5, 0.0, 100, 50.0),
        ThresholdSweepPoint(0.5, 0.5, 0.5, 0.5, 0.2, 0.5, 50, 25.0),
    ]
    threshold, selection = select_threshold(points)
    assert threshold == 0.4
    assert selection["atGridBoundary"] is True
    assert "outside it" in selection["warning"]

    inner = [
        ThresholdSweepPoint(0.4, 0.3, 0.3, 0.3, 0.5, 0.7, 100, 50.0),
        ThresholdSweepPoint(0.5, 0.9, 0.9, 0.9, 0.1, 0.1, 50, 25.0),
        ThresholdSweepPoint(0.6, 0.4, 0.4, 0.4, 0.2, 0.6, 20, 10.0),
    ]
    threshold, selection = select_threshold(inner)
    assert threshold == 0.5
    assert selection["atGridBoundary"] is False
    assert selection["warning"] is None


def test_a_rule_detector_is_not_given_a_threshold_sweep(
    fixture_dataset: EvaluationDataset, fixture_features: dict[str, tuple[float, ...]]
) -> None:
    plan = build_split(fixture_dataset, strategy=STRATIFIED_GROUP, seed=13)
    result = run_experiment(
        dataset=fixture_dataset,
        plan=plan,
        spec=DetectorSpec(detector=RulesDetector(), fixed_threshold=0.5),
        features=fixture_features,
        seed=13,
    )
    assert result.sweep == []
    assert result.threshold_selection["method"] == "not applicable"
    assert result.test.ranking["rocAuc"] is None
    assert "no ordering" in result.test.ranking["unavailableReason"]


def test_union_hybrid_detects_at_least_what_its_components_detect(
    fixture_dataset: EvaluationDataset, fixture_features: dict[str, tuple[float, ...]]
) -> None:
    """A union cannot detect fewer positives than either part alone."""
    plan = build_split(fixture_dataset, strategy=STRATIFIED_GROUP, seed=17)

    def run(detector, threshold=0.65):
        return run_experiment(
            dataset=fixture_dataset,
            plan=plan,
            spec=DetectorSpec(detector=detector, fixed_threshold=threshold),
            features=fixture_features,
            seed=17,
        )

    rules = run(RulesDetector(), 0.5)
    anomaly = run(AnomalyDetector(feature_names=FEATURE_NAMES, random_state=17))
    hybrid = run(
        UnionHybridDetector(
            rules=RulesDetector(),
            anomaly=AnomalyDetector(feature_names=FEATURE_NAMES, random_state=17),
        )
    )
    assert hybrid.test.confusion.true_positives >= rules.test.confusion.true_positives
    assert hybrid.test.confusion.true_positives >= anomaly.test.confusion.true_positives
    # And it cannot have fewer false positives either - that is the cost.
    assert hybrid.test.confusion.false_positives >= rules.test.confusion.false_positives


# -------------------------------------------------------------------- honesty


def test_a_detector_that_cannot_be_fitted_is_reported_not_dropped(
    fixture_dataset: EvaluationDataset, fixture_features: dict[str, tuple[float, ...]]
) -> None:
    """A single-class training split must not silently vanish from the table."""
    single_class = EvaluationDataset(
        name=fixture_dataset.name,
        version=fixture_dataset.version,
        provenance=fixture_dataset.provenance,
        label_schema=fixture_dataset.label_schema,
        samples=[
            EvaluationSample(
                id=sample.id,
                category="benign",
                is_malicious=False,
                candidate=sample.candidate,
                timestamp=sample.timestamp,
                group_key=sample.group_key,
            )
            for sample in fixture_dataset.samples
        ],
    )
    plan = build_split(single_class, strategy=STRATIFIED_GROUP, seed=3)
    suite = run_suite(
        dataset=single_class,
        plan=plan,
        features=fixture_features,
        specs=[
            DetectorSpec(
                detector=SupervisedDetector(feature_names=FEATURE_NAMES), fixed_threshold=0.5
            )
        ],
    )
    assert suite.results == []
    assert len(suite.skipped) == 1
    assert "single class" in suite.skipped[0]["reason"]


def test_leakage_audit_reports_a_share_not_a_verdict(
    fixture_dataset: EvaluationDataset, fixture_features: dict[str, tuple[float, ...]]
) -> None:
    plan = build_split(fixture_dataset, strategy=STRATIFIED_GROUP, seed=5)
    audit = leakage_audit(plan, fixture_features)
    assert set(audit["splits"]) == {"validation", "test"}
    for entry in audit["splits"].values():
        assert 0.0 <= (entry["share"] or 0.0) <= 1.0
    assert isinstance(audit["concerning"], bool)


def test_supervised_detector_emits_a_probability_and_the_anomaly_one_does_not() -> None:
    """The vocabulary distinction, asserted rather than assumed."""
    supervised = SupervisedDetector(feature_names=FEATURE_NAMES)
    anomaly = AnomalyDetector(feature_names=FEATURE_NAMES)
    assert "probability" in supervised.score_kind
    assert "NOT a probability" in anomaly.score_kind
    assert "probability" not in anomaly.describe()["scoreKind"].replace(
        "NOT a probability", ""
    )
