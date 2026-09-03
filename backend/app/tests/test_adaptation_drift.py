"""Drift detection (V5 Phase D).

Drift detection produces a *signal*, never a retrain. These tests hold three
lines that are easy to lose:

1. A distribution changing is not the model failing. The two are separate
   claims and the code must not conflate them.
2. Statistical significance is not effect size. Over a large window any
   difference is significant, so status must follow effect size.
3. A drift result on too little data is a false alarm waiting to happen, and
   must be refused rather than reported quietly.
"""

from __future__ import annotations

import numpy as np
import pytest

from app.adaptation.drift import metrics


class TestPopulationStabilityIndex:
    def test_identical_distributions_have_zero_psi(self) -> None:
        rng = np.random.default_rng(1337)
        sample = rng.normal(size=5_000)
        assert metrics.population_stability_index(sample, sample) == pytest.approx(0.0, abs=1e-9)

    def test_psi_matches_a_hand_computed_value(self) -> None:
        """Two bins, 50/50 against 60/40.

        sum (c - r) * ln(c / r)
          = 0.1 * ln(1.2) + (-0.1) * ln(0.8) = 0.018232 + 0.022314
        """
        reference = np.array([0.0] * 50 + [1.0] * 50)
        current = np.array([0.0] * 60 + [1.0] * 40)
        value = metrics.population_stability_index(reference, current, bins=2)
        assert value == pytest.approx(0.040546, abs=1e-4)

    def test_psi_grows_with_the_size_of_the_shift(self) -> None:
        rng = np.random.default_rng(7)
        reference = rng.normal(loc=0.0, size=10_000)
        small = metrics.population_stability_index(reference, rng.normal(loc=0.2, size=10_000))
        large = metrics.population_stability_index(reference, rng.normal(loc=2.0, size=10_000))
        assert 0 < small < large

    def test_an_empty_bin_does_not_produce_infinity(self) -> None:
        """A category present in one window and absent from the other is the
        normal case, not an error, and must not divide by zero."""
        reference = np.array([0.0] * 100)
        current = np.array([1.0] * 100)
        value = metrics.population_stability_index(reference, current, bins=2)
        assert np.isfinite(value)
        assert value > 0

    def test_psi_is_deterministic(self) -> None:
        rng = np.random.default_rng(99)
        reference, current = rng.normal(size=2_000), rng.normal(loc=0.5, size=2_000)
        first = metrics.population_stability_index(reference, current)
        second = metrics.population_stability_index(reference, current)
        assert first == second


class TestWasserstein:
    def test_identical_distributions_have_zero_distance(self) -> None:
        sample = np.array([1.0, 2.0, 3.0, 4.0])
        assert metrics.wasserstein(sample, sample) == pytest.approx(0.0)

    def test_a_translation_moves_the_distance_by_the_translation(self) -> None:
        sample = np.array([1.0, 2.0, 3.0, 4.0])
        assert metrics.wasserstein(sample, sample + 5.0) == pytest.approx(5.0)


class TestCategoricalDrift:
    def test_identical_categories_show_no_drift(self) -> None:
        counts = {"endpoint": 100, "network": 50, "identity": 25}
        result = metrics.categorical_drift(counts, counts)
        assert result.effect_size == pytest.approx(0.0, abs=1e-9)

    def test_an_unseen_category_is_drift(self) -> None:
        reference = {"endpoint": 100, "network": 100}
        current = {"endpoint": 100, "network": 100, "cloud": 100}
        result = metrics.categorical_drift(reference, current)
        assert result.effect_size > 0
        assert "cloud" in result.new_categories

    def test_effect_size_not_p_value_drives_the_verdict(self) -> None:
        """Over a large window a trivial difference is statistically significant.

        Reporting 'drift detected' from a p-value alone would fire constantly on
        a busy sensor while telling an analyst nothing about magnitude.
        """
        reference = {"a": 500_000, "b": 500_000}
        current = {"a": 502_000, "b": 498_000}
        result = metrics.categorical_drift(reference, current)
        assert result.p_value < 0.05  # significant
        assert result.effect_size < 0.01  # but negligible
        assert result.status == metrics.DriftStatus.STABLE


class TestDriftStatus:
    def test_the_conventional_psi_bands_are_used_and_configurable(self) -> None:
        assert metrics.classify(0.05) is metrics.DriftStatus.STABLE
        assert metrics.classify(0.15) is metrics.DriftStatus.MODERATE
        assert metrics.classify(0.40) is metrics.DriftStatus.SIGNIFICANT
        # A caller may tighten the bands; nothing is hard-coded at the call site.
        assert metrics.classify(0.05, moderate=0.01, significant=0.02) is (
            metrics.DriftStatus.SIGNIFICANT
        )

    def test_too_few_samples_is_refused_rather_than_reported(self) -> None:
        rng = np.random.default_rng(3)
        with pytest.raises(ValueError, match="samples"):
            metrics.population_stability_index(
                rng.normal(size=5), rng.normal(size=5), min_samples=100
            )


class TestDriftKindsAreDistinct:
    def test_data_prediction_and_concept_drift_are_separate_kinds(self) -> None:
        """Data drift is evidence about the input. It is not evidence that the
        relationship between features and truth has changed, and V5 must never
        report one as the other."""
        from app.adaptation.drift.detector import DriftKind

        assert {kind.value for kind in DriftKind} == {"data", "prediction", "concept"}

    def test_concept_drift_requires_labels(self) -> None:
        """Without ground truth there is nothing to say about the relationship
        between features and truth, so the detector must refuse rather than
        infer concept drift from inputs alone."""
        from app.adaptation.drift import detector

        with pytest.raises(ValueError, match="labels"):
            detector.assess_concept_drift(
                reference_labels=[], current_labels=[], reference_scores=[], current_scores=[]
            )


class TestDriftPersistence:
    """A drift measurement is only useful as a series. One reading says the
    window differs from the baseline; a history says whether that is a trend, a
    spike, or the sensor being noisy."""

    def test_a_measurement_records_its_baseline_and_window(self, db) -> None:
        from app.adaptation.drift import monitor
        from app.adaptation.drift.detector import DriftKind

        rng = np.random.default_rng(11)
        record = monitor.record_feature_drift(
            db,
            feature="bytes_out",
            reference=rng.normal(loc=0.0, size=500),
            current=rng.normal(loc=1.5, size=500),
            kind=DriftKind.DATA,
            baseline_label="model-fit-window",
            window_label="last-24h",
        )

        assert record.id is not None
        assert record.feature == "bytes_out"
        assert record.kind == "data"
        assert record.baseline_label == "model-fit-window"
        assert record.window_label == "last-24h"
        assert record.status == "significant"
        assert record.metric_name == "psi"
        assert record.reference_samples == 500
        assert record.current_samples == 500
        # The thresholds in force are stored with the reading: a status is not
        # interpretable months later without the bands that produced it.
        assert record.moderate_threshold == pytest.approx(0.10)
        assert record.significant_threshold == pytest.approx(0.25)

    def test_history_is_returned_newest_first(self, db) -> None:
        from app.adaptation.drift import monitor
        from app.adaptation.drift.detector import DriftKind

        rng = np.random.default_rng(12)
        for shift in (0.0, 2.0):
            monitor.record_feature_drift(
                db,
                feature="distinct_ports",
                reference=rng.normal(size=300),
                current=rng.normal(loc=shift, size=300),
                kind=DriftKind.DATA,
                baseline_label="baseline",
                window_label="w",
            )

        history = monitor.history(db, feature="distinct_ports")
        assert len(history) >= 2
        assert history[0].id > history[1].id

    def test_recording_drift_does_not_touch_the_model_registry(self, db) -> None:
        """The hard line: a drift signal is not a retrain, and this is the test
        that will fail if anyone later wires one to the other."""
        from app.adaptation.drift import monitor
        from app.adaptation.drift.detector import DriftKind
        from app.models.ml import MLModel

        before = db.query(MLModel).count()
        rng = np.random.default_rng(13)
        monitor.record_feature_drift(
            db,
            feature="failed_logons",
            reference=rng.normal(size=400),
            current=rng.normal(loc=5.0, size=400),
            kind=DriftKind.DATA,
            baseline_label="baseline",
            window_label="w",
        )
        assert db.query(MLModel).count() == before


class TestDriftAPI:
    def test_drift_status_is_readable_by_a_viewer(self, client, auth_headers) -> None:
        response = client.get("/api/v1/adaptation/drift", headers=auth_headers)
        assert response.status_code == 200, response.text

    def test_the_drift_api_never_says_the_model_failed(self, client, auth_headers) -> None:
        """A distribution moving is not a model being wrong. The API must not
        let a dashboard imply otherwise."""
        response = client.get("/api/v1/adaptation/drift", headers=auth_headers)
        body = response.json()
        assert "interpretation" in body
        assert "not evidence" in body["interpretation"].lower()

    def test_no_endpoint_can_trigger_retraining_from_drift(self) -> None:
        from app.main import app

        schema = app.openapi()
        drift_paths = {
            path: methods for path, methods in schema["paths"].items() if "/drift" in path
        }
        assert drift_paths, "the drift API should be mounted"
        for path, methods in drift_paths.items():
            assert set(methods) <= {"get"}, f"{path} exposes a write method: {sorted(methods)}"
