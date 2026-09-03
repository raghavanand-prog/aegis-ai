"""Candidate evaluation and promotion gates (V5 Phase G).

A gate answers one question: *is it safe to put this in front of live traffic?*
Not *is it better* - better on one metric is how a detector loses half its
recall in exchange for a prettier false-positive rate.

The rules these tests hold:

- a gate never passes on a metric that was not measured;
- one improved metric never outweighs a catastrophic regression;
- thresholds are configuration with a stated rationale, not constants;
- passing every gate promotes nothing.
"""

from __future__ import annotations

import pytest

from app.adaptation.candidates import gates
from app.evaluation.metrics.classification import ConfusionMatrix


def _matrix(tp: int, fp: int, tn: int, fn: int) -> ConfusionMatrix:
    return ConfusionMatrix(
        true_positives=tp, false_positives=fp, true_negatives=tn, false_negatives=fn
    )


class TestGatePolicy:
    def test_thresholds_are_configuration_not_constants(self) -> None:
        policy = gates.GatePolicy()
        assert policy.max_recall_drop > 0
        assert policy.max_fpr_increase > 0
        # Every threshold carries a stated reason, so a reviewer can argue with
        # the number rather than discovering it in a source file.
        for name, rationale in policy.rationale().items():
            assert rationale, f"{name} has no documented rationale"

    def test_a_deployment_may_tighten_the_policy(self) -> None:
        strict = gates.GatePolicy(max_recall_drop=0.01, max_fpr_increase=0.005)
        assert strict.max_recall_drop == 0.01
        assert strict.max_fpr_increase == 0.005


class TestRecallRegression:
    def test_a_catastrophic_recall_drop_fails_however_good_the_precision(self) -> None:
        """The exact trade a naive 'is it better' check would wave through:
        precision 60% -> 100%, recall 74% -> 20%."""
        baseline = _matrix(tp=116, fp=78, tn=156, fn=40)
        candidate = _matrix(tp=31, fp=0, tn=234, fn=125)

        result = gates.evaluate(baseline=baseline, candidate=candidate)

        assert result.passed is False
        assert any("recall" in failure.lower() for failure in result.failures)

    def test_a_small_recall_drop_within_policy_passes(self) -> None:
        baseline = _matrix(tp=100, fp=20, tn=180, fn=20)
        candidate = _matrix(tp=98, fp=10, tn=190, fn=22)
        result = gates.evaluate(baseline=baseline, candidate=candidate)
        assert result.passed is True, result.failures


class TestFalsePositiveRegression:
    def test_an_unacceptable_fpr_increase_fails(self) -> None:
        baseline = _matrix(tp=100, fp=10, tn=190, fn=20)
        candidate = _matrix(tp=105, fp=120, tn=80, fn=15)
        result = gates.evaluate(baseline=baseline, candidate=candidate)
        assert result.passed is False
        assert any("false positive" in failure.lower() for failure in result.failures)


class TestUnmeasuredMetrics:
    def test_a_gate_does_not_pass_on_a_metric_that_was_not_measured(self) -> None:
        """Precision is undefined when nothing was flagged. V4's rule holds:
        an unmeasured metric is not a passing one."""
        baseline = _matrix(tp=100, fp=10, tn=190, fn=20)
        candidate = _matrix(tp=0, fp=0, tn=200, fn=120)

        result = gates.evaluate(baseline=baseline, candidate=candidate)

        assert result.passed is False
        assert any(
            "not measured" in failure.lower() or "recall" in failure.lower()
            for failure in result.failures
        )

    def test_latency_is_skipped_rather_than_assumed_when_absent(self) -> None:
        baseline = _matrix(tp=100, fp=20, tn=180, fn=20)
        candidate = _matrix(tp=98, fp=10, tn=190, fn=22)
        result = gates.evaluate(
            baseline=baseline, candidate=candidate, baseline_latency_ms=None,
            candidate_latency_ms=None,
        )
        latency_checks = [c for c in result.checks if c.name == "latency"]
        assert latency_checks and latency_checks[0].status == "not_measured"
        # A skipped check is reported, never silently counted as a pass.
        assert latency_checks[0].passed is False or latency_checks[0].advisory is True


class TestLatencyRegression:
    def test_a_large_latency_regression_fails(self) -> None:
        baseline = _matrix(tp=100, fp=20, tn=180, fn=20)
        candidate = _matrix(tp=100, fp=18, tn=182, fn=20)
        result = gates.evaluate(
            baseline=baseline,
            candidate=candidate,
            baseline_latency_ms=5.0,
            candidate_latency_ms=90.0,
        )
        assert result.passed is False
        assert any("latency" in failure.lower() for failure in result.failures)


class TestGatesDoNotPromote:
    def test_passing_every_gate_changes_no_model_state(self, db, tmp_path) -> None:
        """The hard line: a gate result is evidence for a human decision. It is
        not the decision."""
        from app.adaptation.candidates import training
        from app.models.enums import MLModelStatus

        candidate = training.train_candidate(
            db, samples=400, seed=4242, directory=tmp_path, created_by="test"
        )
        baseline = _matrix(tp=100, fp=20, tn=180, fn=20)
        better = _matrix(tp=105, fp=10, tn=190, fn=15)

        result = gates.evaluate(baseline=baseline, candidate=better)
        db.refresh(candidate)

        assert result.passed is True, result.failures
        assert candidate.status == MLModelStatus.CANDIDATE.value
        assert candidate.activated_at is None


class TestComparabilityIsEnforced:
    def test_comparing_across_dataset_fingerprints_is_refused(self) -> None:
        """V4 refused to compare experiments across dataset fingerprints. A
        promotion decision is a comparison, so the same rule applies."""
        baseline = _matrix(tp=100, fp=20, tn=180, fn=20)
        candidate = _matrix(tp=105, fp=10, tn=190, fn=15)

        with pytest.raises(ValueError, match="fingerprint"):
            gates.evaluate(
                baseline=baseline,
                candidate=candidate,
                baseline_dataset_fingerprint="aaaaaaaaaaaaaaaa",
                candidate_dataset_fingerprint="bbbbbbbbbbbbbbbb",
            )

    def test_the_same_fingerprint_compares_fine(self) -> None:
        baseline = _matrix(tp=100, fp=20, tn=180, fn=20)
        candidate = _matrix(tp=105, fp=10, tn=190, fn=15)
        result = gates.evaluate(
            baseline=baseline,
            candidate=candidate,
            baseline_dataset_fingerprint="aaaaaaaaaaaaaaaa",
            candidate_dataset_fingerprint="aaaaaaaaaaaaaaaa",
        )
        assert result.passed is True


class TestGateReporting:
    def test_every_check_reports_its_threshold_and_observed_value(self) -> None:
        baseline = _matrix(tp=100, fp=20, tn=180, fn=20)
        candidate = _matrix(tp=98, fp=10, tn=190, fn=22)
        result = gates.evaluate(baseline=baseline, candidate=candidate)

        for check in result.checks:
            assert check.name
            assert check.description
            if check.status != "not_measured":
                assert check.threshold is not None
                assert check.observed is not None


class TestCandidateEvaluation:
    """The runner that turns two model artifacts into two confusion matrices on
    the same labelled data, so the gates have something real to judge."""

    def test_a_candidate_is_evaluated_against_the_deployed_model(
        self, db, tmp_path
    ) -> None:
        from app.adaptation.candidates import evaluation, training
        from app.ml.registry import registry

        candidate = training.train_candidate(
            db, samples=600, seed=4242, directory=tmp_path, created_by="test"
        )
        baseline = registry.get_active(db, "isolation_forest")

        report = evaluation.evaluate_candidate(
            db, candidate=candidate, baseline=baseline, samples_per_class=6
        )

        assert report["candidate"]["identity"] == candidate.identity
        assert report["dataset"]["fingerprint"]
        # Both sides measured on the same data, or the comparison is meaningless.
        assert report["dataset"]["samples"] > 0
        assert "gates" in report
        assert "passed" in report["gates"]

    def test_evaluation_does_not_change_the_candidate_status(self, db, tmp_path) -> None:
        from app.adaptation.candidates import evaluation, training
        from app.models.enums import MLModelStatus

        candidate = training.train_candidate(
            db, samples=600, seed=4242, directory=tmp_path, created_by="test"
        )
        evaluation.evaluate_candidate(db, candidate=candidate, samples_per_class=6)
        db.refresh(candidate)

        assert candidate.status == MLModelStatus.CANDIDATE.value
        assert candidate.activated_at is None

    def test_the_report_carries_full_provenance(self, db, tmp_path) -> None:
        """V4 rule 19: a result without its dataset fingerprint, feature schema
        and model digest is not a result."""
        from app.adaptation.candidates import evaluation, training

        candidate = training.train_candidate(
            db, samples=600, seed=4242, directory=tmp_path, created_by="test"
        )
        report = evaluation.evaluate_candidate(db, candidate=candidate, samples_per_class=6)

        assert report["dataset"]["fingerprint"]
        assert report["candidate"]["artifactSha256"]
        assert report["candidate"]["featureSchemaVersion"]
        assert report["threshold"] is not None

    def test_evaluating_without_a_deployed_model_says_so(self, db, tmp_path) -> None:
        """An empty registry is a real condition. The report must name it rather
        than comparing against zeros."""
        from app.adaptation.candidates import evaluation, training

        candidate = training.train_candidate(
            db, samples=600, seed=4242, directory=tmp_path, created_by="test"
        )
        report = evaluation.evaluate_candidate(
            db, candidate=candidate, baseline=None, samples_per_class=6
        )

        assert report["baseline"] is None
        assert report["gates"]["passed"] is False
        assert any("baseline" in f.lower() for f in report["gates"]["failures"])


class TestPerCategoryRecallGate:
    """V6 §8 measured that a candidate can lose 20 points of recall on one
    attack category while aggregate recall moves less than its own seed noise.
    Every aggregate gate passes that candidate. This is the gate that does not."""

    def _matrix(self, *, tp: int, fn: int, fp: int = 5, tn: int = 500) -> ConfusionMatrix:
        return ConfusionMatrix(
            true_positives=tp, false_negatives=fn, false_positives=fp, true_negatives=tn
        )

    def test_a_single_category_collapse_fails_even_when_the_aggregate_passes(
        self,
    ) -> None:
        """The §8 attack, expressed as a gate input: aggregate recall barely
        moves, one category's recall halves."""
        baseline = self._matrix(tp=130, fn=26)
        candidate = self._matrix(tp=126, fn=30)  # aggregate recall 0.833 -> 0.808

        aggregate_only = gates.evaluate(baseline=baseline, candidate=candidate)
        assert aggregate_only.passed, "the aggregate gates must not see this"

        result = gates.evaluate(
            baseline=baseline,
            candidate=candidate,
            baseline_per_category={"MALWARE": self._matrix(tp=20, fn=4)},
            candidate_per_category={"MALWARE": self._matrix(tp=10, fn=14)},
        )
        assert not result.passed
        assert any("MALWARE" in failure for failure in result.failures)

    def test_a_category_within_the_bound_passes(self) -> None:
        result = gates.evaluate(
            baseline=self._matrix(tp=130, fn=26),
            candidate=self._matrix(tp=129, fn=27),
            baseline_per_category={"MALWARE": self._matrix(tp=20, fn=4)},
            candidate_per_category={"MALWARE": self._matrix(tp=20, fn=4)},
        )
        assert result.passed

    def test_absent_per_category_data_is_advisory_not_a_silent_pass(self) -> None:
        """Backward compatibility without pretending. Existing callers supply no
        per-category data, so vetoing would reject every candidate; but the
        absence is surfaced to the approver rather than treated as fine, which is
        what the `advisory` flag exists for."""
        result = gates.evaluate(
            baseline=self._matrix(tp=130, fn=26), candidate=self._matrix(tp=129, fn=27)
        )
        check = next(c for c in result.checks if c.name == "per_category_recall")
        assert check.advisory
        assert check.status == "not_measured"
        assert result.passed, "an advisory must not veto"

    def test_a_category_present_in_the_baseline_but_missing_from_the_candidate_fails(
        self,
    ) -> None:
        """A candidate evaluated on fewer categories than the incumbent has not
        been shown to be safe on the rest."""
        result = gates.evaluate(
            baseline=self._matrix(tp=130, fn=26),
            candidate=self._matrix(tp=129, fn=27),
            baseline_per_category={"MALWARE": self._matrix(tp=20, fn=4)},
            candidate_per_category={},
        )
        assert not result.passed

    def test_the_policy_states_its_rationale(self) -> None:
        rationale = gates.GatePolicy().rationale()
        assert "max_per_category_recall_drop" in rationale
        assert "min_category_samples" in rationale
