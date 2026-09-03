"""Track 2: how feedback quality affects the redesigned Arm 2.

Track 2 was designed against V5's arm. §6 replaced that arm, which changes what
the question means. The redesigned arm admits analyst-verified *benign* rows into
training data, so the conditions that matter most are the ones that push analysts
toward calling things benign - those are simultaneously a quality problem and a
poisoning vector.

Ground truth, analyst labels and model predictions stay separate throughout, as
V5 required.
"""

from __future__ import annotations

import pytest

from app.adaptation.experiments import feedback_quality as fq
from app.adaptation.feedback.labels import FeedbackLabel


class TestConditionRegistry:
    def test_every_condition_documents_what_it_models(self) -> None:
        for spec in fq.CONDITIONS.values():
            assert spec.description.strip()

    def test_the_baseline_condition_matches_the_v5_simulator(self) -> None:
        """A control. If `nominal` ever diverges from the settings V5 and Track 1
        used, every comparison against them silently changes meaning."""
        spec = fq.CONDITIONS["nominal"]
        assert spec.noise_rate == 0.05
        assert spec.coverage == 0.5


class TestGroundTruthSeparation:
    def test_analyst_labels_never_overwrite_ground_truth(self) -> None:
        verdicts, truth = fq.generate(condition="benign_biased", seed=1337)
        # The simulator may be wrong about many of these; truth is unchanged.
        assert truth == fq.ground_truth(seed=1337)
        assert any(
            v.label.binary_label is not truth[v.index]
            for v in verdicts
            if v.label.binary_label is not None
        ), "a biased analyst should disagree with truth somewhere"

    def test_erroneous_verdicts_are_flagged_not_silently_correct(self) -> None:
        verdicts, truth = fq.generate(condition="high_noise", seed=1337)
        flagged = [v for v in verdicts if v.is_erroneous]
        assert flagged, "high noise must actually produce errors"
        for verdict in flagged:
            assert verdict.label.binary_label is not truth[verdict.index]


class TestConditionsBehaveAsNamed:
    def test_benign_bias_admits_more_rows_than_nominal(self) -> None:
        """The poisoning-relevant condition: an analyst who calls things benign
        feeds more rows into a fit set that only accepts benign."""
        nominal, _ = fq.generate(condition="nominal", seed=1337)
        biased, _ = fq.generate(condition="benign_biased", seed=1337)
        assert fq.admissible_count(biased) > fq.admissible_count(nominal)

    def test_malicious_bias_admits_fewer_rows_than_nominal(self) -> None:
        nominal, _ = fq.generate(condition="nominal", seed=1337)
        biased, _ = fq.generate(condition="malicious_biased", seed=1337)
        assert fq.admissible_count(biased) < fq.admissible_count(nominal)

    def test_sparse_feedback_produces_fewer_verdicts(self) -> None:
        nominal, _ = fq.generate(condition="nominal", seed=1337)
        sparse, _ = fq.generate(condition="sparse", seed=1337)
        assert len(sparse) < len(nominal)

    def test_uncertain_heavy_produces_mostly_untrainable_verdicts(self) -> None:
        verdicts, _ = fq.generate(condition="uncertain_heavy", seed=1337)
        uncertain = [v for v in verdicts if v.label is FeedbackLabel.UNCERTAIN]
        assert len(uncertain) > 0.25 * len(verdicts)

    def test_delayed_feedback_covers_only_the_earlier_events(self) -> None:
        """Feedback arrives late, so recent events are unreviewed. The indices
        are chronological, so a delayed analyst never labels the tail."""
        verdicts, truth = fq.generate(condition="delayed", seed=1337)
        assert max(v.index for v in verdicts) < len(truth) - 1

    def test_conflicting_labels_are_superseded_not_duplicated(self) -> None:
        """Feedback is append-only and corrections supersede, so a consumer must
        see one verdict per event - the latest."""
        verdicts, _ = fq.generate(condition="conflicting", seed=1337)
        indices = [v.index for v in verdicts]
        assert len(indices) == len(set(indices))

    def test_an_unknown_condition_is_refused(self) -> None:
        with pytest.raises(KeyError, match="unknown condition"):
            fq.generate(condition="nope", seed=1337)


class TestMeasurement:
    def test_it_measures_each_condition_against_the_same_baseline(self) -> None:
        result = fq.measure(condition="nominal", seed=1337)
        assert result["baseline"]["falsePositiveRate"] is not None
        assert result["augmented"]["falsePositiveRate"] is not None
        assert result["feedbackRows"] >= 0
        assert result["condition"] == "nominal"


class TestFeedbackQualityRunner:
    def test_it_reports_recall_beside_the_false_positive_rate(self, tmp_path) -> None:
        """Recall is the only one of these metrics that exposes benign bias, so
        a report that omitted it would hide the failure mode it exists to find."""
        import json

        from app.adaptation.experiments import run_feedback_quality_eval

        assert (
            run_feedback_quality_eval.main(
                [
                    "--seeds",
                    "2",
                    "--conditions",
                    "nominal",
                    "benign_biased",
                    "--output-dir",
                    str(tmp_path),
                    "--max-seconds",
                    "900",
                ]
            )
            == 0
        )
        report = json.loads(
            next(tmp_path.glob("v6-feedback-quality-*.json")).read_text()
        )
        for row in report["results"]:
            assert row["comparison"]["recall"]["delta"] is not None
            assert row["comparison"]["falsePositiveRate"]["delta"] is not None
            assert row["description"]
