"""Arm 2, redesigned so it can act in the production configuration.

V5's curation purified the fit set, which assumed the fit set and the observed
event stream were the same collection. V6 §5 measured that they are not:
production fits unlabelled runtime telemetry, so analyst labels have nothing
there to purify.

The redesign inverts the direction. Instead of removing analyst-identified
malicious rows from a corpus of observed events, it *adds* analyst-verified
benign observed events to the telemetry corpus - teaching the density model that
this traffic is normal. That is a use of labels an unsupervised model can
consume, and it targets the measured weakness: a 34% false-positive rate.

Adding analyst-supplied rows to training data is a poisoning surface, so most of
these tests are about what may not get in.
"""

from __future__ import annotations

import pytest

from app.adaptation.experiments import arm2
from app.adaptation.feedback.labels import FeedbackLabel


class TestAdmissionRules:
    def test_only_verified_benign_events_are_admitted(self) -> None:
        built = arm2.build_augmented_corpus(seed=1337)
        for label in built["admittedLabels"]:
            assert FeedbackLabel(label).is_training_eligible
            assert FeedbackLabel(label).binary_label is False

    def test_events_called_malicious_are_never_admitted(self) -> None:
        """The whole poisoning concern in one property. A confirmed-malicious
        event added to an anomaly model's fit set teaches it that the attack is
        normal."""
        built = arm2.build_augmented_corpus(seed=1337)
        assert FeedbackLabel.CONFIRMED_MALICIOUS.value not in built["admittedLabels"]
        assert FeedbackLabel.TRUE_POSITIVE.value not in built["admittedLabels"]

    def test_hesitation_is_never_admitted(self) -> None:
        built = arm2.build_augmented_corpus(seed=1337)
        assert FeedbackLabel.UNCERTAIN.value not in built["admittedLabels"]
        assert FeedbackLabel.SUSPICIOUS.value not in built["admittedLabels"]

    def test_the_feedback_share_is_capped(self) -> None:
        """Bounds the blast radius of a mistaken or hostile analyst. Without a
        cap, enough benign-labelled verdicts could rewrite the training
        distribution outright."""
        built = arm2.build_augmented_corpus(seed=1337, max_feedback_fraction=0.05)
        assert built["feedbackFraction"] <= 0.05 + 1e-9

    def test_a_cap_outside_the_unit_interval_is_refused(self) -> None:
        with pytest.raises(ValueError, match="between 0 and"):
            arm2.build_augmented_corpus(seed=1337, max_feedback_fraction=1.5)

    def test_the_telemetry_corpus_is_augmented_never_replaced(self) -> None:
        built = arm2.build_augmented_corpus(seed=1337)
        assert built["telemetryRows"] > 0
        assert built["size"] == built["telemetryRows"] + built["feedbackRows"]


class TestPoisoningIsBounded:
    def test_an_analyst_labelling_everything_benign_cannot_dominate_training(
        self,
    ) -> None:
        """The adversarial case, measured rather than argued: every verdict is
        'benign', including on genuinely malicious events. The cap must still
        hold, and the admitted rows must stay a bounded minority."""
        built = arm2.build_augmented_corpus(
            seed=1337, max_feedback_fraction=0.20, all_benign_attack=True
        )
        assert built["feedbackFraction"] <= 0.20 + 1e-9
        assert built["poisonedRows"] > 0, "the scenario must actually poison"
        assert built["poisonedRows"] <= built["feedbackRows"]


class TestNoLeakage:
    def test_every_admitted_event_comes_from_the_fit_split(self) -> None:
        """The property that actually prevents training on test data. Feedback
        indexes the fit split, and the splitter makes fit and test
        sample-disjoint, so no scored sample can be trained on."""
        result = arm2.measure(seed=1337)
        assert result["admittedOutsideFitSplit"] == 0

    def test_shared_feature_vectors_are_reported_not_hidden(self) -> None:
        """Distinct events can share a feature vector - V6 §2.7 measured 5.1% of
        test rows. That is corpus coarseness, not leakage, and the number is
        surfaced so nobody has to rediscover it and assume the worse
        explanation."""
        result = arm2.measure(seed=1337)
        collisions = result["admittedVectorsAlsoSeenInScoringSet"]
        assert 0 <= collisions <= 0.10 * result["feedbackRows"]


class TestMeasurement:
    def test_it_reports_against_the_production_baseline(self) -> None:
        result = arm2.measure(seed=1337)
        assert result["baseline"]["f1"] is not None
        assert result["augmented"]["f1"] is not None
        assert result["fitCorpus"] == "runtime-telemetry-generator + verified-benign feedback"

    def test_it_is_deterministic_for_a_seed(self) -> None:
        assert arm2.measure(seed=99)["augmented"]["f1"] == arm2.measure(seed=99)["augmented"]["f1"]


class TestArm2Runner:
    def test_it_reports_the_safety_bounds_beside_the_metrics(self, tmp_path) -> None:
        import json

        from app.adaptation.experiments import run_arm2_eval

        assert (
            run_arm2_eval.main(
                ["--seeds", "3", "--output-dir", str(tmp_path), "--max-seconds", "900"]
            )
            == 0
        )
        report = json.loads(next(tmp_path.glob("v6-arm2-*.json")).read_text())
        assert report["design"]["admission"]
        assert report["composition"]["admittedOutsideFitSplit"] == 0
        assert report["comparison"]["falsePositiveRate"]["cohensD"] is not None
