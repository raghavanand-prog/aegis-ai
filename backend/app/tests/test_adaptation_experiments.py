"""V5 adaptation experiments (Phase L).

These tests cover the *instrument*, not the findings. A simulated analyst whose
noise rate is wrong, or a curation step that quietly drops the wrong rows, would
produce results that look fine and mean nothing.
"""

from __future__ import annotations

import pytest

from app.adaptation.experiments import simulation
from app.adaptation.feedback.labels import FeedbackLabel


class TestSimulatedAnalyst:
    def test_the_same_seed_produces_the_same_feedback(self) -> None:
        truth = [True, False, True, False] * 25
        first = simulation.simulate_feedback(truth, seed=7)
        second = simulation.simulate_feedback(truth, seed=7)
        assert [item.label for item in first] == [item.label for item in second]

    def test_zero_noise_and_full_coverage_agrees_with_truth(self) -> None:
        truth = [True, False] * 50
        feedback = simulation.simulate_feedback(
            truth, seed=1, noise_rate=0.0, coverage=1.0, abstention_rate=0.0
        )
        assert len(feedback) == len(truth)
        for item in feedback:
            assert item.label.binary_label is truth[item.index]

    def test_noise_flips_roughly_the_requested_share(self) -> None:
        """Approximate on purpose - an exact count would be testing the RNG."""
        truth = [True, False] * 500
        feedback = simulation.simulate_feedback(
            truth, seed=3, noise_rate=0.15, coverage=1.0, abstention_rate=0.0
        )
        wrong = sum(1 for item in feedback if item.label.binary_label is not truth[item.index])
        assert 0.10 < wrong / len(feedback) < 0.20

    def test_coverage_limits_how_much_is_reviewed(self) -> None:
        truth = [True, False] * 250
        feedback = simulation.simulate_feedback(truth, seed=5, coverage=0.25)
        assert 0.15 < len(feedback) / len(truth) < 0.35

    def test_abstention_produces_uncertain_labels(self) -> None:
        truth = [True, False] * 250
        feedback = simulation.simulate_feedback(
            truth, seed=11, coverage=1.0, abstention_rate=0.2, noise_rate=0.0
        )
        uncertain = [item for item in feedback if item.label is FeedbackLabel.UNCERTAIN]
        assert uncertain, "abstention should produce uncertain verdicts"
        # And an uncertain verdict carries no binary position, so it cannot
        # silently become a training label.
        assert all(item.label.binary_label is None for item in uncertain)

    def test_shuffled_control_destroys_the_label_signal(self) -> None:
        """The control the whole comparison rests on. If this still correlates
        with truth, it is not a control."""
        truth = [True] * 200 + [False] * 200
        shuffled = simulation.simulate_feedback(
            truth, seed=13, coverage=1.0, noise_rate=0.0, abstention_rate=0.0, shuffle_labels=True
        )
        agreement = sum(
            1 for item in shuffled if item.label.binary_label is truth[item.index]
        ) / len(shuffled)
        assert 0.35 < agreement < 0.65, "shuffled labels should be near chance"


class TestThresholdArm:
    def test_the_chosen_threshold_is_bounded_by_the_safety_step(self) -> None:
        scores = [0.1, 0.2, 0.6, 0.66, 0.7, 0.9]
        truth = [False, False, False, True, True, True]
        chosen = simulation.choose_threshold(
            scores, truth, current=0.65, max_step=0.05
        )
        assert abs(chosen - 0.65) <= 0.05

    def test_it_prefers_an_operating_point_that_reduces_false_positives(self) -> None:
        # Benign scores cluster just above the current threshold.
        scores = [0.66, 0.67, 0.68] * 20 + [0.95] * 10
        truth = [False] * 60 + [True] * 10
        chosen = simulation.choose_threshold(scores, truth, current=0.65, max_step=0.05)
        assert chosen > 0.65

    def test_it_refuses_to_choose_from_no_labelled_data(self) -> None:
        with pytest.raises(ValueError, match="labelled"):
            simulation.choose_threshold([], [], current=0.65, max_step=0.05)


class TestCurationArm:
    def test_curation_drops_events_analysts_called_malicious(self) -> None:
        """Isolation Forest assumes its fit set is mostly normal. Curation is
        the only way feedback can act on that assumption."""
        vectors = [(float(i),) for i in range(10)]
        verdicts = {0: False, 1: True, 2: False, 3: True}
        kept = simulation.curate_fit_set(vectors, verdicts)
        assert len(kept) == len(vectors) - 2
        assert (1.0,) not in kept and (3.0,) not in kept

    def test_unreviewed_events_are_kept(self) -> None:
        """Absence of a verdict is not evidence of malice, and dropping
        unreviewed data would shrink the corpus for no reason."""
        vectors = [(float(i),) for i in range(10)]
        kept = simulation.curate_fit_set(vectors, {1: True})
        assert len(kept) == 9

    def test_curation_refuses_to_empty_the_fit_set(self) -> None:
        vectors = [(1.0,), (2.0,)]
        with pytest.raises(ValueError, match="fit set"):
            simulation.curate_fit_set(vectors, {0: True, 1: True})
