"""Re-running V5's comparison without the frozen-threshold confound.

V6 §15 classified ten of eleven comparison sites as confounded: they compare
models fitted on different data at one frozen 0.65, and §14 measured that such a
threshold names a different operating point per model. V5's headline is the most
affected, because its adapted arms refit while the static baseline does not.

Three matched comparisons, each answering a different question:

``rocAuc``
    Capability with no operating point at all. Rank-based, so calibration
    cannot touch it.
``bestF1``
    Each model at its own optimum. Comparable, but an optimistic ceiling chosen
    with knowledge of the labels that no operator gets.
``recallAtMatchedBudget``
    Every model allowed the same number of alerts. This is the operationally
    honest match: a SOC has fixed analyst capacity, and a model that "wins" by
    flagging five times as much has not won.
"""

from __future__ import annotations

import pytest

from app.adaptation.experiments import matched_operating_point as mop


class TestMatchedBudget:
    def test_every_condition_is_scored_at_the_same_alert_budget(self) -> None:
        """The point of the budget comparison. Different alert volumes are not
        comparable recalls."""
        result = mop.run(seed=1337, conditions=("static_v4", "both_arms"), budget=40)
        for row in result["conditions"].values():
            assert row["alertsAtBudget"] == pytest.approx(40, abs=2)

    def test_it_reports_all_three_matched_measures(self) -> None:
        result = mop.run(seed=1337, conditions=("static_v4", "both_arms"), budget=40)
        for row in result["conditions"].values():
            assert row["rocAuc"] is not None
            assert row["bestF1"] is not None
            assert row["recallAtMatchedBudget"] is not None

    def test_the_frozen_figure_is_reported_beside_the_matched_ones(self) -> None:
        """So the size of the confound is visible rather than merely asserted."""
        result = mop.run(seed=1337, conditions=("static_v4", "both_arms"), budget=40)
        for row in result["conditions"].values():
            assert row["f1AtFrozen"] is not None
            assert row["frozenPercentile"] is not None

    def test_a_budget_larger_than_the_test_set_is_refused(self) -> None:
        with pytest.raises(ValueError, match="budget"):
            mop.run(seed=1337, conditions=("static_v4",), budget=10_000)


class TestTheControlIsPreserved:
    def test_the_random_label_control_is_available(self) -> None:
        """V5 decision 27: controls are published with results. The control is
        what decides whether any of this is attributable to feedback."""
        assert "random_feedback" in mop.DEFAULT_CONDITIONS

    def test_the_static_baseline_is_available(self) -> None:
        assert "static_v4" in mop.DEFAULT_CONDITIONS
