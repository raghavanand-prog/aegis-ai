"""Approval-latency measurement: what it measures and what it refuses to claim.

The value of this module is almost entirely in what it declines to say. V5, V6
and V7 all listed human approval latency as unmeasured; the temptation in V8 was
to time the feedback simulator and put a number in the row. These tests hold the
boundary instead: the machine half is measured, the human half is reported as
``UNMEASURED``, and no code path can turn one into the other.

One test exists because the first version of the measurement was wrong. Timing a
call inside ``try`` and recording the elapsed time after ``except`` leaves the
timing variable holding the *previous* stage's value, so the refusal and
``create`` were reported with identical latency to four decimal places.
"""

from __future__ import annotations

import pytest

from app.adaptation.experiments import approval_latency
from app.models.enums import ProposalStatus


class TestWhatItMeasures:
    def test_every_workflow_stage_is_timed(self, db) -> None:
        result = approval_latency.measure(db, iterations=3)

        for stage in approval_latency.STAGES:
            stats = result["perStage"][stage]
            assert stats["samples"] == 3
            assert stats["mean"] > 0
            assert stats["p50"] is not None

    def test_the_four_eyes_refusal_is_exercised_every_iteration(self, db) -> None:
        """The refusal is on the approval path, so its cost is part of what an
        approver waits for. It is also a live check that four-eyes still holds:
        ``measure`` raises if a self-approval ever succeeds."""
        result = approval_latency.measure(db, iterations=4)

        assert result["refusals"]["self_approval"] == 4
        assert result["perStage"]["refused_self_approval"]["samples"] == 4

    def test_the_refusal_is_timed_separately_from_create(self, db) -> None:
        """The regression test for the measurement bug.

        These two stages have no reason to agree: ``create`` writes a row and
        the refusal fails before it writes anything. Identical statistics meant
        the refusal was reporting ``create``'s timing.
        """
        result = approval_latency.measure(db, iterations=10)

        created = result["perStage"]["create"]
        refused = result["perStage"]["refused_self_approval"]
        assert created["mean"] != refused["mean"]
        # A refusal that fails closed early must not cost more than the write it
        # prevents; if it ever does, the guard has grown expensive.
        assert refused["p50"] < created["p50"]

    def test_the_workflow_actually_completes(self, db) -> None:
        """A latency number for a workflow that did not run is meaningless."""
        from app.adaptation.proposals import service as proposals

        approval_latency.measure(db, iterations=2)
        rows = proposals.list_proposals(db, limit=50)
        probes = [p for p in rows if "latency probe" in p.title]

        assert len(probes) == 2
        assert all(p.status == ProposalStatus.ROLLED_BACK.value for p in probes)
        # Four-eyes held throughout: nothing was approved by its proposer.
        assert all(not p.self_approved for p in probes)

    def test_end_to_end_is_the_sum_of_the_stages(self, db) -> None:
        """End-to-end is summed per iteration from unrounded samples, while each
        stage mean is rounded to 4dp for reporting, so the two agree only to
        within that rounding - half an ulp per stage."""
        result = approval_latency.measure(db, iterations=5)

        stage_means = sum(result["perStage"][s]["mean"] for s in approval_latency.STAGES)
        tolerance = 0.00005 * len(approval_latency.STAGES)
        assert result["endToEnd"]["mean"] == pytest.approx(stage_means, abs=tolerance)


class TestWhatItRefusesToClaim:
    def test_human_latency_is_reported_as_unmeasured(self, db) -> None:
        result = approval_latency.measure(db, iterations=1)

        assert result["humanLatencyStatus"] == "UNMEASURED"
        assert result["humanLatencyRequires"]

    def test_no_stage_is_named_as_human_decision_time(self, db) -> None:
        """`UNMEASURED` and a measured number must not be reachable by the same
        path - V7's decision 42, applied to latency."""
        result = approval_latency.measure(db, iterations=1)

        for stage in result["perStage"]:
            assert "human" not in stage.lower()
            assert "analyst" not in stage.lower()
            assert "decision" not in stage.lower()

    def test_the_report_says_what_it_does_not_measure(self, db) -> None:
        result = approval_latency.measure(db, iterations=1)

        assert "UNMEASURED" in result["doesNotMeasure"]
        assert "simulator" in result["doesNotMeasure"].lower()


class TestEdges:
    def test_zero_iterations_is_refused(self, db) -> None:
        """Reporting statistics over an empty sample would be a fabrication."""
        with pytest.raises(ValueError, match="at least 1"):
            approval_latency.measure(db, iterations=0)

    def test_a_single_iteration_reports_zero_spread_not_a_crash(self, db) -> None:
        result = approval_latency.measure(db, iterations=1)

        assert result["perStage"]["create"]["stdev"] == 0.0
        assert result["perStage"]["create"]["samples"] == 1

    def test_percentiles_are_observed_values(self, db) -> None:
        """Nearest-rank, so every reported percentile is a real sample."""
        values = [5.0, 1.0, 3.0, 2.0, 4.0]
        assert approval_latency._percentile(values, 50) == 3.0
        assert approval_latency._percentile(values, 100) == 5.0
        assert approval_latency._percentile([], 50) is None
