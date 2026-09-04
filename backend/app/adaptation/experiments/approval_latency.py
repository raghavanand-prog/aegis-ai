"""Approval-workflow latency: the part of it a machine can honestly measure.

**What this measures, and what it deliberately does not.**

An adaptation reaches production through four service-layer transitions:

    create  ->  approve  ->  mark_deployed  ->  (mark_rolled_back)

Each is a database transaction plus the invariant checks V5-V7 put in front of
it: the status machine, the permission matrix, the four-eyes refusal, and - on
deployment - ``registry.activate_model``, the single chokepoint between the
candidate lifecycle and the serving model. This module times those transitions.

That is **system processing latency**. It is the cost the platform adds to a
decision, and it is reproducible: same machine, same backend, same numbers to
within ordinary scheduling noise.

**It is not approval latency in the sense that matters operationally.** The
number a SOC cares about is how long a proposal waits for a human to read the
evidence and decide, and that is dominated entirely by the human. V5 §7 listed
"human approval latency is unmeasured, deliberately"; V6 listed it; V7 did not
reach it. This module does not close that gap and must not be read as closing
it - **no analyst population exists**, so there is nothing to time.

Measuring it against the feedback simulator was considered and rejected. The
simulator models an analyst's *verdicts* - noise, coverage, abstention, a
false-positive bias - and models nothing whatever about how long a person takes
to reach one. Timing it would produce a number that is a property of a
``sleep`` somebody chose, dressed as a finding about human behaviour. V6 spent a
session establishing what that failure looks like; repeating it here to fill a
row in a table would be the same mistake with a stopwatch.

So the two are reported separately and one of them is reported as absent. What
would close it is a real study: instrument the queue in a deployment with real
analysts, record submit-to-decision wall time per proposal, and report the
distribution with the population size and the selection effects stated.

**[LIMITATION]** Even the machine half is laptop-and-SQLite, single process, on
a database holding a handful of rows. It is a floor, not a throughput claim: it
excludes HTTP, authentication, serialization, and any contention. A deployment
on PostgreSQL under load will be slower, and nothing here predicts by how much.
"""

from __future__ import annotations

import statistics
import time
from dataclasses import dataclass, field
from typing import Any

from app.adaptation.proposals import service as proposals
from app.models.enums import ProposalType

#: The transitions timed, in the order production performs them.
STAGES = ("create", "approve", "deploy", "rollback")

PROPOSER = "analyst@aegisx.dev"
APPROVER = "admin@aegisx.dev"
DEPLOYER = "admin@aegisx.dev"


@dataclass
class LatencySamples:
    """Per-stage wall-clock samples, in milliseconds."""

    stages: dict[str, list[float]] = field(default_factory=dict)

    def record(self, stage: str, milliseconds: float) -> None:
        self.stages.setdefault(stage, []).append(milliseconds)

    def summarise(self) -> dict[str, Any]:
        return {stage: _describe(values) for stage, values in self.stages.items()}


def _percentile(values: list[float], pct: float) -> float | None:
    """Nearest-rank percentile. ``None`` for an empty sample.

    Nearest-rank rather than an interpolating estimator because every reported
    value is then one that was actually observed. An interpolated p95 on 20
    samples is a number no run produced.
    """
    if not values:
        return None
    ordered = sorted(values)
    rank = max(1, min(len(ordered), int(-(-pct * len(ordered) // 100))))
    return round(ordered[rank - 1], 4)


def _describe(values: list[float]) -> dict[str, Any]:
    if not values:
        return {"samples": 0, "mean": None, "p50": None, "p95": None,
                "min": None, "max": None, "stdev": None}
    return {
        "samples": len(values),
        "mean": round(statistics.fmean(values), 4),
        "p50": _percentile(values, 50),
        "p95": _percentile(values, 95),
        "min": round(min(values), 4),
        "max": round(max(values), 4),
        # Population stdev: these are all the samples taken, not a draw from a
        # larger set.
        "stdev": round(statistics.pstdev(values), 4) if len(values) > 1 else 0.0,
    }


def _timed(fn, *args, **kwargs) -> tuple[Any, float]:  # noqa: ANN001
    start = time.perf_counter()
    result = fn(*args, **kwargs)
    return result, (time.perf_counter() - start) * 1000.0


def _timed_refusal(fn, *args, **kwargs) -> float:  # noqa: ANN001
    """Time a call that is *expected* to raise, and insist that it does.

    Written as its own helper after the obvious version produced a measurement
    bug: timing the call inside a ``try`` and recording the elapsed time after
    the ``except`` leaves the timing variable holding whatever the *previous*
    stage measured, because the assignment never happens when the call raises.
    The first run of this module duly reported the four-eyes refusal and
    ``create`` as having identical latency to four decimal places - which is the
    kind of coincidence that should always be read as a bug rather than a
    finding.
    """
    start = time.perf_counter()
    try:
        fn(*args, **kwargs)
    except ValueError:
        return (time.perf_counter() - start) * 1000.0
    raise AssertionError(
        "a self-approval succeeded; four-eyes is not being enforced"
    )


def measure(db, *, iterations: int = 20) -> dict[str, Any]:  # noqa: ANN001 - Session
    """Time ``iterations`` complete approval workflows against ``db``.

    A threshold proposal is used rather than a model update: it exercises the
    same status machine, permission matrix and four-eyes refusal without
    requiring a fitted artifact, so the number is about the *workflow* rather
    than about scikit-learn.
    """
    if iterations < 1:
        raise ValueError("iterations must be at least 1")

    samples = LatencySamples()
    refusals = {"self_approval": 0}

    for index in range(iterations):
        proposal, ms = _timed(
            proposals.create,
            db,
            proposal_type=ProposalType.THRESHOLD_UPDATE,
            title=f"Raise the anomaly threshold (latency probe {index})",
            reason="Measuring the workflow's own cost, not a detection claim.",
            affected_component="ml.anomaly_threshold",
            before_state={"threshold": 0.65},
            after_state={"threshold": 0.7},
            evidence={"probe": index},
            proposed_by=PROPOSER,
            proposed_by_role="analyst",
        )
        samples.record("create", ms)

        # The four-eyes refusal is on the approval path, so its cost is part of
        # what an approver waits for whenever a proposer tries their own
        # proposal. Timed separately rather than folded into `approve`.
        ms = _timed_refusal(
            proposals.approve,
            db,
            proposal.id,
            approved_by=PROPOSER,
            approver_role="analyst",
        )
        refusals["self_approval"] += 1
        samples.record("refused_self_approval", ms)

        _, ms = _timed(
            proposals.approve,
            db,
            proposal.id,
            approved_by=APPROVER,
            approver_role="admin",
        )
        samples.record("approve", ms)

        _, ms = _timed(
            proposals.mark_deployed, db, proposal.id, deployed_by=DEPLOYER
        )
        samples.record("deploy", ms)

        _, ms = _timed(
            proposals.mark_rolled_back,
            db,
            proposal.id,
            rolled_back_by=DEPLOYER,
            reason="Latency probe; the rollback path is timed too.",
        )
        samples.record("rollback", ms)

    per_stage = samples.summarise()
    end_to_end = [
        sum(samples.stages[stage][i] for stage in STAGES)
        for i in range(iterations)
    ]

    return {
        "iterations": iterations,
        "perStage": per_stage,
        "endToEnd": _describe(end_to_end),
        "refusals": refusals,
        "measures": (
            "System processing latency of the approval workflow's service-layer "
            "transitions: the status machine, the permission matrix, the "
            "four-eyes refusal and the deployment chokepoint, plus their "
            "database transactions."
        ),
        "doesNotMeasure": (
            "Human analyst decision latency. No analyst population exists, so "
            "submit-to-decision time is UNMEASURED and cannot be inferred from "
            "anything in this repository. Timing the feedback simulator would "
            "report a property of the simulator, not of people."
        ),
        "humanLatencyStatus": "UNMEASURED",
        "humanLatencyRequires": (
            "A study against a real analyst population: instrument the proposal "
            "queue in a deployment, record submit-to-decision wall time per "
            "proposal, and report the distribution with the population size and "
            "the selection effects stated."
        ),
    }
