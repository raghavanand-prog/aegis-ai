"""Signals that make an event worth an analyst's attention.

Each selector returns a bounded [0, 1] score, so they can be combined into one
priority without any of them dominating by scale. They are deliberately simple
and separately testable: a review queue whose ordering nobody can explain is a
queue nobody trusts.
"""

from __future__ import annotations

#: Relative weights. Disagreement leads because it is the only signal that
#: identifies a case where one of two independent detectors is definitely wrong.
#: These are a starting policy, not a measured optimum, and V5 records which
#: weighting produced a queue so the choice stays arguable.
DEFAULT_WEIGHTS: dict[str, float] = {
    "disagreement": 0.45,
    "uncertainty": 0.35,
    "novelty": 0.20,
}


def uncertainty(score: float, *, threshold: float) -> float:
    """How close an anomaly score sits to the decision boundary.

    1.0 at the threshold, falling to 0.0 at whichever end of the range is
    further away. Symmetric on purpose: a near miss and a near hit are equally
    worth a human's time, and treating only one side as interesting is how a
    feedback set acquires a systematic bias toward the alerts that fired.
    """
    score = float(score)
    threshold = float(threshold)
    span = max(threshold, 1.0 - threshold)
    if span <= 0:
        return 0.0
    distance = abs(score - threshold)
    return max(0.0, 1.0 - (distance / span))


def disagreement(*, rule_hit: bool, ml_flagged: bool) -> float:
    """Whether the deterministic rules and the model reached different verdicts.

    The strongest available signal, because when two independent detectors
    disagree one of them is wrong, and which one is a question only a human can
    settle. Agreement carries no review value - both being right teaches nothing
    and both being wrong is invisible from here.
    """
    return 1.0 if bool(rule_hit) != bool(ml_flagged) else 0.0


def novelty(*, seen_count: int, horizon: int = 50) -> float:
    """How rarely this kind of event has been seen before.

    A behaviour the platform has scored a thousand times is well covered by
    existing feedback; one it has seen twice is not. Saturates at ``horizon`` so
    that a single unseen event cannot outrank a genuine disagreement.
    """
    seen_count = max(int(seen_count), 0)
    if seen_count >= horizon:
        return 0.0
    return 1.0 - (seen_count / horizon)


def combine(signals: dict[str, float], *, weights: dict[str, float] | None = None) -> float:
    """Weighted priority in [0, 1]."""
    weights = weights or DEFAULT_WEIGHTS
    total_weight = sum(weights.get(name, 0.0) for name in signals)
    if total_weight <= 0:
        return 0.0
    score = sum(signals[name] * weights.get(name, 0.0) for name in signals)
    return max(0.0, min(1.0, score / total_weight))
