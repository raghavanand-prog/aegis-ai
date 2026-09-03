"""Building the analyst review queue.

Computed on demand rather than stored. A persisted queue would be a second
source of truth that goes stale the moment an analyst gives feedback, and the
inputs here are cheap to re-read. What *is* durable is the feedback an analyst
produces afterwards - that is the artifact worth keeping.

Nothing in this module writes. A test asserts that selecting candidates leaves
the feedback, dataset and model tables untouched.
"""

from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.adaptation.active_learning import selectors
from app.adaptation.feedback.labels import FeedbackTargetType
from app.models.adaptation import AnalystFeedback
from app.models.event import Event
from app.models.ml import MLInference

#: How many recent events to consider. Bounded because a review queue over the
#: whole event table is a table scan on the ingestion database.
DEFAULT_POOL = 500


@dataclass(frozen=True)
class ReviewCandidate:
    """One event recommended for analyst review, and why."""

    event_id: int
    public_id: str
    title: str
    priority: float
    reason: str
    signals: dict[str, float]
    anomaly_score: float | None
    threshold: float | None
    rule_hit: bool
    ml_flagged: bool
    risk_score: int

    def as_dict(self) -> dict:
        return {
            "eventId": self.public_id,
            "title": self.title,
            "priority": round(self.priority, 4),
            "reason": self.reason,
            "signals": {name: round(value, 4) for name, value in self.signals.items()},
            "anomalyScore": self.anomaly_score,
            "threshold": self.threshold,
            "ruleHit": self.rule_hit,
            "mlFlagged": self.ml_flagged,
            "riskScore": self.risk_score,
        }


def _reason(signals: dict[str, float]) -> str:
    """Plain-language explanation of why this event is in the queue."""
    parts: list[str] = []
    if signals.get("disagreement", 0.0) > 0:
        parts.append("the rules and the model disagree")
    if signals.get("uncertainty", 0.0) >= 0.5:
        parts.append("the anomaly score sits close to the decision threshold")
    if signals.get("novelty", 0.0) >= 0.5:
        parts.append("this behaviour has rarely been seen before")
    if not parts:
        return "Selected to keep the reviewed sample representative of ordinary traffic."
    return "Recommended because " + ", and ".join(parts) + "."


def select_candidates(
    db: Session,
    *,
    limit: int = 25,
    pool: int = DEFAULT_POOL,
    weights: dict[str, float] | None = None,
) -> list[ReviewCandidate]:
    """Rank recent events by how much an analyst's verdict would be worth.

    Events that already carry feedback are excluded: asking again wastes the
    analyst's time and would over-weight whatever they already told us.
    """
    already_reviewed = set(
        db.scalars(
            select(AnalystFeedback.target_id).where(
                AnalystFeedback.target_type == FeedbackTargetType.EVENT.value
            )
        )
    )

    # How often each event type has been seen, for the novelty signal.
    seen_counts = dict(
        db.execute(select(Event.event_type, func.count(Event.id)).group_by(Event.event_type)).all()
    )

    events = list(
        db.scalars(select(Event).order_by(Event.id.desc()).limit(pool))
    )

    inferences = {
        inference.event_id: inference
        for inference in db.scalars(
            select(MLInference).where(
                MLInference.event_id.in_([event.id for event in events] or [0])
            )
        )
    }

    candidates: list[ReviewCandidate] = []
    for event in events:
        if event.id in already_reviewed:
            continue

        inference = inferences.get(event.id)
        anomaly_score = inference.anomaly_score if inference else None
        threshold = inference.threshold if inference else None
        ml_flagged = bool(inference.is_anomaly) if inference else False
        rule_hit = bool(event.detection_rules)

        signals = {
            "disagreement": selectors.disagreement(rule_hit=rule_hit, ml_flagged=ml_flagged),
            "uncertainty": (
                selectors.uncertainty(anomaly_score, threshold=threshold)
                if anomaly_score is not None and threshold is not None
                else 0.0
            ),
            "novelty": selectors.novelty(seen_count=seen_counts.get(event.event_type, 0)),
        }
        priority = selectors.combine(signals, weights=weights)

        candidates.append(
            ReviewCandidate(
                event_id=event.id,
                public_id=event.event_id,
                title=event.title,
                priority=priority,
                reason=_reason(signals),
                signals=signals,
                anomaly_score=anomaly_score,
                threshold=threshold,
                rule_hit=rule_hit,
                ml_flagged=ml_flagged,
                risk_score=int(event.risk_score or 0),
            )
        )

    # Ties break on event id so that two calls over unchanged data return the
    # same order. A queue that reshuffles itself between refreshes is unusable.
    candidates.sort(key=lambda item: (-item.priority, item.event_id))
    return candidates[:limit]
