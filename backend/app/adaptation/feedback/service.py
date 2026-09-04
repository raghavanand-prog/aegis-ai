"""Submitting, correcting and reading analyst feedback.

Every write goes through here so that the two rules feedback rests on hold in
one place: confidence is validated rather than clamped, and a correction never
edits the row it corrects.
"""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.adaptation.feedback.labels import FeedbackLabel, FeedbackTargetType
from app.ai.grounding import TECHNIQUE_PATTERN
from app.ml.schemas import FEATURE_SCHEMA_VERSION
from app.models.adaptation import AnalystFeedback

#: Where a feedback row came from. Adaptation experiments must be able to
#: separate a claim a human made from one a simulation generated.
SOURCE_ANALYST = "analyst"
SOURCE_ACTIVE_LEARNING = "active_learning"
SOURCE_SIMULATION = "simulation"

VALID_SOURCES = frozenset({SOURCE_ANALYST, SOURCE_ACTIVE_LEARNING, SOURCE_SIMULATION})


def _validate_confidence(confidence: float | None) -> float | None:
    if confidence is None:
        return None
    if not 0.0 <= confidence <= 1.0:
        raise ValueError(
            f"confidence must be between 0.0 and 1.0, got {confidence!r}. "
            "A value outside the range is refused rather than clamped: clamping "
            "would record a certainty the analyst did not express."
        )
    return float(confidence)


def _validate_techniques(techniques: list[str] | None) -> list[str]:
    """Accept only well-formed MITRE technique identifiers.

    Feedback may *confirm* a technique. It may not introduce a string that will
    later be read as authoritative attribution, which is why a malformed id is
    refused rather than dropped - silently discarding it would leave the analyst
    believing they had recorded something.
    """
    if not techniques:
        return []
    cleaned: list[str] = []
    for technique in techniques:
        value = str(technique).strip()
        if not TECHNIQUE_PATTERN.fullmatch(value):
            raise ValueError(
                f"{technique!r} is not a MITRE ATT&CK technique id (expected "
                "T1234 or T1234.001). Feedback may confirm a technique, never invent one."
            )
        cleaned.append(value)
    return cleaned


def submit(
    db: Session,
    *,
    target_type: FeedbackTargetType,
    target_id: int,
    label: FeedbackLabel,
    analyst: str,
    confidence: float | None = None,
    comment: str | None = None,
    mitre_techniques: list[str] | None = None,
    evidence_reference: str | None = None,
    source: str = SOURCE_ANALYST,
    model_identity: str | None = None,
    analyst_id: int | None = None,
    analyst_role: str | None = None,
) -> AnalystFeedback:
    """Record one analyst claim. Never overwrites an existing one.

    ``analyst_id`` and ``analyst_role`` are V7 additions and are both optional:
    simulated feedback has no account behind it, and recording one would make a
    generated claim indistinguishable from a human's. The API supplies them
    from the authenticated user, never from the request body - a claim able to
    name its own author would not be evidence about anything.
    """
    if source not in VALID_SOURCES:
        raise ValueError(f"Unknown feedback source {source!r}; expected one of {sorted(VALID_SOURCES)}")

    record = AnalystFeedback(
        target_type=FeedbackTargetType(target_type).value,
        target_id=int(target_id),
        label=FeedbackLabel(label).value,
        confidence=_validate_confidence(confidence),
        comment=comment,
        mitre_techniques=_validate_techniques(mitre_techniques),
        evidence_reference=evidence_reference,
        analyst=analyst,
        analyst_id=analyst_id,
        analyst_role=analyst_role,
        source=source,
        feature_schema_version=FEATURE_SCHEMA_VERSION,
        model_identity=model_identity,
    )
    db.add(record)
    db.flush()
    return record


def correct(
    db: Session,
    *,
    feedback_id: int,
    label: FeedbackLabel,
    analyst: str,
    reason: str,
    confidence: float | None = None,
    comment: str | None = None,
    analyst_id: int | None = None,
    analyst_role: str | None = None,
) -> AnalystFeedback:
    """Supersede an earlier claim with a new one.

    The original row is left exactly as it was written. Only its
    ``superseded_by_id`` pointer changes, which is a statement about the claim's
    currency, not about its content.

    Identity is taken from the *correcting* analyst, not inherited from the
    original: a correction is a new claim by whoever made it, and attributing it
    to the person being corrected would misreport who concluded what.
    """
    original = db.get(AnalystFeedback, feedback_id)
    if original is None:
        raise ValueError(f"No feedback with id {feedback_id}")
    if original.superseded_by_id is not None:
        raise ValueError(
            f"Feedback {feedback_id} is already superseded by "
            f"{original.superseded_by_id}. Correct the current row instead - "
            "two corrections of one claim would leave two current answers."
        )

    correction = AnalystFeedback(
        target_type=original.target_type,
        target_id=original.target_id,
        label=FeedbackLabel(label).value,
        confidence=_validate_confidence(confidence),
        comment=comment,
        mitre_techniques=[],
        evidence_reference=original.evidence_reference,
        analyst=analyst,
        analyst_id=analyst_id,
        analyst_role=analyst_role,
        source=original.source,
        feature_schema_version=FEATURE_SCHEMA_VERSION,
        model_identity=original.model_identity,
        supersedes_id=original.id,
        correction_reason=reason,
    )
    db.add(correction)
    db.flush()

    original.superseded_by_id = correction.id
    db.flush()
    return correction


def active_for_target(
    db: Session, *, target_type: FeedbackTargetType, target_id: int
) -> list[AnalystFeedback]:
    """Current feedback for one object: superseded claims excluded."""
    return list(
        db.scalars(
            select(AnalystFeedback)
            .where(
                AnalystFeedback.target_type == FeedbackTargetType(target_type).value,
                AnalystFeedback.target_id == int(target_id),
                AnalystFeedback.superseded_by_id.is_(None),
            )
            .order_by(AnalystFeedback.submitted_at.asc(), AnalystFeedback.id.asc())
        )
    )
