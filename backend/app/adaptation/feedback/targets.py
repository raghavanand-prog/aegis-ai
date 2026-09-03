"""Resolving a feedback target between its public identifier and its row.

Analysts address events, incidents and sequences by the identifier the UI shows
them (``EVT-000042``). The feedback table stores the primary key, because a
foreign key is what stops feedback accumulating claims about objects that were
never there. This module is the only place the two representations meet.
"""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.adaptation.feedback.labels import FeedbackTargetType
from app.models.event import Event
from app.models.incident import Incident
from app.models.sequence import SecuritySequence

#: (model, public identifier column) for each target type.
_TARGETS = {
    FeedbackTargetType.EVENT: (Event, Event.event_id),
    FeedbackTargetType.INCIDENT: (Incident, Incident.incident_id),
    FeedbackTargetType.SEQUENCE: (SecuritySequence, SecuritySequence.sequence_id),
}


class UnknownTargetError(LookupError):
    """The referenced object does not exist."""


def resolve(db: Session, *, target_type: FeedbackTargetType, public_id: str) -> int:
    """Primary key for a public identifier, or ``UnknownTargetError``."""
    model, column = _TARGETS[FeedbackTargetType(target_type)]
    row_id = db.scalar(select(model.id).where(column == public_id))
    if row_id is None:
        raise UnknownTargetError(
            f"No {FeedbackTargetType(target_type).value} with identifier {public_id!r}"
        )
    return int(row_id)


def public_id(db: Session, *, target_type: str, target_id: int) -> str:
    """Public identifier for a stored row, falling back to the key itself.

    The fallback matters: an object deleted after feedback was given must not
    make the feedback unreadable. The claim still happened.
    """
    model, column = _TARGETS[FeedbackTargetType(target_type)]
    value = db.scalar(select(column).where(model.id == target_id))
    return str(value) if value is not None else str(target_id)
