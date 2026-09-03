"""Analyst feedback and the adaptation lifecycle (V5).

``AnalystFeedback`` is deliberately **append-only**. A feedback row records what
a named analyst claimed at a moment in time, and later disagreement does not
make the earlier claim not have happened. Corrections therefore insert a new row
that supersedes the old one, and both survive.

That costs a self-referential pair of columns and buys the only thing that makes
feedback-driven adaptation auditable: months later, "why was this model trained
on that label" has an answer, including when the label was wrong and who changed
it.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, JSONType, utcnow


class AnalystFeedback(Base):
    """One analyst's claim about one detection."""

    __tablename__ = "analyst_feedback"
    __table_args__ = (
        CheckConstraint(
            "confidence IS NULL OR (confidence >= 0.0 AND confidence <= 1.0)",
            name="ck_analyst_feedback_confidence_range",
        ),
        # A row cannot supersede itself: that would make the active-set query
        # non-terminating and the provenance chain meaningless.
        CheckConstraint(
            "supersedes_id IS NULL OR supersedes_id <> id",
            name="ck_analyst_feedback_no_self_supersede",
        ),
        Index("ix_analyst_feedback_target", "target_type", "target_id"),
        Index("ix_analyst_feedback_active", "superseded_by_id", "label"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)

    # --- What this is feedback about ---------------------------------------
    target_type: Mapped[str] = mapped_column(String(16), nullable=False)
    target_id: Mapped[int] = mapped_column(Integer, nullable=False)

    # --- The claim ----------------------------------------------------------
    label: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    #: Nullable on purpose. An analyst who does not state a confidence has not
    #: stated one; recording 1.0 would invent certainty they never expressed.
    confidence: Mapped[float | None] = mapped_column(Float, nullable=True)
    comment: Mapped[str | None] = mapped_column(Text, nullable=True)
    #: Techniques the analyst *confirmed*. Never techniques anything inferred.
    mitre_techniques: Mapped[list] = mapped_column(JSONType, default=list, nullable=False)
    evidence_reference: Mapped[str | None] = mapped_column(String(512), nullable=True)

    # --- Provenance ---------------------------------------------------------
    analyst: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    #: How the claim arrived: an analyst working an alert, an active-learning
    #: review, or a simulation. Adaptation results must be separable by source.
    source: Mapped[str] = mapped_column(String(32), default="analyst", nullable=False)
    #: The feature schema the analyst was shown. Feedback collected across a
    #: schema change describes different inputs and must not be pooled.
    feature_schema_version: Mapped[str] = mapped_column(String(16), nullable=False)
    #: The model serving when the claim was made, where one was.
    model_identity: Mapped[str | None] = mapped_column(String(128), nullable=True)
    submitted_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False, index=True
    )

    # --- Correction chain ---------------------------------------------------
    supersedes_id: Mapped[int | None] = mapped_column(
        ForeignKey("analyst_feedback.id", ondelete="SET NULL"), nullable=True
    )
    superseded_by_id: Mapped[int | None] = mapped_column(
        ForeignKey("analyst_feedback.id", ondelete="SET NULL"), nullable=True
    )
    correction_reason: Mapped[str | None] = mapped_column(Text, nullable=True)

    supersedes: Mapped[AnalystFeedback | None] = relationship(
        "AnalystFeedback",
        remote_side=[id],
        foreign_keys=[supersedes_id],
        post_update=True,
    )

    @property
    def is_active(self) -> bool:
        return self.superseded_by_id is None

    def __repr__(self) -> str:  # pragma: no cover
        return (
            f"<AnalystFeedback {self.id} {self.target_type}:{self.target_id} "
            f"{self.label} by {self.analyst}>"
        )
