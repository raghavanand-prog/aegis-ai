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
    Boolean,
    CheckConstraint,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
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


class FeedbackDataset(Base):
    """An immutable snapshot of analyst feedback, used to train or evaluate.

    Identity is ``(name, version, fingerprint)``, exactly as ``evaluation_datasets``
    is. Two snapshots that share a name and version but hash differently are not
    the same data, and a model trained on one must never be compared against a
    result produced on the other.

    Membership is materialised into ``feedback_dataset_members`` rather than
    recomputed from a query. A query would return whatever the feedback table
    says *today*: correct one label and the "training data" of an already-trained
    model silently changes underneath it. The snapshot is the whole point.
    """

    __tablename__ = "feedback_datasets"
    __table_args__ = (
        UniqueConstraint(
            "name", "version", "fingerprint", name="uq_feedback_dataset_identity"
        ),
        CheckConstraint("sample_count >= 0", name="ck_feedback_dataset_sample_count"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    version: Mapped[str] = mapped_column(String(32), nullable=False)
    #: SHA-256 over the ordered membership, truncated to 16 hex characters -
    #: the same convention V4 uses for evaluation datasets.
    fingerprint: Mapped[str] = mapped_column(String(64), nullable=False, index=True)

    sample_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    #: Counts per label at build time, so the balance of a training set is
    #: recoverable without rejoining the members.
    label_distribution: Mapped[dict] = mapped_column(JSONType, default=dict, nullable=False)
    feature_schema_version: Mapped[str] = mapped_column(String(16), nullable=False)
    #: The filters that produced this membership. Without them a snapshot says
    #: what it contains but not what it was asked for.
    selection: Mapped[dict] = mapped_column(JSONType, default=dict, nullable=False)

    created_by: Mapped[str] = mapped_column(String(255), default="system", nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False, index=True
    )
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)

    members: Mapped[list[FeedbackDatasetMember]] = relationship(
        "FeedbackDatasetMember",
        back_populates="dataset",
        cascade="all, delete-orphan",
        order_by="FeedbackDatasetMember.feedback_id",
    )

    @property
    def identity(self) -> str:
        return f"{self.name}@{self.version}[{self.fingerprint}]"

    def __repr__(self) -> str:  # pragma: no cover
        return f"<FeedbackDataset {self.identity} n={self.sample_count}>"


class FeedbackDatasetMember(Base):
    """One feedback row as it stood when the snapshot was taken.

    ``label`` and ``binary_label`` are copied rather than joined. The feedback
    row they came from may later be superseded; this table must still say what
    the model was actually trained on.
    """

    __tablename__ = "feedback_dataset_members"
    __table_args__ = (
        UniqueConstraint("dataset_id", "feedback_id", name="uq_feedback_member_unique"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    dataset_id: Mapped[int] = mapped_column(
        ForeignKey("feedback_datasets.id", ondelete="CASCADE"), nullable=False, index=True
    )
    feedback_id: Mapped[int] = mapped_column(
        ForeignKey("analyst_feedback.id", ondelete="RESTRICT"), nullable=False
    )

    target_type: Mapped[str] = mapped_column(String(16), nullable=False)
    target_id: Mapped[int] = mapped_column(Integer, nullable=False)
    label: Mapped[str] = mapped_column(String(32), nullable=False)
    #: The malicious/benign projection at build time. Never None here: rows
    #: without a projection are not training-eligible and never become members.
    binary_label: Mapped[bool] = mapped_column(Boolean, nullable=False)

    dataset: Mapped[FeedbackDataset] = relationship("FeedbackDataset", back_populates="members")


class DriftMeasurement(Base):
    """One drift reading, with everything needed to argue with it later.

    The thresholds in force are stored **on the row**. A status of "significant"
    is not interpretable months afterwards without the bands that produced it,
    and those bands are configurable per deployment - so recording the verdict
    without them would preserve a conclusion while discarding its basis.

    Nothing about this table triggers anything. A reading is a signal an analyst
    reads, and V5 has no path from a row here to a retrain.
    """

    __tablename__ = "drift_measurements"
    __table_args__ = (
        CheckConstraint(
            "reference_samples >= 0 AND current_samples >= 0",
            name="ck_drift_measurement_samples",
        ),
        Index("ix_drift_measurements_feature_time", "feature", "measured_at"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)

    #: data | prediction | concept. Kept explicit because the three support
    #: different conclusions and must never be reported as one another.
    kind: Mapped[str] = mapped_column(String(16), nullable=False, index=True)
    feature: Mapped[str] = mapped_column(String(128), nullable=False, index=True)

    #: Which windows were compared. Free text on purpose: "the window the model
    #: was fitted on" is a statement about provenance, not a foreign key.
    baseline_label: Mapped[str] = mapped_column(String(128), nullable=False)
    window_label: Mapped[str] = mapped_column(String(128), nullable=False)

    metric_name: Mapped[str] = mapped_column(String(32), nullable=False)
    metric_value: Mapped[float] = mapped_column(Float, nullable=False)
    #: Reported beside PSI because it is in the units of the feature, which is
    #: what makes a reading actionable rather than merely alarming.
    secondary_metric_name: Mapped[str | None] = mapped_column(String(32), nullable=True)
    secondary_metric_value: Mapped[float | None] = mapped_column(Float, nullable=True)

    status: Mapped[str] = mapped_column(String(16), nullable=False, index=True)
    moderate_threshold: Mapped[float] = mapped_column(Float, nullable=False)
    significant_threshold: Mapped[float] = mapped_column(Float, nullable=False)

    reference_samples: Mapped[int] = mapped_column(Integer, nullable=False)
    current_samples: Mapped[int] = mapped_column(Integer, nullable=False)
    detail: Mapped[dict] = mapped_column(JSONType, default=dict, nullable=False)

    model_identity: Mapped[str | None] = mapped_column(String(128), nullable=True)
    measured_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False, index=True
    )

    def __repr__(self) -> str:  # pragma: no cover
        return f"<DriftMeasurement {self.kind}:{self.feature} {self.status}>"
