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
from typing import TYPE_CHECKING

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

if TYPE_CHECKING:  # pragma: no cover - typing only, avoids an import cycle
    from app.models.ml import MLModel


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
    #: The account behind the claim, where there was one (V7). Nullable because
    #: simulated and fixture feedback has no account, and minting one for it
    #: would make a generated claim indistinguishable from a human's.
    #: ``SET NULL`` rather than cascade: deleting an account must not delete the
    #: record of what that account concluded.
    analyst_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True
    )
    #: The role the analyst held **when the claim was made** (V7). Recorded on
    #: the row rather than joined from ``users`` on read: roles change, and the
    #: auditable fact is the authority a claim was made under at the time, not
    #: the authority its author happens to hold today.
    analyst_role: Mapped[str | None] = mapped_column(String(32), nullable=True)
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


class AdaptationProposal(Base):
    """A request to change what AEGISX detects, and the record of its fate.

    This table is the human-in-the-loop requirement made structural. Production
    detection behaviour changes through an approved proposal or it does not
    change, and every column here exists so that months later the question "why
    does the platform behave this way" has a complete answer: what changed, why,
    on what evidence, who approved it, when, and what it would revert to.

    ``before_state`` is captured at creation and ``rollback_state`` at
    deployment, deliberately rather than being derived afterwards. Reconstructing
    "what was it before" from the current configuration is exactly the operation
    that fails when it is needed most.

    Nothing here is deleted. A rejected proposal is a measured refusal, and a
    rolled-back one is the most valuable row in the table.
    """

    __tablename__ = "adaptation_proposals"
    __table_args__ = (
        CheckConstraint(
            "status IN ('pending', 'approved', 'rejected', 'deployed', "
            "'rolled_back', 'superseded')",
            name="ck_adaptation_proposal_status",
        ),
        Index("ix_adaptation_proposals_status_created", "status", "created_at"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)

    proposal_type: Mapped[str] = mapped_column(String(48), nullable=False, index=True)
    status: Mapped[str] = mapped_column(String(16), nullable=False, index=True)

    title: Mapped[str] = mapped_column(String(255), nullable=False)
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    #: The thing that would change, named precisely enough to act on.
    affected_component: Mapped[str] = mapped_column(String(128), nullable=False, index=True)

    before_state: Mapped[dict] = mapped_column(JSONType, default=dict, nullable=False)
    after_state: Mapped[dict] = mapped_column(JSONType, default=dict, nullable=False)
    #: What supports the request. A proposal without this is an opinion.
    evidence: Mapped[dict] = mapped_column(JSONType, default=dict, nullable=False)
    #: Gate results and the evaluation behind them.
    validation: Mapped[dict] = mapped_column(JSONType, default=dict, nullable=False)
    expected_impact: Mapped[dict] = mapped_column(JSONType, default=dict, nullable=False)
    risk_assessment: Mapped[str | None] = mapped_column(Text, nullable=True)

    #: Links to the artifacts a reviewer needs. Nullable: a threshold proposal
    #: has no candidate model, and inventing one would be worse than a null.
    candidate_model_id: Mapped[int | None] = mapped_column(
        ForeignKey("ml_models.id", ondelete="SET NULL"), nullable=True
    )
    feedback_dataset_id: Mapped[int | None] = mapped_column(
        ForeignKey("feedback_datasets.id", ondelete="SET NULL"), nullable=True
    )

    #: Who did what. Separate columns rather than one actor field, because the
    #: whole point is that these are different people.
    proposed_by: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    approved_by: Mapped[str | None] = mapped_column(String(255), nullable=True)
    rejected_by: Mapped[str | None] = mapped_column(String(255), nullable=True)
    deployed_by: Mapped[str | None] = mapped_column(String(255), nullable=True)
    rolled_back_by: Mapped[str | None] = mapped_column(String(255), nullable=True)

    #: The role each actor held **at the moment they acted** (V7). Recorded on
    #: the row for the same reason feedback records it: roles change, and an
    #: audit trail that resolved authority at read time would retroactively
    #: restate every past decision in terms of today's permissions.
    proposed_by_role: Mapped[str | None] = mapped_column(String(32), nullable=True)
    approved_by_role: Mapped[str | None] = mapped_column(String(32), nullable=True)
    rejected_by_role: Mapped[str | None] = mapped_column(String(32), nullable=True)

    #: **Prevented since V7, not merely recorded.** Through V6 this was a flag:
    #: `approve` set it when the approver was the proposer and then carried on,
    #: so four-eyes was a label on the row rather than a property of the system.
    #: `proposals.approve` now refuses. The column is kept because rows written
    #: before V7 may legitimately carry ``True``, and rewriting history to make
    #: the guarantee look older than it is would be the more dishonest option.
    self_approved: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    rejection_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    rollback_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    #: Captured at deployment: the state to return to, not a state to recompute.
    rollback_state: Mapped[dict] = mapped_column(JSONType, default=dict, nullable=False)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False, index=True
    )
    approved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    #: V7. Every other terminal decision recorded when it happened; a rejection
    #: did not, so "when was this refused" was answerable only from the audit log.
    rejected_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    deployed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    rolled_back_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    #: The candidate this proposal would deploy. Read-only and lazily loaded:
    #: it exists so an approver can be shown what the candidate was *built
    #: from*, not so anything can be written through it.
    candidate_model: Mapped[MLModel | None] = relationship(
        "MLModel",
        foreign_keys=[candidate_model_id],
        lazy="selectin",
        viewonly=True,
    )

    @property
    def augmentation(self) -> dict | None:
        """How analyst feedback entered this candidate's fit set, or ``None``.

        V6 recorded this block on the *model's* ``parameters`` and V7 closed by
        noting it never reached the approver: "``actorCounts``, ``groupCounts``
        and ``baselineAssessment`` live on the model's parameters, not the
        proposal's validation". So an approver could see how a candidate
        *scored* and not what it was *trained on* — which is the half an
        adversary controls.

        ``None`` has three distinct causes and they are not the same fact, so
        none of them is flattened to an empty dict here: the proposal carries no
        candidate model (a threshold change), the candidate model row was
        deleted (``ON DELETE SET NULL``), or the candidate was trained with no
        feedback augmentation at all. The API layer distinguishes them.
        """
        model = self.candidate_model
        if model is None:
            return None
        block = (model.parameters or {}).get("augmentation")
        return block if isinstance(block, dict) else None

    def __repr__(self) -> str:  # pragma: no cover
        return f"<AdaptationProposal {self.id} {self.proposal_type} {self.status}>"
