"""API contract for analyst feedback and adaptation (V5)."""

from __future__ import annotations

from datetime import datetime

from pydantic import Field

from app.adaptation.feedback.labels import FeedbackLabel, FeedbackTargetType
from app.models.enums import ProposalType
from app.schemas.common import CamelModel


class FeedbackSubmit(CamelModel):
    """One analyst claim about one detection."""

    target_type: FeedbackTargetType = Field(
        default=FeedbackTargetType.EVENT, examples=["event"]
    )
    #: The public identifier an analyst can see, e.g. ``EVT-000042``.
    target_id: str = Field(examples=["EVT-000042"], max_length=64)
    label: FeedbackLabel = Field(examples=["false_positive"])
    confidence: float | None = Field(default=None, ge=0.0, le=1.0, examples=[0.8])
    comment: str | None = Field(default=None, max_length=4000)
    mitre_techniques: list[str] = Field(default_factory=list, examples=[["T1059.001"]])
    evidence_reference: str | None = Field(default=None, max_length=512)


class FeedbackCorrect(CamelModel):
    """A correction. It supersedes an earlier claim rather than editing it."""

    label: FeedbackLabel
    reason: str = Field(min_length=1, max_length=2000)
    confidence: float | None = Field(default=None, ge=0.0, le=1.0)
    comment: str | None = Field(default=None, max_length=4000)


class FeedbackRead(CamelModel):
    id: int
    target_type: str
    target_id: str
    label: str
    confidence: float | None
    comment: str | None
    mitre_techniques: list[str]
    evidence_reference: str | None
    analyst: str
    source: str
    feature_schema_version: str
    model_identity: str | None
    submitted_at: datetime
    supersedes_id: int | None
    superseded_by_id: int | None
    correction_reason: str | None


class FeedbackDatasetRead(CamelModel):
    """An immutable feedback snapshot.

    ``fingerprint`` is part of the identity, not a detail: a result produced
    over one fingerprint may not be compared against another.
    """

    id: int
    name: str
    version: str
    fingerprint: str
    sample_count: int
    label_distribution: dict[str, int]
    feature_schema_version: str
    selection: dict
    created_by: str
    created_at: datetime
    notes: str | None


class DriftMeasurementRead(CamelModel):
    """One drift reading, with the bands that produced its status."""

    id: int
    kind: str
    feature: str
    baseline_label: str
    window_label: str
    metric_name: str
    metric_value: float
    secondary_metric_name: str | None
    secondary_metric_value: float | None
    status: str
    moderate_threshold: float
    significant_threshold: float
    reference_samples: int
    current_samples: int
    model_identity: str | None
    measured_at: datetime


class DriftStatusResponse(CamelModel):
    """The drift overview.

    ``interpretation`` is part of the contract, not decoration. A dashboard that
    renders "drift detected" without it invites the inference that the model has
    failed, which the measurement does not support.
    """

    features: list[DriftMeasurementRead]
    counts_by_status: dict[str, int]
    interpretation: str


class ReviewCandidateRead(CamelModel):
    """One event recommended for analyst review, with the reason it was chosen."""

    event_id: str
    title: str
    priority: float
    reason: str
    signals: dict[str, float]
    anomaly_score: float | None
    threshold: float | None
    rule_hit: bool
    ml_flagged: bool
    risk_score: int


class ReviewQueueResponse(CamelModel):
    """The active-learning review queue.

    ``interpretation`` is part of the contract. A ranked list of events looks
    like a worklist of confirmed findings unless it says otherwise, and these
    are recommendations about where attention is worth spending - not claims
    about what any of them are.
    """

    candidates: list[ReviewCandidateRead]
    weights: dict[str, float]
    interpretation: str


class ProposalCreate(CamelModel):
    """A request to change what AEGISX detects."""

    proposal_type: ProposalType
    title: str = Field(min_length=1, max_length=255)
    reason: str = Field(min_length=1, max_length=4000)
    affected_component: str = Field(min_length=1, max_length=128)
    before_state: dict = Field(default_factory=dict)
    after_state: dict = Field(default_factory=dict)
    #: Required. A proposal without evidence is an opinion.
    evidence: dict
    expected_impact: dict = Field(default_factory=dict)
    risk_assessment: str | None = Field(default=None, max_length=4000)
    candidate_model_id: int | None = None
    feedback_dataset_id: int | None = None


class ProposalDecision(CamelModel):
    reason: str | None = Field(default=None, max_length=4000)


class ProposalRead(CamelModel):
    id: int
    proposal_type: str
    status: str
    title: str
    reason: str
    affected_component: str
    before_state: dict
    after_state: dict
    evidence: dict
    validation: dict
    expected_impact: dict
    risk_assessment: str | None
    candidate_model_id: int | None
    feedback_dataset_id: int | None
    proposed_by: str
    approved_by: str | None
    rejected_by: str | None
    deployed_by: str | None
    rolled_back_by: str | None
    #: Surfaced rather than prevented: with three roles an administrator can
    #: propose and approve, and hiding that would be worse than showing it.
    self_approved: bool
    rejection_reason: str | None
    rollback_reason: str | None
    rollback_state: dict
    created_at: datetime
    approved_at: datetime | None
    deployed_at: datetime | None
    rolled_back_at: datetime | None
