"""API contract for analyst feedback and adaptation (V5)."""

from __future__ import annotations

from datetime import datetime

from pydantic import Field

from app.adaptation.feedback.labels import FeedbackLabel, FeedbackTargetType
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
