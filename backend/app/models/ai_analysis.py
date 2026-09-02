"""Stored AI analyst output.

The analysis is stored as structured fields, not only as prose, because prose
cannot be queried, compared across runs, or checked for grounding. The raw
response is kept alongside it so a disputed summary can be traced back to what
the provider actually returned.

Every row names its provider, model, prompt version and analysis version. An
AI answer whose prompt you cannot reconstruct is not evidence of anything.
"""

from __future__ import annotations

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, JSONType, TimestampMixin
from app.models.enums import AIAnalysisKind


class AIAnalysis(Base, TimestampMixin):
    __tablename__ = "ai_analyses"
    __table_args__ = (
        Index("ix_ai_analyses_incident_created", "incident_id", "created_at"),
        CheckConstraint(
            "kind IN ('analyze', 'explain', 'recommend')", name="ck_ai_analyses_kind"
        ),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    incident_id: Mapped[int] = mapped_column(
        ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False, index=True
    )

    kind: Mapped[str] = mapped_column(
        String(16), default=AIAnalysisKind.ANALYZE.value, nullable=False
    )
    provider: Mapped[str] = mapped_column(String(32), nullable=False)
    model: Mapped[str] = mapped_column(String(120), default="", nullable=False)
    prompt_version: Mapped[str] = mapped_column(String(16), nullable=False)
    analysis_version: Mapped[str] = mapped_column(String(16), nullable=False)

    # --- Structured output -------------------------------------------------
    summary: Mapped[str] = mapped_column(Text, default="", nullable=False)
    why_it_matters: Mapped[str] = mapped_column(Text, default="", nullable=False)
    risk_assessment: Mapped[str] = mapped_column(Text, default="", nullable=False)
    likely_behaviour: Mapped[str] = mapped_column(Text, default="", nullable=False)
    #: Statements the model made, each pointing at the evidence item it used.
    supporting_evidence: Mapped[list] = mapped_column(JSONType, default=list, nullable=False)
    mitre_techniques: Mapped[list] = mapped_column(JSONType, default=list, nullable=False)
    investigation_steps: Mapped[list] = mapped_column(JSONType, default=list, nullable=False)
    containment_actions: Mapped[list] = mapped_column(JSONType, default=list, nullable=False)
    #: The model's own stated confidence: "high" / "medium" / "low" /
    #: "insufficient_evidence". Not a calibrated probability, and labelled as
    #: such everywhere it is displayed.
    confidence: Mapped[str] = mapped_column(String(32), default="unknown", nullable=False)
    uncertainty: Mapped[str] = mapped_column(Text, default="", nullable=False)

    # --- Provenance and grounding -----------------------------------------
    #: Fingerprint of the evidence package the answer was produced from, so an
    #: analysis can be told apart from one generated before new events landed.
    evidence_fingerprint: Mapped[str] = mapped_column(String(64), default="", nullable=False)
    evidence_summary: Mapped[dict] = mapped_column(JSONType, default=dict, nullable=False)
    #: False when the grounding check found claims that the evidence does not
    #: support. The analysis is still stored - and shown with a warning.
    grounded: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    grounding_warnings: Mapped[list] = mapped_column(JSONType, default=list, nullable=False)

    raw_response: Mapped[str | None] = mapped_column(Text, nullable=True)
    latency_ms: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    tokens_used: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    requested_by: Mapped[str] = mapped_column(String(255), default="system", nullable=False)
    requested_by_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )

    incident = relationship("Incident", back_populates="ai_analyses")

    def __repr__(self) -> str:  # pragma: no cover
        return f"<AIAnalysis {self.kind} incident={self.incident_id} {self.provider}>"
