"""ML, correlation, threat intelligence and AI schemas (V3).

Field names are chosen so a consumer cannot mistake one kind of number for
another. ``anomalyScore`` is never called a probability; ``confidence`` on an
AI analysis is the model's own stated confidence, not a calibrated one, and the
schema descriptions say so.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import Field

from app.schemas.common import CamelModel


# --------------------------------------------------------------------------- ML
class FeatureContributionRead(CamelModel):
    """One feature that sat far from the training norm."""

    name: str
    value: float
    deviation: float = Field(
        description="Standard deviations from the training mean. Signed."
    )
    direction: str = Field(examples=["above", "below"])


class MLInferenceRead(CamelModel):
    """A model's verdict on one event."""

    event_id: str
    model: str = Field(examples=["isolation_forest"])
    model_version: str = Field(examples=["1.0"])
    feature_schema_version: str
    anomaly_score: float = Field(
        ge=0,
        le=1,
        description=(
            "Normalized 0..1 ranking score from an unsupervised anomaly model. "
            "NOT a probability and NOT a confidence."
        ),
    )
    score_kind: str = "anomaly_score"
    is_anomaly: bool
    threshold: float
    top_contributors: list[FeatureContributionRead] = Field(default_factory=list)
    latency_ms: float
    inferred_at: datetime


class MLModelRead(CamelModel):
    id: int
    name: str
    version: str
    identity: str
    model_type: str
    feature_schema_version: str
    dataset_version: str
    dataset_fingerprint: str | None = None
    training_samples: int
    parameters: dict[str, Any] = Field(default_factory=dict)
    metrics: dict[str, Any] = Field(default_factory=dict)
    feature_names: list[str] = Field(default_factory=list)
    feature_count: int
    artifact_name: str
    artifact_sha256: str | None = None
    status: str
    notes: str | None = None
    created_by: str
    trained_at: str | None = None
    activated_at: str | None = None


class MLStatus(CamelModel):
    """Whether the anomaly detector can currently score anything, and why not."""

    enabled: bool
    available: bool
    model_name: str
    model_version: str | None = None
    feature_schema_version: str
    feature_count: int
    threshold: float
    loaded_at: str | None = None
    events_scored: int
    anomalies_flagged: int
    failures: int
    reason: str | None = Field(
        default=None,
        description="Plain-language explanation when the detector is unavailable.",
    )
    context: dict[str, Any] = Field(default_factory=dict)


# --------------------------------------------------------------------------- risk
class RiskSignalRead(CamelModel):
    """One named contribution to a risk score."""

    type: str = Field(examples=["rule", "ml", "threat_intel", "correlation", "context"])
    source: str
    contribution: int
    detail: str
    metadata: dict[str, Any] = Field(default_factory=dict)


# --------------------------------------------------------------- threat intel
class ThreatIntelRead(CamelModel):
    provider: str
    ioc_type: str
    ioc_value: str
    status: str = Field(
        examples=["ok", "not_found", "rate_limited", "timeout", "error", "unavailable"]
    )
    reputation: str = Field(examples=["malicious", "suspicious", "harmless", "unknown"])
    confidence: int
    malicious_count: int
    suspicious_count: int
    harmless_count: int
    undetected_count: int
    last_analysis_at: str | None = None
    looked_up_at: str | None = None
    expires_at: str | None = None
    error: str | None = None
    details: dict[str, Any] = Field(default_factory=dict)
    is_actionable: bool = Field(
        description="True only when a verdict was actually obtained."
    )


# --------------------------------------------------------------------------- sequences
class TechniqueRead(CamelModel):
    technique: str
    provenance: str = Field(
        examples=["mapped", "inferred", "contextual"],
        description=(
            "mapped = declared by a deterministic rule; inferred = derived by the "
            "correlation engine from the shape of the sequence; contextual = merely "
            "present on a member event. The ML model contributes no techniques."
        ),
    )
    source: str
    detail: str = ""


class SequenceRead(CamelModel):
    id: str
    title: str
    description: str
    pattern: str
    correlation_key: str
    severity: str
    status: str
    risk_score: int
    confidence: float = Field(
        ge=0, le=1, description="Correlation confidence. Not a probability of compromise."
    )
    start_time: str
    end_time: str
    event_count: int
    techniques: list[TechniqueRead] = Field(default_factory=list)
    entities: dict[str, list[str]] = Field(default_factory=dict)
    rationale: list[str] = Field(default_factory=list)
    risk_signals: list[RiskSignalRead] = Field(default_factory=list)
    incident_id: str | None = None
    event_ids: list[str] = Field(default_factory=list)
    created_at: str | None = None
    updated_at: str | None = None


# --------------------------------------------------------------------------- AI
class AIEvidenceRef(CamelModel):
    claim: str
    evidence_ref: str


class AITechniqueClaim(CamelModel):
    technique: str
    provenance: str
    rationale: str


class AIAnalysisRead(CamelModel):
    """AI-generated analysis. Always labelled; never deterministic platform output."""

    id: int
    kind: str
    provider: str
    model: str
    prompt_version: str
    analysis_version: str
    summary: str
    why_it_matters: str
    risk_assessment: str
    likely_behaviour: str
    supporting_evidence: list[AIEvidenceRef] = Field(default_factory=list)
    mitre_techniques: list[AITechniqueClaim] = Field(default_factory=list)
    investigation_steps: list[str] = Field(default_factory=list)
    containment_actions: list[str] = Field(default_factory=list)
    confidence: str = Field(
        examples=["high", "medium", "low", "insufficient_evidence"],
        description="The model's own stated confidence. Not calibrated.",
    )
    uncertainty: str
    evidence_fingerprint: str
    evidence_summary: dict[str, Any] = Field(default_factory=dict)
    grounded: bool = Field(
        description="False when the answer cited evidence the package does not contain."
    )
    grounding_warnings: list[str] = Field(default_factory=list)
    latency_ms: float
    tokens_used: int
    requested_by: str
    created_at: str | None = None
    generated_by: str = "ai"
    is_template_provider: bool
    disclaimer: str


class AIAnalysisRequest(CamelModel):
    """Optional analyst question accompanying an analysis request."""

    question: str | None = Field(default=None, max_length=500)


class AIStatus(CamelModel):
    enabled: bool
    available: bool
    provider: str
    model: str | None = None
    reason: str | None = None
    is_template_provider: bool = False
    sends_data_externally: bool = False
    prompt_version: str
    analysis_version: str
    max_evidence_events: int | None = None
    budget: dict[str, Any] = Field(default_factory=dict)
