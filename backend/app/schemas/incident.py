"""Incident schemas."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import Field

from app.models.enums import IncidentStatus, Severity
from app.schemas.common import CamelModel
from app.schemas.ioc import IOCRead
from app.schemas.ml import AIAnalysisRead, RiskSignalRead, SequenceRead


class IncidentEventSummary(CamelModel):
    """Compact representation of an event attached to an incident."""

    id: str
    timestamp: datetime
    source: str
    title: str
    severity: Severity
    status: str
    risk_score: int = 0
    #: Set when the anomaly model flagged this event, so the incident view can
    #: mark it without loading the full inference payload.
    is_anomaly: bool = False
    anomaly_score: float | None = None


class IncidentCreate(CamelModel):
    title: str = Field(max_length=255)
    description: str = ""
    severity: Severity = Severity.MEDIUM
    status: IncidentStatus = IncidentStatus.OPEN
    source: str = Field(default="AEGISX", max_length=120)
    analyst: str = Field(default="Unassigned", max_length=120)
    event_ids: list[str] = Field(default_factory=list)
    mitre_techniques: list[str] = Field(default_factory=list)


class IncidentUpdate(CamelModel):
    title: str | None = Field(default=None, max_length=255)
    description: str | None = None
    severity: Severity | None = None
    status: IncidentStatus | None = None
    #: Why the status is changing. Required by the lifecycle for any transition
    #: that ends recorded work (`-> Resolved`, `-> Closed`) or undoes it (a
    #: reopen), and ignored when the request does not change the status. The
    #: requirement is enforced in the domain layer rather than by making this
    #: field mandatory here, because whether a reason is needed depends on
    #: which two states are involved and this schema cannot see the current one.
    status_reason: str | None = Field(default=None, max_length=500)
    #: The evidence manifest the caller reviewed before deciding. Optional,
    #: and when supplied a consequential transition is refused if the evidence
    #: has moved since - which is the window between rendering a page and
    #: clicking on it. Omitting it keeps the pre-V9 behaviour and gets no
    #: protection; that is a deliberate compatibility choice, not an oversight.
    expected_evidence_digest: str | None = Field(default=None, max_length=64)
    analyst: str | None = Field(default=None, max_length=120)
    assignee_id: int | None = None


class IncidentRead(CamelModel):
    id: str
    title: str
    description: str
    severity: Severity
    status: IncidentStatus
    source: str
    analyst: str
    assignee_id: int | None = None
    risk_score: int
    mitre_techniques: list[str] = Field(default_factory=list)
    #: Aggregated signal breakdown across the incident's events.
    risk_signals: list[RiskSignalRead] = Field(default_factory=list)
    #: Correlated sequences any of the incident's events belong to.
    sequences: list[SequenceRead] = Field(default_factory=list)
    #: AI analyses produced for this incident, newest first. Always labelled.
    ai_analyses: list[AIAnalysisRead] = Field(default_factory=list)
    #: Count of the incident's events the anomaly model flagged.
    ml_anomaly_count: int = 0
    timeline: list[dict[str, Any]] = Field(default_factory=list)
    event_ids: list[str] = Field(default_factory=list)
    events: list[IncidentEventSummary] = Field(default_factory=list)
    iocs: list[IOCRead] = Field(default_factory=list)
    event_count: int = 0
    created_at: datetime
    updated_at: datetime
    resolved_at: datetime | None = None
