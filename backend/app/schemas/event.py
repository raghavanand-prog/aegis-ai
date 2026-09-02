"""Event schemas.

``id`` is the human readable identifier (``EVT-000042``) because that is what
the existing frontend renders and routes on; the integer primary key stays
internal to the backend.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import Field, field_validator

from app.models.enums import EventStatus, Severity, SourceType
from app.schemas.common import CamelModel
from app.schemas.ioc import IOCRead
from app.schemas.ml import MLInferenceRead, RiskSignalRead


class EventBase(CamelModel):
    source: str = Field(max_length=120)
    source_type: SourceType
    event_type: str = Field(max_length=64)
    title: str = Field(max_length=255)
    description: str | None = None
    severity: Severity = Severity.LOW
    status: EventStatus = EventStatus.NEW
    hostname: str | None = Field(default=None, max_length=255)
    username: str | None = Field(default=None, max_length=255)
    source_ip: str | None = Field(default=None, max_length=64)
    destination_ip: str | None = Field(default=None, max_length=64)
    destination_port: int | None = Field(default=None, ge=0, le=65535)
    process: str | None = Field(default=None, max_length=255)
    command_line: str | None = None
    raw_log: str | None = None
    normalized_data: dict[str, Any] = Field(default_factory=dict)
    mitre_techniques: list[str] = Field(default_factory=list)


class EventIngest(EventBase):
    """Payload accepted by ``POST /events`` for external collectors."""

    timestamp: datetime | None = None
    is_synthetic: bool = True
    iocs: list[str] = Field(default_factory=list)

    @field_validator("mitre_techniques")
    @classmethod
    def _cap_techniques(cls, value: list[str]) -> list[str]:
        return value[:20]


class DetectionRead(CamelModel):
    """Why a rule fired, as shown to the analyst."""

    rule_id: str = Field(examples=["DET-PS-001"])
    rule_version: str = Field(examples=["1.0"])
    rule_name: str = Field(examples=["Suspicious PowerShell"])
    reason: str = Field(
        examples=["PowerShell launched with a base64 encoded command (69 character payload)"]
    )
    severity: Severity
    risk_contribution: int = Field(examples=[50])
    mitre_techniques: list[str] = Field(default_factory=list, examples=[["T1059.001"]])
    matched_at: datetime


class EventRead(EventBase):
    id: str
    timestamp: datetime
    risk_score: int
    #: Severity band the hybrid score falls into. Can raise the rule-assigned
    #: severity, never lower it.
    risk_level: Severity = Severity.LOW
    #: Every contribution to `riskScore`, named by source. This is what lets an
    #: analyst answer "why is this scored this way".
    risk_signals: list[RiskSignalRead] = Field(default_factory=list)
    detection_rules: list[str] = Field(default_factory=list)
    detections: list[DetectionRead] = Field(default_factory=list)
    #: Anomaly model verdicts. Empty when the model was unavailable - which is
    #: not the same as "the model found nothing".
    ml_findings: list[MLInferenceRead] = Field(default_factory=list)
    is_synthetic: bool
    incident_id: str | None = None
    iocs: list[IOCRead] = Field(default_factory=list)
    created_at: datetime


class EventStatusUpdate(CamelModel):
    status: EventStatus


class EventPromoteRequest(CamelModel):
    """Optional overrides when promoting an event into an incident."""

    title: str | None = Field(default=None, max_length=255)
    description: str | None = None
    severity: Severity | None = None
    analyst: str | None = Field(default=None, max_length=120)
