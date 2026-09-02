"""Normalized security event.

One row per piece of telemetry, after normalization. Source specific fields
that do not fit the common schema are preserved in ``normalized_data`` (JSONB
on PostgreSQL) and the untouched original stays in ``raw_log``.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import CheckConstraint, DateTime, ForeignKey, Index, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, JSONType, TimestampMixin, utcnow
from app.models.enums import EventStatus, Severity
from app.models.ioc import event_iocs
from app.models.sequence import sequence_events


class Event(Base, TimestampMixin):
    __tablename__ = "events"

    # Indexing follows the queries the SOC actually runs, not every column:
    # the events table is always read newest-first, filtered by exactly one of
    # severity / source / status / host, or scoped to an incident. Each index
    # below serves one of those, with `timestamp` trailing so the filter and
    # the ordering are satisfied by the same index.
    __table_args__ = (
        Index("ix_events_severity_timestamp", "severity", "timestamp"),
        Index("ix_events_source_timestamp", "source", "timestamp"),
        Index("ix_events_status_timestamp", "status", "timestamp"),
        Index("ix_events_hostname_timestamp", "hostname", "timestamp"),
        Index("ix_events_incident_timestamp", "incident_id", "timestamp"),
        # V3: the ML/correlation views read "recent events for this entity",
        # which is a scan over one entity column ordered by time.
        Index("ix_events_username_timestamp", "username", "timestamp"),
        Index("ix_events_sourceip_timestamp", "source_ip", "timestamp"),
        CheckConstraint(
            "severity IN ('Low', 'Medium', 'High', 'Critical')", name="ck_events_severity"
        ),
        CheckConstraint(
            "status IN ('New', 'Investigating', 'Resolved')", name="ck_events_status"
        ),
        CheckConstraint("risk_score >= 0 AND risk_score <= 100", name="ck_events_risk_score"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    # Human readable identifier shown in the UI, e.g. EVT-000042.
    event_id: Mapped[str] = mapped_column(String(32), unique=True, index=True, nullable=False)

    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False, index=True
    )

    # --- Origin ------------------------------------------------------------
    source: Mapped[str] = mapped_column(String(120), nullable=False, index=True)
    source_type: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    event_type: Mapped[str] = mapped_column(String(64), nullable=False, index=True)

    # --- Classification ----------------------------------------------------
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    severity: Mapped[str] = mapped_column(
        String(16), default=Severity.LOW.value, nullable=False, index=True
    )
    status: Mapped[str] = mapped_column(
        String(24), default=EventStatus.NEW.value, nullable=False, index=True
    )
    risk_score: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    # --- Entities ----------------------------------------------------------
    hostname: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)
    username: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)
    source_ip: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    destination_ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    destination_port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    process: Mapped[str | None] = mapped_column(String(255), nullable=True)
    command_line: Mapped[str | None] = mapped_column(Text, nullable=True)

    # --- Payloads ----------------------------------------------------------
    raw_log: Mapped[str | None] = mapped_column(Text, nullable=True)
    normalized_data: Mapped[dict] = mapped_column(JSONType, default=dict, nullable=False)
    mitre_techniques: Mapped[list] = mapped_column(JSONType, default=list, nullable=False)
    # Ids of the rules that fired, kept flat so they are cheap to filter on.
    detection_rules: Mapped[list] = mapped_column(JSONType, default=list, nullable=False)
    # Full explanation per match: rule id + version, reason, severity, risk
    # contribution and technique. This is what makes a stored detection
    # reviewable months later, when the rule may already have moved on.
    detections: Mapped[list] = mapped_column(JSONType, default=list, nullable=False)
    # V3: the breakdown behind `risk_score`. Each entry names its source (rule
    # / ml / threat_intel / correlation / context) and what it contributed, so
    # an analyst can always answer "why is this scored the way it is".
    risk_signals: Mapped[list] = mapped_column(JSONType, default=list, nullable=False)
    risk_level: Mapped[str] = mapped_column(
        String(16), default=Severity.LOW.value, nullable=False
    )

    # Marks events produced by the built-in synthetic generator so demo data can
    # never be mistaken for real telemetry.
    is_synthetic: Mapped[bool] = mapped_column(default=True, nullable=False)

    # --- Relationships -----------------------------------------------------
    incident_id: Mapped[int | None] = mapped_column(
        ForeignKey("incidents.id", ondelete="SET NULL"), nullable=True, index=True
    )
    incident = relationship("Incident", back_populates="events")
    iocs = relationship("IOC", secondary=event_iocs, back_populates="events", lazy="selectin")
    ml_inferences = relationship(
        "MLInference",
        back_populates="event",
        lazy="selectin",
        cascade="all, delete-orphan",
    )
    sequences = relationship(
        "SecuritySequence", secondary=sequence_events, back_populates="events"
    )

    def __repr__(self) -> str:  # pragma: no cover
        return f"<Event {self.event_id} {self.severity} {self.title!r}>"
