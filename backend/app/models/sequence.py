"""Correlated security sequences.

A sequence is a set of events that share an entity (host, user, source address,
process) inside a time window and that, taken together, say more than any of
them says alone. Twenty failed logins are noise; twenty failed logins followed
by a success from the same address is a story.

This is deliberately a relational implementation. A graph database would model
the relationships more naturally, and would also be a whole new piece of
infrastructure to run - the join table below answers every question V3 asks.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import (
    CheckConstraint,
    Column,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Table,
    Text,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, JSONType, TimestampMixin
from app.models.enums import SequenceStatus, Severity

sequence_events = Table(
    "sequence_events",
    Base.metadata,
    Column(
        "sequence_id",
        Integer,
        ForeignKey("security_sequences.id", ondelete="CASCADE"),
        primary_key=True,
    ),
    Column("event_id", Integer, ForeignKey("events.id", ondelete="CASCADE"), primary_key=True),
)


class SecuritySequence(Base, TimestampMixin):
    __tablename__ = "security_sequences"
    __table_args__ = (
        Index("ix_sequences_status_created", "status", "created_at"),
        Index("ix_sequences_pattern_key", "pattern", "correlation_key"),
        CheckConstraint(
            "severity IN ('Low', 'Medium', 'High', 'Critical')", name="ck_sequences_severity"
        ),
        CheckConstraint(
            "status IN ('Open', 'Promoted', 'Dismissed')", name="ck_sequences_status"
        ),
        CheckConstraint(
            "risk_score >= 0 AND risk_score <= 100", name="ck_sequences_risk_score"
        ),
        CheckConstraint("confidence >= 0 AND confidence <= 1", name="ck_sequences_confidence"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    #: Human readable identifier shown in the UI, e.g. SEQ-000007.
    sequence_id: Mapped[str] = mapped_column(String(32), unique=True, index=True, nullable=False)

    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, default="", nullable=False)

    #: Which correlation pattern produced this sequence (see app/correlation).
    pattern: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    #: The entity the pattern grouped on, e.g. "user:a.sharma". Together with
    #: ``pattern`` this is what an incoming event is matched against so related
    #: activity extends an existing sequence instead of opening a new one.
    correlation_key: Mapped[str] = mapped_column(String(255), nullable=False)

    severity: Mapped[str] = mapped_column(
        String(16), default=Severity.MEDIUM.value, nullable=False, index=True
    )
    status: Mapped[str] = mapped_column(
        String(16), default=SequenceStatus.OPEN.value, nullable=False, index=True
    )
    risk_score: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    #: How strongly the correlation itself is believed, 0..1. Derived from the
    #: number of distinct signal types and events, never from a model.
    confidence: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)

    start_time: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    end_time: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    event_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    #: Techniques carried by the member events, each tagged with how it was
    #: obtained (mapped / inferred / contextual) - see app/correlation/mitre.py.
    techniques: Mapped[list] = mapped_column(JSONType, default=list, nullable=False)
    #: {"hosts": [...], "users": [...], "sourceIps": [...], "processes": [...]}
    entities: Mapped[dict] = mapped_column(JSONType, default=dict, nullable=False)
    #: Plain-language statements of why these events were grouped.
    rationale: Mapped[list] = mapped_column(JSONType, default=list, nullable=False)
    #: The signal breakdown behind ``risk_score``, same shape as an event's.
    risk_signals: Mapped[list] = mapped_column(JSONType, default=list, nullable=False)

    incident_id: Mapped[int | None] = mapped_column(
        ForeignKey("incidents.id", ondelete="SET NULL"), nullable=True, index=True
    )
    incident = relationship("Incident", back_populates="sequences")
    events = relationship(
        "Event", secondary=sequence_events, back_populates="sequences", lazy="selectin"
    )

    def __repr__(self) -> str:  # pragma: no cover
        return f"<SecuritySequence {self.sequence_id} {self.pattern} n={self.event_count}>"
