"""Analyst facing incident, created from one or more events."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import CheckConstraint, DateTime, ForeignKey, Index, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, JSONType, TimestampMixin
from app.models.enums import IncidentStatus, Severity
from app.models.ioc import incident_iocs


class Incident(Base, TimestampMixin):
    __tablename__ = "incidents"

    # The incident queue is read by status and by severity, newest first, and
    # filtered per analyst on the workload view.
    __table_args__ = (
        Index("ix_incidents_status_created", "status", "created_at"),
        Index("ix_incidents_severity_created", "severity", "created_at"),
        Index("ix_incidents_analyst_status", "analyst", "status"),
        CheckConstraint(
            "severity IN ('Low', 'Medium', 'High', 'Critical')", name="ck_incidents_severity"
        ),
        CheckConstraint(
            "status IN ('Open', 'Investigating', 'Contained', 'Resolved')",
            name="ck_incidents_status",
        ),
        CheckConstraint("risk_score >= 0 AND risk_score <= 100", name="ck_incidents_risk_score"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    # Human readable identifier shown in the UI, e.g. INC-1024.
    incident_id: Mapped[str] = mapped_column(String(32), unique=True, index=True, nullable=False)

    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, default="", nullable=False)
    severity: Mapped[str] = mapped_column(
        String(16), default=Severity.MEDIUM.value, nullable=False, index=True
    )
    status: Mapped[str] = mapped_column(
        String(24), default=IncidentStatus.OPEN.value, nullable=False, index=True
    )
    source: Mapped[str] = mapped_column(String(120), default="AEGISX", nullable=False)
    risk_score: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    # Analyst display name kept denormalized so the existing UI keeps working
    # even when an incident is unassigned.
    analyst: Mapped[str] = mapped_column(String(120), default="Unassigned", nullable=False)
    assignee_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    assignee = relationship("User", back_populates="incidents", foreign_keys=[assignee_id])

    mitre_techniques: Mapped[list] = mapped_column(JSONType, default=list, nullable=False)
    timeline: Mapped[list] = mapped_column(JSONType, default=list, nullable=False)
    # V3: aggregated signal breakdown across the incident's events.
    risk_signals: Mapped[list] = mapped_column(JSONType, default=list, nullable=False)

    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    events = relationship("Event", back_populates="incident", lazy="selectin")
    iocs = relationship("IOC", secondary=incident_iocs, back_populates="incidents", lazy="selectin")
    sequences = relationship("SecuritySequence", back_populates="incident", lazy="selectin")
    ai_analyses = relationship(
        "AIAnalysis",
        back_populates="incident",
        lazy="selectin",
        cascade="all, delete-orphan",
        order_by="AIAnalysis.created_at.desc()",
    )

    def __repr__(self) -> str:  # pragma: no cover
        return f"<Incident {self.incident_id} {self.status} {self.title!r}>"
