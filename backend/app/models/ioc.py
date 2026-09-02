"""Indicators of compromise and their links to events and incidents."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import (
    CheckConstraint,
    Column,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Table,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, TimestampMixin, utcnow

event_iocs = Table(
    "event_iocs",
    Base.metadata,
    Column("event_id", Integer, ForeignKey("events.id", ondelete="CASCADE"), primary_key=True),
    Column("ioc_id", Integer, ForeignKey("iocs.id", ondelete="CASCADE"), primary_key=True),
)

incident_iocs = Table(
    "incident_iocs",
    Base.metadata,
    Column("incident_id", Integer, ForeignKey("incidents.id", ondelete="CASCADE"), primary_key=True),
    Column("ioc_id", Integer, ForeignKey("iocs.id", ondelete="CASCADE"), primary_key=True),
)


class IOC(Base, TimestampMixin):
    __tablename__ = "iocs"
    __table_args__ = (
        # Lookup is always "have we seen this value before", so the unique
        # constraint doubles as the lookup index; the second index serves the
        # "recent indicators of this type" view.
        UniqueConstraint("type", "value", name="uq_ioc_type_value"),
        Index("ix_iocs_type_lastseen", "type", "last_seen"),
        CheckConstraint("confidence >= 0 AND confidence <= 100", name="ck_iocs_confidence"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    type: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    value: Mapped[str] = mapped_column(String(512), nullable=False, index=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    severity: Mapped[str] = mapped_column(String(16), default="Medium", nullable=False)
    confidence: Mapped[int] = mapped_column(Integer, default=50, nullable=False)
    source: Mapped[str | None] = mapped_column(String(120), nullable=True)
    sighting_count: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)

    events = relationship("Event", secondary=event_iocs, back_populates="iocs")
    incidents = relationship("Incident", secondary=incident_iocs, back_populates="iocs")
    threat_intel = relationship(
        "ThreatIntelResult",
        back_populates="ioc",
        lazy="selectin",
        cascade="all, delete-orphan",
    )

    def __repr__(self) -> str:  # pragma: no cover
        return f"<IOC {self.type}:{self.value}>"
