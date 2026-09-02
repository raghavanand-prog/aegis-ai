"""Cached threat intelligence verdicts.

One row per (provider, indicator). The row doubles as the cache: ``expires_at``
says when the verdict may be reused, and ``status`` records what actually
happened on the last attempt. A timeout and a clean "nothing known about this
indicator" are different facts and are stored differently - conflating them
would let an outage look like a clean bill of health.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, JSONType, TimestampMixin, utcnow
from app.models.enums import ThreatIntelReputation, ThreatIntelStatus


class ThreatIntelResult(Base, TimestampMixin):
    __tablename__ = "threat_intel_results"
    __table_args__ = (
        UniqueConstraint("provider", "ioc_type", "ioc_value", name="uq_ti_provider_indicator"),
        Index("ix_ti_reputation_checked", "reputation", "looked_up_at"),
        Index("ix_ti_expires", "expires_at"),
        CheckConstraint(
            "reputation IN ('malicious', 'suspicious', 'harmless', 'unknown')",
            name="ck_ti_reputation",
        ),
        CheckConstraint("confidence >= 0 AND confidence <= 100", name="ck_ti_confidence"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)

    ioc_id: Mapped[int | None] = mapped_column(
        ForeignKey("iocs.id", ondelete="CASCADE"), nullable=True, index=True
    )
    ioc_type: Mapped[str] = mapped_column(String(32), nullable=False)
    ioc_value: Mapped[str] = mapped_column(String(512), nullable=False, index=True)

    provider: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    status: Mapped[str] = mapped_column(
        String(24), default=ThreatIntelStatus.UNAVAILABLE.value, nullable=False
    )
    reputation: Mapped[str] = mapped_column(
        String(16), default=ThreatIntelReputation.UNKNOWN.value, nullable=False, index=True
    )
    #: The provider's own confidence where it publishes one, otherwise derived
    #: from its vote counts. 0 whenever the lookup did not succeed.
    confidence: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    malicious_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    suspicious_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    harmless_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    undetected_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    #: When the provider last analysed the indicator (their clock, not ours).
    last_analysis_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    #: When AEGISX asked (our clock).
    looked_up_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False, index=True
    )
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    #: A trimmed, non-sensitive subset of the provider response. Never the API
    #: key, never the full body - providers echo submitted content back.
    details: Mapped[dict] = mapped_column(JSONType, default=dict, nullable=False)

    ioc = relationship("IOC", back_populates="threat_intel")

    @property
    def is_actionable(self) -> bool:
        """True when this row carries a verdict, rather than a failure."""
        return self.status == ThreatIntelStatus.OK.value

    def __repr__(self) -> str:  # pragma: no cover
        return f"<ThreatIntelResult {self.provider} {self.ioc_value} {self.reputation}>"
