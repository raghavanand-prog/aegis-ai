"""Append-only audit trail of analyst actions."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Index, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, JSONType, utcnow


class AuditLog(Base):
    __tablename__ = "audit_logs"

    # Audit is queried "what happened to this object" and "who did this kind of
    # thing recently".
    __table_args__ = (
        Index("ix_audit_action_timestamp", "action", "timestamp"),
        Index("ix_audit_target", "target_type", "target_id"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False, index=True
    )

    user_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True
    )
    # Kept denormalized so the trail survives user deletion.
    username: Mapped[str] = mapped_column(String(255), default="system", nullable=False)

    action: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    target_type: Mapped[str | None] = mapped_column(String(32), nullable=True)
    target_id: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    ip_address: Mapped[str | None] = mapped_column(String(64), nullable=True)
    details: Mapped[dict] = mapped_column(JSONType, default=dict, nullable=False)

    user = relationship("User", back_populates="audit_logs")

    def __repr__(self) -> str:  # pragma: no cover
        return f"<AuditLog {self.action} {self.target_type}:{self.target_id}>"
