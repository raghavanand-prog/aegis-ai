"""Analyst notifications raised by the platform."""

from __future__ import annotations

from sqlalchemy import Boolean, CheckConstraint, ForeignKey, Index, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, TimestampMixin
from app.models.enums import NotificationCategory, NotificationSeverity


class Notification(Base, TimestampMixin):
    __tablename__ = "notifications"

    # The drawer reads unread-first, newest-first.
    __table_args__ = (
        Index("ix_notifications_read_created", "is_read", "created_at"),
        CheckConstraint(
            "severity IN ('low', 'medium', 'high', 'critical')",
            name="ck_notifications_severity",
        ),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, default="", nullable=False)
    severity: Mapped[str] = mapped_column(
        String(16), default=NotificationSeverity.MEDIUM.value, nullable=False, index=True
    )
    category: Mapped[str] = mapped_column(
        String(32), default=NotificationCategory.SYSTEM.value, nullable=False
    )
    is_read: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False, index=True)

    # Null user_id means the notification is visible to the whole SOC.
    user_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=True, index=True
    )
    event_id: Mapped[int | None] = mapped_column(
        ForeignKey("events.id", ondelete="CASCADE"), nullable=True
    )
    incident_id: Mapped[int | None] = mapped_column(
        ForeignKey("incidents.id", ondelete="CASCADE"), nullable=True
    )

    def __repr__(self) -> str:  # pragma: no cover
        return f"<Notification {self.severity} {self.title!r}>"
