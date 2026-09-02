"""Analyst accounts."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import Boolean, CheckConstraint, DateTime, Integer, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, TimestampMixin
from app.models.enums import UserRole


class User(Base, TimestampMixin):
    __tablename__ = "users"

    __table_args__ = (
        CheckConstraint("role IN ('admin', 'analyst', 'viewer')", name="ck_users_role"),
        CheckConstraint("token_version >= 1", name="ck_users_token_version"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True, nullable=False)
    full_name: Mapped[str] = mapped_column(String(120), nullable=False, default="")
    # PBKDF2 digest - never the plaintext, never returned by the API.
    hashed_password: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[str] = mapped_column(String(32), default=UserRole.ANALYST.value, nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    # Bumped whenever every existing session for this user must stop working
    # (password change, "sign out everywhere", account compromise). Tokens
    # carry the value they were issued with, so revocation needs no token store.
    token_version: Mapped[int] = mapped_column(Integer, default=1, nullable=False)

    incidents = relationship("Incident", back_populates="assignee", foreign_keys="Incident.assignee_id")
    audit_logs = relationship("AuditLog", back_populates="user")

    def __repr__(self) -> str:  # pragma: no cover - debugging helper
        return f"<User {self.email} ({self.role})>"
