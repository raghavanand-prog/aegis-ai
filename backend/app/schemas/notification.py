"""Notification schemas."""

from __future__ import annotations

from datetime import datetime

from app.models.enums import NotificationCategory, NotificationSeverity
from app.schemas.common import CamelModel


class NotificationRead(CamelModel):
    id: int
    title: str
    description: str
    severity: NotificationSeverity
    category: NotificationCategory
    is_read: bool
    event_id: str | None = None
    incident_id: str | None = None
    created_at: datetime


class NotificationCounts(CamelModel):
    total: int
    unread: int
