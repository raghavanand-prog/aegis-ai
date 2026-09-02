"""Audit log schemas."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import Field

from app.schemas.common import CamelModel


class AuditLogRead(CamelModel):
    id: int
    timestamp: datetime
    username: str
    action: str
    target_type: str | None = None
    target_id: str | None = None
    ip_address: str | None = None
    details: dict[str, Any] = Field(default_factory=dict)
