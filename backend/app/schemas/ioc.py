"""IOC schemas."""

from __future__ import annotations

from datetime import datetime

from app.models.enums import IOCType, Severity
from app.schemas.common import CamelModel


class IOCRead(CamelModel):
    id: int
    type: IOCType
    value: str
    description: str | None = None
    severity: Severity
    confidence: int
    source: str | None = None
    sighting_count: int
    first_seen: datetime
    last_seen: datetime
