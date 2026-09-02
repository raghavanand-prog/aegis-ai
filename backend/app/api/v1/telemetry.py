"""Telemetry control endpoints."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.api.deps import require
from app.core.database import get_db
from app.core.rbac import Permission
from app.models.user import User
from app.telemetry.collector import collector

router = APIRouter(prefix="/telemetry", tags=["telemetry"])


@router.get("/status")
def telemetry_status(_: User = Depends(require(Permission.TELEMETRY_READ))) -> dict[str, Any]:
    """Report collector health, ingestion counters and registered sources."""
    return collector.status()


@router.post("/tick")
def telemetry_tick(
    db: Session = Depends(get_db), _: User = Depends(require(Permission.TELEMETRY_CONTROL))
) -> dict[str, Any]:
    """Run one collection cycle on demand (useful for demos and debugging)."""
    events = collector.collect_once(db)
    db.commit()
    return {"ingested": len(events), "eventIds": [event.event_id for event in events]}
