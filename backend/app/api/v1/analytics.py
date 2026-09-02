"""Analytics endpoints."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.api.deps import require
from app.core.database import get_db
from app.core.rbac import Permission
from app.models.user import User
from app.schemas.analytics import AnalyticsSummary
from app.services import analytics_service

router = APIRouter(prefix="/analytics", tags=["analytics"])


@router.get("/summary", response_model=AnalyticsSummary)
def analytics_summary(
    db: Session = Depends(get_db),
    _: User = Depends(require(Permission.ANALYTICS_READ)),
    window_hours: int = Query(default=24, ge=1, le=168, alias="windowHours"),
) -> AnalyticsSummary:
    """Aggregates for the Analytics page, computed from persisted rows."""
    return analytics_service.build_summary(db, window_hours=window_hours)
