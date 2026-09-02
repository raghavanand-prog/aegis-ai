"""Notification endpoints."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.api.deps import require
from app.core.database import get_db
from app.core.rbac import Permission
from app.models.user import User
from app.repositories.notification_repository import notification_repository
from app.schemas.common import Page
from app.schemas.notification import NotificationCounts, NotificationRead
from app.services.serializers import notification_to_schema

router = APIRouter(prefix="/notifications", tags=["notifications"])


def _to_schema(db: Session, notification) -> NotificationRead:
    """Resolve the related event/incident display ids for the client."""
    event_id = notification.event.event_id if getattr(notification, "event", None) else None
    incident_id = None

    if notification.event_id or notification.incident_id:
        from app.models.event import Event
        from app.models.incident import Incident

        if notification.event_id:
            event = db.get(Event, notification.event_id)
            event_id = event.event_id if event else None
        if notification.incident_id:
            incident = db.get(Incident, notification.incident_id)
            incident_id = incident.incident_id if incident else None

    return notification_to_schema(notification, event_id=event_id, incident_id=incident_id)


@router.get("", response_model=Page[NotificationRead])
def list_notifications(
    db: Session = Depends(get_db),
    _: User = Depends(require(Permission.NOTIFICATIONS_READ)),
    unread_only: bool = Query(default=False, alias="unreadOnly"),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
) -> Page[NotificationRead]:
    notifications, total = notification_repository.list_paginated(
        db, unread_only=unread_only, limit=limit, offset=offset
    )
    return Page[NotificationRead](
        items=[_to_schema(db, notification) for notification in notifications],
        total=total,
        limit=limit,
        offset=offset,
    )


@router.get("/counts", response_model=NotificationCounts)
def notification_counts(
    db: Session = Depends(get_db), _: User = Depends(require(Permission.NOTIFICATIONS_READ))
) -> NotificationCounts:
    return NotificationCounts(
        total=notification_repository.count(db), unread=notification_repository.unread_count(db)
    )


@router.post("/{notification_id}/read", response_model=NotificationRead)
def mark_read(
    notification_id: int,
    db: Session = Depends(get_db),
    _: User = Depends(require(Permission.NOTIFICATIONS_UPDATE)),
) -> NotificationRead:
    notification = notification_repository.get(db, notification_id)
    if notification is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Notification not found")

    notification.is_read = True
    db.commit()
    return _to_schema(db, notification)


@router.post("/read-all", response_model=NotificationCounts)
def mark_all_read(
    db: Session = Depends(get_db), _: User = Depends(require(Permission.NOTIFICATIONS_UPDATE))
) -> NotificationCounts:
    notification_repository.mark_all_read(db)
    db.commit()
    return NotificationCounts(
        total=notification_repository.count(db), unread=notification_repository.unread_count(db)
    )
