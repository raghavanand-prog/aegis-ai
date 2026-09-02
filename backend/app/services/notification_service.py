"""Notification creation and delivery.

Notifications are persisted first and then pushed to connected clients, so a
client that was offline still sees them when it reconnects.
"""

from __future__ import annotations

import logging

from sqlalchemy.orm import Session

from app.models.enums import NotificationCategory, NotificationSeverity, Severity
from app.models.event import Event
from app.models.incident import Incident
from app.models.notification import Notification
from app.repositories.notification_repository import notification_repository
from app.services.serializers import notification_to_schema
from app.ws.manager import manager

logger = logging.getLogger(__name__)

#: Events at or above this severity raise a notification.
NOTIFY_FROM = {Severity.HIGH.value, Severity.CRITICAL.value}

_SEVERITY_MAP = {
    Severity.LOW.value: NotificationSeverity.LOW,
    Severity.MEDIUM.value: NotificationSeverity.MEDIUM,
    Severity.HIGH.value: NotificationSeverity.HIGH,
    Severity.CRITICAL.value: NotificationSeverity.CRITICAL,
}


def to_notification_severity(severity: str) -> NotificationSeverity:
    return _SEVERITY_MAP.get(severity, NotificationSeverity.MEDIUM)


def create(
    db: Session,
    *,
    title: str,
    description: str,
    severity: NotificationSeverity,
    category: NotificationCategory,
    event: Event | None = None,
    incident: Incident | None = None,
    user_id: int | None = None,
    broadcast: bool = True,
) -> Notification:
    notification = Notification(
        title=title,
        description=description,
        severity=severity.value,
        category=category.value,
        user_id=user_id,
        event_id=event.id if event else None,
        incident_id=incident.id if incident else None,
    )
    notification_repository.add(db, notification)

    if broadcast:
        payload = notification_to_schema(
            notification,
            event_id=event.event_id if event else None,
            incident_id=incident.incident_id if incident else None,
        )
        manager.broadcast_threadsafe("notification.created", payload.model_dump(by_alias=True, mode="json"))

    return notification


def notify_for_event(db: Session, event: Event, *, broadcast: bool = True) -> Notification | None:
    """Raise a notification for a high or critical event."""
    if event.severity not in NOTIFY_FROM:
        return None

    location = event.hostname or event.source_ip or event.username or "unknown asset"
    return create(
        db,
        title=event.title,
        description=f"{event.source} - {location} ({event.event_id})",
        severity=to_notification_severity(event.severity),
        category=NotificationCategory.EVENT,
        event=event,
        broadcast=broadcast,
    )


def notify_incident_created(db: Session, incident: Incident, *, broadcast: bool = True) -> Notification:
    return create(
        db,
        title=f"Incident opened: {incident.title}",
        description=f"{incident.incident_id} - {incident.severity} severity, assigned to {incident.analyst}.",
        severity=to_notification_severity(incident.severity),
        category=NotificationCategory.INCIDENT,
        incident=incident,
        broadcast=broadcast,
    )


def notify_incident_assigned(db: Session, incident: Incident, *, broadcast: bool = True) -> Notification:
    return create(
        db,
        title=f"Incident assigned: {incident.incident_id}",
        description=f"{incident.title} is now owned by {incident.analyst}.",
        severity=to_notification_severity(incident.severity),
        category=NotificationCategory.ASSIGNMENT,
        incident=incident,
        broadcast=broadcast,
    )


def notify_response_action(
    db: Session, incident: Incident, action: str, *, broadcast: bool = True
) -> Notification:
    return create(
        db,
        title=f"Response action: {action}",
        description=f"{action} initiated on {incident.incident_id} ({incident.title}).",
        severity=to_notification_severity(incident.severity),
        category=NotificationCategory.RESPONSE,
        incident=incident,
        broadcast=broadcast,
    )
