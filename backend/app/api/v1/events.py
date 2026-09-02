"""Event endpoints."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy.orm import Session

from app.api.deps import client_ip, require
from app.core.database import get_db
from app.core.rbac import Permission
from app.models.enums import AuditAction, EventStatus, Severity, SourceType
from app.models.user import User
from app.schemas.common import Page
from app.schemas.event import EventIngest, EventPromoteRequest, EventRead, EventStatusUpdate
from app.schemas.incident import IncidentRead
from app.services import audit_service, event_service, incident_service
from app.services.serializers import event_to_schema, incident_to_schema

router = APIRouter(prefix="/events", tags=["events"])


@router.get("", response_model=Page[EventRead])
def list_events(
    db: Session = Depends(get_db),
    _: User = Depends(require(Permission.EVENTS_READ)),
    search: str | None = Query(default=None, max_length=200),
    severity: Severity | None = Query(default=None),
    status_filter: EventStatus | None = Query(default=None, alias="status"),
    source: str | None = Query(default=None, max_length=120),
    source_type: SourceType | None = Query(default=None, alias="sourceType"),
    is_anomaly: bool | None = Query(
        default=None,
        alias="isAnomaly",
        description=(
            "Filter to events the anomaly model flagged (true) or did not (false). "
            "Omit for all events. Note that 'false' includes events that were never "
            "scored - use /ml/status to tell the two apart."
        ),
    ),
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
) -> Page[EventRead]:
    events, total = event_service.list_events(
        db,
        search=search,
        severity=severity.value if severity else None,
        status=status_filter.value if status_filter else None,
        source=source,
        source_type=source_type.value if source_type else None,
        is_anomaly=is_anomaly,
        limit=limit,
        offset=offset,
    )
    return Page[EventRead](
        items=[event_to_schema(event) for event in events],
        total=total,
        limit=limit,
        offset=offset,
    )


@router.get("/{event_id}", response_model=EventRead)
def get_event(
    event_id: str,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(require(Permission.EVENTS_READ)),
) -> EventRead:
    event = event_service.get_event(db, event_id)
    if event is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Event not found")

    audit_service.record(
        db,
        action=AuditAction.EVENT_VIEWED,
        user=user,
        target_type="event",
        target_id=event.event_id,
        ip_address=client_ip(request),
    )
    db.commit()
    return event_to_schema(event)


@router.post("", response_model=EventRead, status_code=status.HTTP_201_CREATED)
def ingest_event(
    payload: EventIngest,
    db: Session = Depends(get_db),
    _: User = Depends(require(Permission.EVENTS_INGEST)),
) -> EventRead:
    """Ingest a single event from an external collector."""
    event = event_service.ingest_payload(db, payload)
    db.commit()
    return event_to_schema(event)


@router.patch("/{event_id}/status", response_model=EventRead)
def update_event_status(
    event_id: str,
    payload: EventStatusUpdate,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(require(Permission.EVENTS_UPDATE)),
) -> EventRead:
    event = event_service.get_event(db, event_id)
    if event is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Event not found")

    event_service.update_status(db, event, payload.status)
    audit_service.record(
        db,
        action=AuditAction.EVENT_STATUS_CHANGED,
        user=user,
        target_type="event",
        target_id=event.event_id,
        ip_address=client_ip(request),
        details={"status": payload.status.value},
    )
    db.commit()
    return event_to_schema(event)


@router.post("/{event_id}/promote", response_model=IncidentRead, status_code=status.HTTP_201_CREATED)
def promote_event(
    event_id: str,
    payload: EventPromoteRequest | None = None,
    db: Session = Depends(get_db),
    user: User = Depends(require(Permission.EVENTS_PROMOTE)),
) -> IncidentRead:
    """Promote an event into a new incident (event -> incident -> audit -> notification)."""
    event = event_service.get_event(db, event_id)
    if event is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Event not found")

    try:
        incident = incident_service.promote_event(db, event, payload, user=user)
    except incident_service.IncidentError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc

    db.commit()
    return incident_to_schema(incident)
