"""Incident creation, promotion from events, and updates."""

from __future__ import annotations

import logging
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from app.models.enums import AuditAction, IncidentStatus
from app.models.event import Event
from app.models.incident import Incident
from app.models.user import User
from app.repositories.event_repository import event_repository
from app.repositories.incident_repository import incident_repository
from app.schemas.event import EventPromoteRequest
from app.schemas.incident import IncidentCreate, IncidentUpdate
from app.services import audit_service, notification_service
from app.services.serializers import incident_to_schema
from app.ws.manager import manager

logger = logging.getLogger(__name__)


class IncidentError(Exception):
    """Raised for invalid incident operations (e.g. promoting twice)."""


def _timeline_entry(action: str, actor: str, detail: str) -> dict:
    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "action": action,
        "actor": actor,
        "detail": detail,
    }


def _broadcast(incident: Incident, message_type: str) -> None:
    manager.broadcast_threadsafe(
        message_type, incident_to_schema(incident).model_dump(by_alias=True, mode="json")
    )


def recompute_risk(db: Session, incident: Incident) -> None:
    """Make the incident's risk score and its explanation agree.

    An incident inherits evidence from several places: the rule and ML signals
    on each linked event, and the correlation signal from any sequence it was
    promoted from. Taking the score from one source and the signal list from
    another - which is what happened before this existed - produces a panel
    where the number and the reasons underneath it do not add up, and an
    analyst has no way to tell which is wrong.

    The strongest contribution per (type, source) is kept rather than the sum:
    one rule firing across twenty linked events is one finding observed twenty
    times, and summing would let repetition alone manufacture a critical.
    """
    strongest: dict[tuple[str, str], dict] = {}

    def offer(signal: dict) -> None:
        key = (str(signal.get("type", "")), str(signal.get("source", "")))
        current = strongest.get(key)
        if current is None or signal.get("contribution", 0) > current.get("contribution", 0):
            strongest[key] = signal

    for event in incident.events or []:
        for signal in event.risk_signals or []:
            offer(signal)
    for sequence in incident.sequences or []:
        for signal in sequence.risk_signals or []:
            offer(signal)

    signals = sorted(
        strongest.values(), key=lambda item: item.get("contribution", 0), reverse=True
    )
    total = min(sum(int(signal.get("contribution", 0)) for signal in signals), 100)

    incident.risk_signals = signals
    # Events scored before V3 carry no signals at all; falling back to the
    # highest member score keeps those incidents from collapsing to zero.
    incident.risk_score = total if signals else max(
        (event.risk_score for event in incident.events or []), default=incident.risk_score
    )
    db.flush()


def _link_events(db: Session, incident: Incident, events: list[Event]) -> None:
    for event in events:
        event.incident_id = incident.id
        for ioc in event.iocs:
            if ioc not in incident.iocs:
                incident.iocs.append(ioc)
        for technique in event.mitre_techniques or []:
            if technique not in (incident.mitre_techniques or []):
                incident.mitre_techniques = [*(incident.mitre_techniques or []), technique]
    db.flush()


def create_incident(
    db: Session,
    payload: IncidentCreate,
    *,
    user: User | None = None,
    broadcast: bool = True,
) -> Incident:
    events = event_repository.get_many_by_event_ids(db, payload.event_ids)
    missing = set(payload.event_ids) - {event.event_id for event in events}
    if missing:
        raise IncidentError(f"Unknown event(s): {', '.join(sorted(missing))}")

    risk_score = max((event.risk_score for event in events), default=0)
    actor = user.full_name or user.email if user else "system"

    incident = Incident(
        title=payload.title,
        description=payload.description,
        severity=payload.severity.value,
        status=payload.status.value,
        source=payload.source,
        analyst=payload.analyst,
        assignee_id=user.id if (user and payload.analyst != "Unassigned") else None,
        risk_score=risk_score,
        mitre_techniques=list(payload.mitre_techniques),
        timeline=[_timeline_entry("created", actor, f"Incident opened from {len(events)} event(s).")],
    )
    incident_repository.create(db, incident)
    _link_events(db, incident, events)
    recompute_risk(db, incident)

    audit_service.record(
        db,
        action=AuditAction.INCIDENT_CREATED,
        user=user,
        target_type="incident",
        target_id=incident.incident_id,
        details={"title": incident.title, "eventIds": [event.event_id for event in events]},
    )
    notification_service.notify_incident_created(db, incident, broadcast=broadcast)
    db.flush()

    if broadcast:
        _broadcast(incident, "incident.created")
    return incident


def promote_event(
    db: Session,
    event: Event,
    payload: EventPromoteRequest | None = None,
    *,
    user: User | None = None,
    broadcast: bool = True,
) -> Incident:
    """Promote a single event into a new incident."""
    if event.incident_id is not None:
        raise IncidentError(f"{event.event_id} is already linked to an incident.")

    payload = payload or EventPromoteRequest()
    actor = (user.full_name or user.email) if user else "system"
    severity = (payload.severity.value if payload.severity else event.severity)
    analyst = payload.analyst or (user.full_name or user.email if user else "Unassigned")

    incident = Incident(
        title=payload.title or event.title,
        description=payload.description
        or f"Promoted from {event.event_id}: {event.description or event.title}",
        severity=severity,
        status=IncidentStatus.OPEN.value,
        source=event.source,
        analyst=analyst,
        assignee_id=user.id if user else None,
        risk_score=event.risk_score,
        mitre_techniques=list(event.mitre_techniques or []),
        timeline=[
            _timeline_entry("promoted", actor, f"Incident promoted from event {event.event_id}."),
        ],
    )
    incident_repository.create(db, incident)
    _link_events(db, incident, [event])
    recompute_risk(db, incident)

    audit_service.record(
        db,
        action=AuditAction.EVENT_PROMOTED,
        user=user,
        target_type="event",
        target_id=event.event_id,
        details={"incidentId": incident.incident_id, "severity": severity},
    )
    audit_service.record(
        db,
        action=AuditAction.INCIDENT_CREATED,
        user=user,
        target_type="incident",
        target_id=incident.incident_id,
        details={"promotedFrom": event.event_id},
    )
    notification_service.notify_incident_created(db, incident, broadcast=broadcast)
    db.flush()

    if broadcast:
        _broadcast(incident, "incident.created")
        from app.services.serializers import event_to_schema  # local import avoids a cycle

        manager.broadcast_threadsafe(
            "event.updated", event_to_schema(event).model_dump(by_alias=True, mode="json")
        )
    return incident


def update_incident(
    db: Session,
    incident: Incident,
    payload: IncidentUpdate,
    *,
    user: User | None = None,
    broadcast: bool = True,
) -> Incident:
    actor = (user.full_name or user.email) if user else "system"
    timeline = list(incident.timeline or [])

    if payload.title is not None:
        incident.title = payload.title
    if payload.description is not None:
        incident.description = payload.description
    if payload.severity is not None and payload.severity.value != incident.severity:
        timeline.append(
            _timeline_entry(
                "severity_changed", actor, f"{incident.severity} -> {payload.severity.value}"
            )
        )
        incident.severity = payload.severity.value

    if payload.status is not None and payload.status.value != incident.status:
        timeline.append(
            _timeline_entry("status_changed", actor, f"{incident.status} -> {payload.status.value}")
        )
        incident.status = payload.status.value
        incident.resolved_at = (
            datetime.now(timezone.utc) if payload.status == IncidentStatus.RESOLVED else None
        )
        audit_service.record(
            db,
            action=AuditAction.INCIDENT_STATUS_CHANGED,
            user=user,
            target_type="incident",
            target_id=incident.incident_id,
            details={"status": incident.status},
        )

    if payload.analyst is not None and payload.analyst != incident.analyst:
        timeline.append(
            _timeline_entry("assigned", actor, f"{incident.analyst} -> {payload.analyst}")
        )
        incident.analyst = payload.analyst
        incident.assignee_id = payload.assignee_id if payload.assignee_id is not None else incident.assignee_id
        audit_service.record(
            db,
            action=AuditAction.INCIDENT_ASSIGNED,
            user=user,
            target_type="incident",
            target_id=incident.incident_id,
            details={"analyst": incident.analyst},
        )
        notification_service.notify_incident_assigned(db, incident, broadcast=broadcast)

    incident.timeline = timeline
    db.flush()

    if broadcast:
        _broadcast(incident, "incident.updated")
    return incident


def get_incident(db: Session, incident_id: str) -> Incident | None:
    return incident_repository.get_by_incident_id(db, incident_id)


def list_incidents(
    db: Session,
    *,
    search: str | None = None,
    severity: str | None = None,
    status: str | None = None,
    limit: int = 100,
    offset: int = 0,
) -> tuple[list[Incident], int]:
    return incident_repository.list_paginated(
        db, search=search, severity=severity, status=status, limit=limit, offset=offset
    )
