"""Incident endpoints."""

from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Body, Depends, HTTPException, Query, Request, status
from sqlalchemy.orm import Session

from app.api.deps import client_ip, require
from app.core.database import get_db
from app.core.rbac import Permission, has_permission
from app.incidents import lifecycle
from app.models.enums import AuditAction, IncidentStatus, Severity
from app.models.user import User
from app.schemas.common import Message, Page
from app.schemas.incident import (
    IncidentCreate,
    IncidentRead,
    IncidentTransitions,
    IncidentUpdate,
)
from app.services import (
    audit_service,
    decision_service,
    incident_service,
    notification_service,
)
from app.services.serializers import incident_to_schema

router = APIRouter(prefix="/incidents", tags=["incidents"])

#: How each lifecycle refusal reaches the caller. Ordered most specific first;
#: `LifecycleError` itself is the fallback and should not normally be raised.
_LIFECYCLE_STATUS: dict[type[Exception], int] = {
    lifecycle.InvalidTransition: status.HTTP_409_CONFLICT,
    lifecycle.UnauthorizedTransition: status.HTTP_403_FORBIDDEN,
    lifecycle.TransitionReasonRequired: status.HTTP_400_BAD_REQUEST,
    lifecycle.LifecycleError: status.HTTP_400_BAD_REQUEST,
}


@router.get("", response_model=Page[IncidentRead])
def list_incidents(
    db: Session = Depends(get_db),
    _: User = Depends(require(Permission.INCIDENTS_READ)),
    search: str | None = Query(default=None, max_length=200),
    severity: Severity | None = Query(default=None),
    status_filter: IncidentStatus | None = Query(default=None, alias="status"),
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
) -> Page[IncidentRead]:
    incidents, total = incident_service.list_incidents(
        db,
        search=search,
        severity=severity.value if severity else None,
        status=status_filter.value if status_filter else None,
        limit=limit,
        offset=offset,
    )
    return Page[IncidentRead](
        items=[incident_to_schema(incident) for incident in incidents],
        total=total,
        limit=limit,
        offset=offset,
    )


@router.get("/{incident_id}", response_model=IncidentRead)
def get_incident(
    incident_id: str,
    db: Session = Depends(get_db),
    _: User = Depends(require(Permission.INCIDENTS_READ)),
) -> IncidentRead:
    incident = incident_service.get_incident(db, incident_id)
    if incident is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Incident not found")
    return incident_to_schema(incident)


@router.post("", response_model=IncidentRead, status_code=status.HTTP_201_CREATED)
def create_incident(
    payload: IncidentCreate,
    db: Session = Depends(get_db),
    user: User = Depends(require(Permission.INCIDENTS_CREATE)),
) -> IncidentRead:
    try:
        incident = incident_service.create_incident(db, payload, user=user)
    except incident_service.IncidentError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    db.commit()
    return incident_to_schema(incident)


@router.patch("/{incident_id}", response_model=IncidentRead)
def update_incident(
    incident_id: str,
    payload: IncidentUpdate,
    db: Session = Depends(get_db),
    user: User = Depends(require(Permission.INCIDENTS_UPDATE)),
) -> IncidentRead:
    incident = incident_service.get_incident(db, incident_id)
    if incident is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Incident not found")

    try:
        incident_service.update_incident(db, incident, payload, user=user)
    except decision_service.EvidenceDriftError as exc:
        # 409, same as an illegal transition: the request is well-formed and
        # the caller is authorised - the world moved underneath it. The refusal
        # is audited, because a decision attempted against stale evidence is
        # worth seeing even though nothing changed.
        db.rollback()
        audit_service.record(
            db,
            action=AuditAction.DECISION_EVIDENCE_STALE,
            user=user,
            target_type="incident",
            target_id=incident_id,
            details={
                "attemptedStatus": payload.status.value if payload.status else None,
                "reviewedDigest": (payload.expected_evidence_digest or "")[:64],
            },
        )
        db.commit()
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    except lifecycle.LifecycleError as exc:
        # Three refusals, three codes, because they tell the caller to do three
        # different things: change what you asked for, get an authority, or
        # write down why. The rollback matters as much as the code - a PATCH
        # carrying both a title and a refused status must not half-apply.
        db.rollback()
        raise HTTPException(status_code=_LIFECYCLE_STATUS[type(exc)], detail=str(exc)) from exc
    db.commit()
    return incident_to_schema(incident)


@router.get(
    "/{incident_id}/transitions",
    response_model=IncidentTransitions,
    summary="What this incident may become, and what that would take",
    description=(
        "Derived from the lifecycle rules themselves rather than restated, so a client "
        "cannot drift from what the server will actually allow. Options the caller may "
        "not take are listed with `permitted: false` rather than omitted - a UI that "
        "silently hides half the lifecycle teaches its users the wrong model of it."
    ),
    responses={404: {"model": Message, "description": "Unknown incident"}},
)
def incident_transitions(
    incident_id: str,
    db: Session = Depends(get_db),
    user: User = Depends(require(Permission.INCIDENTS_READ)),
) -> IncidentTransitions:
    incident = incident_service.get_incident(db, incident_id)
    if incident is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Incident not found")

    current = lifecycle.parse(incident.status)
    options = []
    for target in sorted(lifecycle.allowed_transitions(current), key=lambda s: s.value):
        permission = lifecycle.required_permission(current, target)
        options.append(
            {
                "target": target,
                "requiresReason": lifecycle.requires_reason(current, target),
                "requiredPermission": permission.value,
                "permitted": has_permission(user.role, permission),
                "bindsEvidence": decision_service.is_consequential(current.value, target),
            }
        )

    return IncidentTransitions.model_validate(
        {
            "incidentId": incident.incident_id,
            "currentStatus": current,
            "isTerminal": lifecycle.is_terminal(current),
            "options": options,
        }
    )


@router.post("/{incident_id}/response", response_model=IncidentRead)
def record_response_action(
    incident_id: str,
    request: Request,
    action: str = Body(embed=True, max_length=120),
    db: Session = Depends(get_db),
    user: User = Depends(require(Permission.INCIDENTS_RESPOND)),
) -> IncidentRead:
    """Record a containment or response action against an incident.

    V1 stores and announces the action; it does not execute anything on a real
    system. Automated response is deliberately out of scope until there is a
    reviewed action framework behind it.
    """
    incident = incident_service.get_incident(db, incident_id)
    if incident is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Incident not found")

    actor = user.full_name or user.email
    incident.timeline = [
        *(incident.timeline or []),
        {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "action": "response_action",
            "actor": actor,
            "detail": action,
        },
    ]
    audit_service.record(
        db,
        action=AuditAction.RESPONSE_ACTION,
        user=user,
        target_type="incident",
        target_id=incident.incident_id,
        ip_address=client_ip(request),
        details={"action": action},
    )
    notification_service.notify_response_action(db, incident, action)
    db.commit()
    return incident_to_schema(incident)
