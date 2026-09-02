"""Correlated sequence endpoints.

A sequence is a group of related events the correlation engine opened. It is
explicitly *not* an incident: nothing here is auto-promoted, because a
statistical grouping deciding on its own that the SOC has an incident is how a
queue becomes unusable. An analyst reads the sequence, sees why the events were
grouped, and promotes it if it warrants one.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Body, Depends, HTTPException, Query, Request, status
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.api.deps import client_ip, require
from app.core.database import get_db
from app.core.rbac import Permission
from app.correlation import catalogue
from app.correlation import engine as correlation_engine
from app.models.enums import AuditAction, SequenceStatus, Severity
from app.models.sequence import SecuritySequence
from app.models.user import User
from app.schemas.common import Message, as_utc
from app.schemas.incident import IncidentCreate
from app.services import audit_service, incident_service
from app.services.serializers import incident_to_schema

router = APIRouter(prefix="/sequences", tags=["sequences"])


def _sequence_or_404(db: Session, sequence_id: str) -> SecuritySequence:
    sequence = db.scalar(
        select(SecuritySequence).where(SecuritySequence.sequence_id == sequence_id)
    )
    if sequence is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Sequence not found")
    return sequence


@router.get(
    "",
    summary="Correlated sequences",
    description=(
        "Groups of related events, newest first. Each carries the pattern that grouped "
        "them, the entity they were grouped on, why they were grouped, and the risk "
        "signals behind the score."
    ),
)
def list_sequences(
    db: Session = Depends(get_db),
    _: User = Depends(require(Permission.SEQUENCES_READ)),
    status_filter: SequenceStatus | None = Query(default=None, alias="status"),
    severity: Severity | None = Query(default=None),
    pattern: str | None = Query(default=None, max_length=64),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
) -> dict[str, Any]:
    stmt = select(SecuritySequence)
    count_stmt = select(func.count()).select_from(SecuritySequence)

    def apply(condition):
        nonlocal stmt, count_stmt
        stmt = stmt.where(condition)
        count_stmt = count_stmt.where(condition)

    if status_filter:
        apply(SecuritySequence.status == status_filter.value)
    if severity:
        apply(SecuritySequence.severity == severity.value)
    if pattern:
        apply(SecuritySequence.pattern == pattern)

    total = int(db.scalar(count_stmt) or 0)
    rows = list(
        db.scalars(
            stmt.order_by(SecuritySequence.end_time.desc(), SecuritySequence.id.desc())
            .limit(limit)
            .offset(offset)
        )
    )
    return {
        "items": [correlation_engine.to_dict(row) for row in rows],
        "total": total,
        "limit": limit,
        "offset": offset,
    }


@router.get(
    "/patterns",
    summary="Correlation pattern catalogue",
    description=(
        "Every pattern the engine can apply, with the techniques it *infers* from a "
        "sequence's shape. Inferred is recorded distinctly from a technique a "
        "deterministic rule declared."
    ),
)
def patterns(_: User = Depends(require(Permission.SEQUENCES_READ))) -> dict[str, Any]:
    return {"patterns": catalogue(), "engine": correlation_engine.status()}


@router.get(
    "/{sequence_id}",
    summary="One sequence",
    responses={404: {"model": Message, "description": "Unknown sequence"}},
)
def get_sequence(
    sequence_id: str,
    db: Session = Depends(get_db),
    _: User = Depends(require(Permission.SEQUENCES_READ)),
) -> dict[str, Any]:
    sequence = _sequence_or_404(db, sequence_id)
    payload = correlation_engine.to_dict(sequence)
    payload["events"] = [
        {
            "id": event.event_id,
            "timestamp": as_utc(event.timestamp).isoformat(),
            "source": event.source,
            "eventType": event.event_type,
            "title": event.title,
            "severity": event.severity,
            "riskScore": event.risk_score,
            "hostname": event.hostname,
            "username": event.username,
            "sourceIp": event.source_ip,
            "isAnomaly": any(
                inference.is_anomaly for inference in (event.ml_inferences or [])
            ),
        }
        for event in sorted(sequence.events, key=lambda item: item.timestamp)
    ]
    return payload


@router.post(
    "/{sequence_id}/promote",
    summary="Promote a sequence into an incident",
    description=(
        "Creates one incident from every event in the sequence. This is deliberately an "
        "analyst decision: the correlation engine never opens an incident by itself."
    ),
    responses={
        404: {"model": Message, "description": "Unknown sequence"},
        409: {"model": Message, "description": "Sequence has already been promoted"},
    },
)
def promote_sequence(
    sequence_id: str,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(require(Permission.INCIDENTS_CREATE)),
    title: str | None = Body(default=None, embed=True, max_length=255),
) -> dict[str, Any]:
    sequence = _sequence_or_404(db, sequence_id)
    if sequence.incident_id is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"{sequence.sequence_id} is already linked to an incident.",
        )

    rationale = "\n".join(f"- {reason}" for reason in (sequence.rationale or []))
    payload = IncidentCreate(
        title=title or sequence.title,
        description=(
            f"{sequence.description}\n\n"
            f"Correlated by {sequence.pattern} on {sequence.correlation_key} "
            f"(confidence {sequence.confidence:.2f}).\n\n"
            f"Why these events were grouped:\n{rationale}"
        ),
        severity=Severity(sequence.severity),
        source="AEGISX Correlation",
        analyst=user.full_name or user.email,
        event_ids=[event.event_id for event in sequence.events],
        mitre_techniques=[
            str(entry.get("technique"))
            for entry in (sequence.techniques or [])
            if entry.get("technique")
        ],
    )

    try:
        incident = incident_service.create_incident(db, payload, user=user)
    except incident_service.IncidentError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc

    sequence.incident_id = incident.id
    sequence.status = SequenceStatus.PROMOTED.value
    db.flush()
    # Recomputed after the sequence is linked so the correlation signal is
    # included, and so the score and the breakdown under it agree.
    incident_service.recompute_risk(db, incident)

    audit_service.record(
        db,
        action=AuditAction.SEQUENCE_PROMOTED,
        user=user,
        target_type="sequence",
        target_id=sequence.sequence_id,
        ip_address=client_ip(request),
        details={
            "incidentId": incident.incident_id,
            "pattern": sequence.pattern,
            "eventCount": sequence.event_count,
        },
    )
    db.commit()
    return {
        "sequence": correlation_engine.to_dict(sequence),
        "incident": incident_to_schema(incident).model_dump(by_alias=True, mode="json"),
    }


@router.post(
    "/{sequence_id}/dismiss",
    summary="Dismiss a sequence",
    description=(
        "Marks a sequence as not worth an incident. It stays in the database - a "
        "dismissed correlation is evidence about the correlator's precision, which is "
        "what tuning it later depends on."
    ),
    responses={404: {"model": Message, "description": "Unknown sequence"}},
)
def dismiss_sequence(
    sequence_id: str,
    db: Session = Depends(get_db),
    user: User = Depends(require(Permission.INCIDENTS_UPDATE)),
) -> dict[str, Any]:
    sequence = _sequence_or_404(db, sequence_id)
    sequence.status = SequenceStatus.DISMISSED.value
    db.flush()
    audit_service.record(
        db,
        action=AuditAction.SEQUENCE_CREATED,
        user=user,
        target_type="sequence",
        target_id=sequence.sequence_id,
        details={"outcome": "dismissed"},
    )
    db.commit()
    return correlation_engine.to_dict(sequence)
