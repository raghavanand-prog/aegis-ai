"""Investigation evidence endpoints.

Two routes, both read-only, both scoped to one incident:

* ``GET /incidents/{id}/evidence``            - the evidence set, with filters
* ``GET /incidents/{id}/evidence/{ev_id}``    - one item, for its provenance

There is no third. A general ``/evidence`` collection was considered and
dropped: every legitimate question about evidence starts from an incident, an
unscoped collection would need its own authorization story, and the scoping is
what stops an evidence id learned elsewhere becoming a read primitive.

There is no write route either. Evidence is a projection of records the
platform already holds, so there is nothing to create and nothing to edit -
which is how "an analyst must not be able to silently rewrite historical
evidence" is enforced here: not by a check, but by the absence of a door.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy.orm import Session

from app.api.deps import client_ip, require
from app.core.database import get_db
from app.core.rbac import Permission
from app.evidence import service as evidence_service
from app.evidence.models import EvidenceKind
from app.models.enums import AuditAction
from app.models.user import User
from app.schemas.common import Message
from app.schemas.evidence import EvidenceItemRead, EvidenceSetRead
from app.services import audit_service, incident_service

router = APIRouter(prefix="/incidents", tags=["evidence"])


def _incident_or_404(db: Session, incident_id: str):
    incident = incident_service.get_incident(db, incident_id)
    if incident is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Incident not found")
    return incident


@router.get(
    "/{incident_id}/evidence",
    response_model=EvidenceSetRead,
    summary="Evidence behind an incident",
    description=(
        "Every piece of evidence the platform holds about this incident, each with the "
        "provenance of where it came from, when it was observed, when it was collected, "
        "and how much the platform can promise about the stored record. Providers that "
        "could not answer are reported separately from an empty result."
    ),
    responses={404: {"model": Message, "description": "Unknown incident"}},
)
def list_evidence(
    incident_id: str,
    db: Session = Depends(get_db),
    _: User = Depends(require(Permission.INCIDENTS_READ)),
    kind: EvidenceKind | None = Query(
        default=None,
        description=(
            "Restrict to one kind. The reserved kinds (cloud_finding, endpoint_finding, "
            "identity_finding, network_finding) are valid and currently return nothing - "
            "no provider produces them yet."
        ),
    ),
    provider: str | None = Query(default=None, max_length=64),
) -> EvidenceSetRead:
    incident = _incident_or_404(db, incident_id)
    evidence = evidence_service.collect_for_incident(
        db, incident, kind=kind, provider=provider
    )
    return EvidenceSetRead.model_validate(evidence.to_dict())


@router.get(
    "/{incident_id}/evidence/{evidence_id}",
    response_model=EvidenceItemRead,
    summary="One piece of evidence and its provenance",
    description=(
        "Scoped to the incident in the path. An evidence id belonging to a different "
        "incident returns 404 rather than the item - evidence ids are derived from the "
        "source row and are therefore guessable, so the scoping is the access control."
    ),
    responses={404: {"model": Message, "description": "Unknown incident or evidence"}},
)
def get_evidence(
    incident_id: str,
    evidence_id: str,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(require(Permission.INCIDENTS_READ)),
) -> EvidenceItemRead:
    incident = _incident_or_404(db, incident_id)

    item = evidence_service.get_item(db, incident, evidence_id)
    if item is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Evidence not found"
        )

    # Same precedent as event.viewed and ioc.viewed: reading one specific
    # security record is worth recording. The list is not audited - it is the
    # ordinary way to open the workspace, and auditing it would bury the
    # deliberate lookups it exists to surface.
    audit_service.record(
        db,
        action=AuditAction.EVIDENCE_VIEWED,
        user=user,
        target_type="evidence",
        target_id=item.evidence_id,
        ip_address=client_ip(request),
        details={
            "incidentId": incident.incident_id,
            "kind": item.kind.value,
            "sourceRef": item.provenance.source_ref,
            # Recorded so a later reader can tell whether the evidence someone
            # looked at is still the evidence that is there now.
            "contentDigest": item.content_digest,
        },
    )
    db.commit()

    return EvidenceItemRead.model_validate(item.to_dict())
