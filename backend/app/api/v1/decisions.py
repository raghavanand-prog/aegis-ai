"""Decision-bound evidence integrity endpoints.

Two routes, both read-only, both scoped to one incident:

* ``GET /incidents/{id}/decisions``            - every recorded decision
* ``GET /incidents/{id}/decisions/{ref}``      - one, with its drift report

Neither creates anything. A binding is written by the transition that makes the
decision, inside that transition's transaction, so there is no request that
could produce one out of band - and none that could revise one. An analyst
cannot rewrite what a past decision rested on because the application has no
operation that would.

Every response carries the drift verdict rather than offering it separately. A
binding rendered without one invites the reader to assume nothing moved, which
is the exact assumption this phase exists to stop anyone making for free.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.api.deps import require
from app.core.database import get_db
from app.core.rbac import Permission
from app.evidence.binding import DriftVerdict
from app.models.user import User
from app.schemas.common import Message
from app.schemas.decision import DecisionBindingList, DecisionBindingRead
from app.services import decision_service, incident_service

router = APIRouter(prefix="/incidents", tags=["decisions"])


def _incident_or_404(db: Session, incident_id: str):
    incident = incident_service.get_incident(db, incident_id)
    if incident is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Incident not found")
    return incident


def _render(db: Session, incident, binding) -> dict:
    drift = decision_service.verify(db, incident, binding)
    return {
        "decisionRef": binding.decision_ref,
        "decisionType": binding.decision_type,
        "incidentRef": binding.incident_ref,
        "fromState": binding.from_state,
        "toState": binding.to_state,
        "reason": binding.reason,
        "decidedBy": binding.decided_by,
        "decidedByRole": binding.decided_by_role,
        "decidedAt": binding.decided_at,
        "manifestDigest": binding.manifest_digest,
        "evidenceCount": binding.evidence_count,
        "drift": {
            "verdict": drift.verdict.value,
            "severity": drift.verdict.severity,
            "underminesDecision": drift.undermines_decision,
            "manifestMatches": drift.manifest_matches,
            "manifestAtDecision": drift.manifest_at_decision,
            "manifestNow": drift.manifest_now,
            "added": list(drift.added),
            "removed": list(drift.removed),
            "changed": [
                {
                    "evidenceId": entry.evidence_id,
                    "integrity": entry.integrity.value,
                    "kind": entry.kind,
                    "provider": entry.provider,
                    "digestAtDecision": entry.digest_at_decision,
                    "digestNow": entry.digest_now,
                }
                for entry in drift.changed
            ],
            "attributionComplete": drift.attribution_complete,
            "degradedAtDecision": [dict(entry) for entry in drift.degraded_at_decision],
        },
    }


@router.get(
    "/{incident_id}/decisions",
    response_model=DecisionBindingList,
    summary="Decisions taken on this incident, and whether their evidence still holds",
    description=(
        "Every consequential lifecycle decision recorded against this incident, newest "
        "first, each with a live comparison between the evidence it was taken on and the "
        "evidence there now. Decisions taken before V9 have no binding and do not appear - "
        "which is 'not recorded', never 'unchanged'."
    ),
    responses={404: {"model": Message, "description": "Unknown incident"}},
)
def list_decisions(
    incident_id: str,
    db: Session = Depends(get_db),
    _: User = Depends(require(Permission.INCIDENTS_READ)),
) -> DecisionBindingList:
    incident = _incident_or_404(db, incident_id)
    bindings = decision_service.list_for_incident(db, incident)

    items = [_render(db, incident, binding) for binding in bindings]
    worst = DriftVerdict.UNCHANGED
    for item in items:
        verdict = DriftVerdict(item["drift"]["verdict"])
        if verdict.severity > worst.severity:
            worst = verdict

    return DecisionBindingList.model_validate(
        {
            "incidentId": incident.incident_id,
            "total": len(items),
            "worstVerdict": worst.value,
            "items": items,
        }
    )


@router.get(
    "/{incident_id}/decisions/{decision_ref}",
    response_model=DecisionBindingRead,
    summary="One decision and the state of the evidence behind it",
    description=(
        "Scoped to the incident in the path: a reference belonging to another incident "
        "returns 404 rather than the binding."
    ),
    responses={404: {"model": Message, "description": "Unknown incident or decision"}},
)
def get_decision(
    incident_id: str,
    decision_ref: str,
    db: Session = Depends(get_db),
    _: User = Depends(require(Permission.INCIDENTS_READ)),
) -> DecisionBindingRead:
    incident = _incident_or_404(db, incident_id)
    binding = decision_service.get_for_incident(db, incident, decision_ref)
    if binding is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Decision not found")
    return DecisionBindingRead.model_validate(_render(db, incident, binding))
