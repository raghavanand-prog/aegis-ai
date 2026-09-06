"""Response action request and approval endpoints.

    POST /incidents/{id}/response-actions               raise a request
    GET  /incidents/{id}/response-actions               list them
    POST /incidents/{id}/response-actions/{ref}/approve sign one off
    POST /incidents/{id}/response-actions/{ref}/reject  refuse one

**There is no execute route, and that is the design.** V9 records that a second
authorised person agreed to a containment action and what evidence they agreed
on. Carrying the action out needs a provider interface, an execution record and
a result, none of which exist; adding an endpoint that pretended to would be
the most dangerous thing in this file.

The pre-existing ``POST /incidents/{id}/response`` is untouched. It records a
free-text note by one analyst and executes nothing, with no approval in it at
all. Binding evidence to it would have dressed a single-party note in the
machinery of a governed approval - which is worse than leaving it visibly
weak, so it stays visibly weak and these routes carry the real thing.

Authorization is doubled deliberately. The FastAPI dependency stops the wrong
role at the edge, and ``app.response.approval`` re-checks the same permission
in the domain layer, because the API is one caller.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from app.api.deps import client_ip, require
from app.core.database import get_db
from app.core.rbac import Permission
from app.models.enums import AuditAction
from app.models.user import User
from app.schemas.common import Message
from app.schemas.response_action import (
    ResponseActionApprove,
    ResponseActionCreate,
    ResponseActionList,
    ResponseActionRead,
    ResponseActionReject,
)
from app.services import (
    audit_service,
    decision_service,
    incident_service,
    response_action_service,
)

router = APIRouter(prefix="/incidents", tags=["response-actions"])

#: How each domain refusal reaches the caller. The distinctions matter: a
#: refused approval tells somebody to get an authority, find a second person,
#: reload the evidence, or raise a fresh request - four different next actions.
_APPROVAL_STATUS: dict[type[Exception], int] = {
    response_action_service.approval.NotDecidable: status.HTTP_409_CONFLICT,
    response_action_service.approval.SelfApprovalRefused: status.HTTP_403_FORBIDDEN,
    response_action_service.approval.UnauthorizedApproval: status.HTTP_403_FORBIDDEN,
    response_action_service.approval.ParametersChanged: status.HTTP_409_CONFLICT,
    response_action_service.approval.FreshnessRequired: status.HTTP_400_BAD_REQUEST,
    response_action_service.approval.ApprovalError: status.HTTP_400_BAD_REQUEST,
}


def _incident_or_404(db: Session, incident_id: str):
    incident = incident_service.get_incident(db, incident_id)
    if incident is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Incident not found")
    return incident


def _request_or_404(db: Session, incident, request_ref: str):
    record = response_action_service.get_for_incident(db, incident, request_ref)
    if record is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Response action not found"
        )
    return record


def _render(db: Session, record) -> dict:
    decision_ref = None
    if record.evidence_binding_id is not None and record.evidence_binding is not None:
        decision_ref = record.evidence_binding.decision_ref
    return {
        "requestRef": record.request_ref,
        "incidentRef": record.incident_ref,
        "actionType": record.action_type,
        "parameters": dict(record.parameters or {}),
        "parametersDigest": record.parameters_digest,
        "justification": record.justification,
        "status": record.status,
        "requestedBy": record.requested_by,
        "requestedByRole": record.requested_by_role,
        "requestedAt": record.requested_at,
        "decidedBy": record.decided_by,
        "decidedByRole": record.decided_by_role,
        "decidedAt": record.decided_at,
        "decisionReason": record.decision_reason,
        "decisionRef": decision_ref,
    }


@router.post(
    "/{incident_id}/response-actions",
    response_model=ResponseActionRead,
    status_code=status.HTTP_201_CREATED,
    summary="Request a containment action",
    description=(
        "Raises a request. Nothing happens as a result: the action is not carried out, "
        "and the incident's status does not move. A second, authorised person must "
        "approve it, and containment itself remains a lifecycle transition."
    ),
    responses={404: {"model": Message, "description": "Unknown incident"}},
)
def request_response_action(
    incident_id: str,
    payload: ResponseActionCreate,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(require(Permission.INCIDENTS_RESPOND)),
) -> ResponseActionRead:
    incident = _incident_or_404(db, incident_id)
    try:
        record = response_action_service.request_action(
            db,
            incident,
            action_type=payload.action_type,
            parameters=payload.parameters,
            justification=payload.justification,
            requested_by=user.email,
            requested_by_role=user.role,
        )
    except response_action_service.ResponseActionError as exc:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc

    audit_service.record(
        db,
        action=AuditAction.RESPONSE_ACTION_REQUESTED,
        user=user,
        target_type="response_action",
        target_id=record.request_ref,
        ip_address=client_ip(request),
        details={
            "incidentId": incident.incident_id,
            "actionType": record.action_type,
            "parametersDigest": record.parameters_digest,
        },
    )
    db.commit()
    return ResponseActionRead.model_validate(_render(db, record))


@router.get(
    "/{incident_id}/response-actions",
    response_model=ResponseActionList,
    summary="Response actions requested on this incident",
    responses={404: {"model": Message, "description": "Unknown incident"}},
)
def list_response_actions(
    incident_id: str,
    db: Session = Depends(get_db),
    _: User = Depends(require(Permission.INCIDENTS_READ)),
) -> ResponseActionList:
    incident = _incident_or_404(db, incident_id)
    records = response_action_service.list_for_incident(db, incident)
    items = [_render(db, record) for record in records]
    return ResponseActionList.model_validate(
        {
            "incidentId": incident.incident_id,
            "total": len(items),
            "pending": sum(1 for record in records if record.is_pending),
            "items": items,
        }
    )


@router.post(
    "/{incident_id}/response-actions/{request_ref}/approve",
    response_model=ResponseActionRead,
    summary="Approve a containment action",
    description=(
        "Administrator only, and never the person who raised it. `expectedEvidenceDigest` "
        "is required: an approval must state the evidence manifest it was given, and is "
        "refused with 409 if that evidence has moved since. Approving records the "
        "decision and binds it to the evidence; **it does not execute anything**."
    ),
    responses={
        400: {"model": Message, "description": "No evidence digest stated"},
        403: {"model": Message, "description": "Self-approval, or lacking authority"},
        404: {"model": Message, "description": "Unknown incident or request"},
        409: {"model": Message, "description": "Already decided, parameters changed, or evidence moved"},
    },
)
def approve_response_action(
    incident_id: str,
    request_ref: str,
    payload: ResponseActionApprove,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(require(Permission.INCIDENTS_RESPOND_APPROVE)),
) -> ResponseActionRead:
    incident = _incident_or_404(db, incident_id)
    record = _request_or_404(db, incident, request_ref)

    try:
        response_action_service.approve_action(
            db,
            incident,
            record,
            approver=user.email,
            approver_role=user.role,
            expected_evidence_digest=payload.expected_evidence_digest,
            reason=payload.reason,
        )
    except (
        response_action_service.approval.ApprovalError,
        decision_service.EvidenceDriftError,
    ) as exc:
        db.rollback()
        # A refused approval is worth seeing even though nothing changed: an
        # attempt to sign off a containment action against stale evidence, or
        # by the person who asked for it, is exactly the event a reviewer wants.
        audit_service.record(
            db,
            action=AuditAction.RESPONSE_ACTION_REFUSED,
            user=user,
            target_type="response_action",
            target_id=request_ref,
            ip_address=client_ip(request),
            details={
                "incidentId": incident_id,
                "refusal": type(exc).__name__,
                "reviewedDigest": (payload.expected_evidence_digest or "")[:64],
            },
        )
        db.commit()
        code = (
            status.HTTP_409_CONFLICT
            if isinstance(exc, decision_service.EvidenceDriftError)
            else _APPROVAL_STATUS[type(exc)]
        )
        raise HTTPException(status_code=code, detail=str(exc)) from exc

    audit_service.record(
        db,
        action=AuditAction.RESPONSE_ACTION_APPROVED,
        user=user,
        target_type="response_action",
        target_id=record.request_ref,
        ip_address=client_ip(request),
        details={
            "incidentId": incident.incident_id,
            "actionType": record.action_type,
            "requestedBy": record.requested_by,
            "decisionRef": (
                record.evidence_binding.decision_ref if record.evidence_binding else None
            ),
            "executed": False,
        },
    )
    db.commit()
    return ResponseActionRead.model_validate(_render(db, record))


@router.post(
    "/{incident_id}/response-actions/{request_ref}/reject",
    response_model=ResponseActionRead,
    summary="Refuse a containment action",
    description=(
        "Administrator only. Needs a reason and does not need an evidence digest - "
        "refusing is the fail-safe direction, and blocking a rejection because the "
        "evidence moved would trap the request as pending. The evidence is still "
        "recorded: what was known when containment was refused is worth answering later."
    ),
    responses={
        403: {"model": Message, "description": "Lacking authority"},
        404: {"model": Message, "description": "Unknown incident or request"},
        409: {"model": Message, "description": "Already decided"},
    },
)
def reject_response_action(
    incident_id: str,
    request_ref: str,
    payload: ResponseActionReject,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(require(Permission.INCIDENTS_RESPOND_APPROVE)),
) -> ResponseActionRead:
    incident = _incident_or_404(db, incident_id)
    record = _request_or_404(db, incident, request_ref)

    try:
        response_action_service.reject_action(
            db,
            incident,
            record,
            approver=user.email,
            approver_role=user.role,
            reason=payload.reason,
        )
    except response_action_service.approval.ApprovalError as exc:
        db.rollback()
        raise HTTPException(
            status_code=_APPROVAL_STATUS[type(exc)], detail=str(exc)
        ) from exc

    audit_service.record(
        db,
        action=AuditAction.RESPONSE_ACTION_REJECTED,
        user=user,
        target_type="response_action",
        target_id=record.request_ref,
        ip_address=client_ip(request),
        details={
            "incidentId": incident.incident_id,
            "actionType": record.action_type,
            "reason": record.decision_reason,
        },
    )
    db.commit()
    return ResponseActionRead.model_validate(_render(db, record))
