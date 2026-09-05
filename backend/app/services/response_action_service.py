"""Requesting a containment action, and deciding on one.

Three operations and no fourth: ``request``, ``approve``, ``reject``. There is
no ``execute`` and no provider call anywhere in this module - V9 stops at the
decision, and a test asserts it.

Approval reuses Phase D wholesale rather than growing a second
evidence-integrity mechanism: the same ``snapshot_for``, the same
``check_expected_digest``, the same ``bind`` writing the same
``DecisionEvidenceBinding`` table, so an approved containment action appears in
``GET /incidents/{id}/decisions`` beside the lifecycle transition it justifies,
with drift classified by the same ``classify_drift``.

The authorization checks live in ``app.response.approval``, which is pure and
knows nothing about HTTP. Everything here does is fetch the row, compute the
snapshot server-side, ask that module whether the decision may be recorded, and
write the result. A caller that bypasses the API gets the same refusals.
"""

from __future__ import annotations

import logging
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models.response_action import ResponseActionRequest
from app.response import approval
from app.response.actions import (
    ResponseActionStatus,
    ResponseActionType,
    parameters_digest,
)
from app.services import decision_service

logger = logging.getLogger(__name__)

#: The ``decision_type`` an approved response action is bound under. Distinct
#: from a lifecycle change so a reader can tell a containment approval from a
#: status transition, and so is the rejection - a refusal is a result.
RESPONSE_ACTION_APPROVAL = "response_action.approval"
RESPONSE_ACTION_REJECTION = "response_action.rejection"


class ResponseActionError(ValueError):
    """The request itself is malformed or cannot be raised."""


def _next_reference(db: Session, incident: Any) -> str:
    taken = (
        db.execute(
            select(func.count(ResponseActionRequest.id)).where(
                ResponseActionRequest.incident_id == incident.id
            )
        ).scalar()
        or 0
    )
    return f"RAR-{incident.incident_id}-{taken + 1:04d}"


def request_action(
    db: Session,
    incident: Any,
    *,
    action_type: ResponseActionType | str,
    parameters: dict[str, Any] | None,
    justification: str,
    requested_by: str,
    requested_by_role: str | None,
) -> ResponseActionRequest:
    """Raise a request. Raising one changes nothing and does nothing.

    A machine may reach this - a detection or an assistant proposing
    containment is a legitimate and useful thing. What it may not do is decide,
    and ``approval.check_authority`` is where that is enforced.
    """
    if not (justification or "").strip():
        raise ResponseActionError(
            "A response action request needs a justification. Without one an "
            "approver has nothing to weigh, and the record says only that "
            "somebody wanted it."
        )
    try:
        parsed_type = ResponseActionType(action_type)
    except ValueError as exc:
        known = ", ".join(item.value for item in ResponseActionType)
        raise ResponseActionError(
            f"{action_type!r} is not a known response action. Known: {known}."
        ) from exc

    parameters = dict(parameters or {})
    record = ResponseActionRequest(
        request_ref=_next_reference(db, incident),
        incident_id=incident.id,
        incident_ref=incident.incident_id,
        action_type=parsed_type.value,
        parameters=parameters,
        parameters_digest=parameters_digest(parameters),
        justification=justification.strip(),
        status=ResponseActionStatus.REQUESTED.value,
        requested_by=requested_by,
        requested_by_role=requested_by_role,
    )
    db.add(record)
    db.flush()
    return record


def list_for_incident(db: Session, incident: Any) -> list[ResponseActionRequest]:
    return list(
        db.execute(
            select(ResponseActionRequest)
            .where(ResponseActionRequest.incident_id == incident.id)
            .order_by(ResponseActionRequest.requested_at.desc())
        ).scalars()
    )


def get_for_incident(
    db: Session, incident: Any, request_ref: str
) -> ResponseActionRequest | None:
    """One request, **scoped to this incident**.

    Same discipline as the evidence and decision endpoints: a reference
    belonging to another incident resolves to nothing rather than to somebody
    else's pending containment action.
    """
    return db.execute(
        select(ResponseActionRequest).where(
            ResponseActionRequest.incident_id == incident.id,
            ResponseActionRequest.request_ref == request_ref,
        )
    ).scalar_one_or_none()


def approve_action(
    db: Session,
    incident: Any,
    record: ResponseActionRequest,
    *,
    approver: str,
    approver_role: str | None,
    expected_evidence_digest: str | None,
    reason: str | None = None,
) -> ResponseActionRequest:
    """Sign off a request, binding it to the evidence the approver was shown.

    Every check runs **before** anything is written, so a refusal leaves the
    request pending, the incident untouched and no binding created - without
    depending on the caller to roll back. The API rolls back anyway; a service
    that is only safe when its caller remembers to clean up is not safe.
    """
    # One collection, used for both the freshness check and the stored binding.
    # Collecting twice would leave a window in which the evidence changes
    # between them, and the binding would describe evidence the approval was
    # never actually checked against.
    snapshot = decision_service.snapshot_for(db, incident)

    approval.check_approval(
        requested_by=record.requested_by,
        approver=approver,
        approver_role=approver_role,
        status=record.status,
        recorded_parameters_digest=record.parameters_digest,
        current_parameters_digest=parameters_digest(record.parameters),
        expected_evidence_digest=expected_evidence_digest,
    )
    # Raises EvidenceDriftError, which the router maps to 409. Deliberately
    # after the approval checks: telling somebody the evidence moved when they
    # were never allowed to approve is the wrong thing to send them off to fix.
    decision_service.check_expected_digest(snapshot, expected_evidence_digest)

    binding = decision_service.bind(
        db,
        incident,
        snapshot=snapshot,
        from_state=ResponseActionStatus.REQUESTED.value,
        to_state=ResponseActionStatus.APPROVED.value,
        reason=(reason or record.justification),
        decided_by=approver,
        decided_by_role=approver_role,
        decision_type=RESPONSE_ACTION_APPROVAL,
    )

    record.status = ResponseActionStatus.APPROVED.value
    record.decided_by = approver
    record.decided_by_role = approver_role
    record.decided_at = binding.decided_at
    record.decision_reason = (reason or "").strip() or None
    record.evidence_binding_id = binding.id
    db.flush()
    return record


def reject_action(
    db: Session,
    incident: Any,
    record: ResponseActionRequest,
    *,
    approver: str,
    approver_role: str | None,
    reason: str,
) -> ResponseActionRequest:
    """Refuse a request, with a reason, and record what was known at the time.

    No four-eyes and no freshness requirement - see ``approval.check_rejection``
    for why. The evidence is still bound, because "what did we know when we
    decided not to contain this" is exactly as worth answering later as the
    approving case, and V5 established that a refusal is a result.
    """
    approval.check_rejection(
        requested_by=record.requested_by,
        approver=approver,
        approver_role=approver_role,
        status=record.status,
        reason=reason,
    )

    snapshot = decision_service.snapshot_for(db, incident)
    binding = decision_service.bind(
        db,
        incident,
        snapshot=snapshot,
        from_state=ResponseActionStatus.REQUESTED.value,
        to_state=ResponseActionStatus.REJECTED.value,
        reason=reason.strip(),
        decided_by=approver,
        decided_by_role=approver_role,
        decision_type=RESPONSE_ACTION_REJECTION,
    )

    record.status = ResponseActionStatus.REJECTED.value
    record.decided_by = approver
    record.decided_by_role = approver_role
    record.decided_at = binding.decided_at
    record.decision_reason = reason.strip()
    record.evidence_binding_id = binding.id
    db.flush()
    return record
