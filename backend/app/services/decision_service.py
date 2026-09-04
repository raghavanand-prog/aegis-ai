"""Binding a decision to its evidence, and verifying it afterwards.

Two operations and no third:

``bind``    called from inside the transition, in the same transaction as the
            decision. A decision whose binding did not write does not exist.
``verify``  recompute the evidence now, compare it with what was recorded, and
            classify the difference.

There is deliberately **no update and no delete**. An analyst cannot revise
what a past decision rested on because no function here would do it and no
endpoint reaches one - the same argument Phase C made for evidence itself, and
it is stronger than any check because there is nothing to bypass.

Which decisions are bound is not a new policy. It is the set the lifecycle
already treats as consequential: anything that contains, anything that closes,
and every edge that must carry a reason - which is exactly the set that ends or
undoes recorded work. Routine forward progress (``Open -> Triaged``) is not
bound, because it concludes nothing and binding it would put a seven-provider
evidence collection on the write path of every ordinary PATCH.
"""

from __future__ import annotations

import logging
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.evidence import service as evidence_service
from app.evidence.binding import DriftReport, EvidenceSnapshot, classify_drift
from app.incidents import lifecycle
from app.models.decision import DecisionEvidenceBinding
from app.models.enums import IncidentStatus

logger = logging.getLogger(__name__)

#: What ``decision_type`` a lifecycle transition is recorded under. Later
#: phases add their own; this one is the only producer today.
INCIDENT_STATUS_CHANGE = "incident.status_change"


class EvidenceDriftError(Exception):
    """The caller stated which evidence it was acting on, and it has moved.

    Raised only when a caller supplied ``expected_evidence_digest``. It is the
    "before" half of the protection: it stops a decision being taken against a
    view of the evidence that was rendered minutes ago and has since changed,
    which is precisely the window in which an approver reads a page, thinks,
    and clicks.
    """


def is_consequential(current: str, target: IncidentStatus) -> bool:
    """Whether this transition is one worth binding evidence to.

    Reuses the lifecycle's own notion rather than inventing a second one: a
    transition is consequential when it contains, when it closes, or when the
    lifecycle already demands a reason for it.
    """
    if target is IncidentStatus.CLOSED:
        return True
    if target in lifecycle._CONTAINMENT_TARGETS:  # noqa: SLF001 - same package concept
        return True
    try:
        return lifecycle.requires_reason(current, target)
    except lifecycle.InvalidTransition:
        # An illegal edge is refused before it reaches here; if one somehow
        # does, treat it as consequential rather than silently unbound.
        return True


def snapshot_for(db: Session, incident: Any) -> EvidenceSnapshot:
    """The current evidence for an incident, as a snapshot.

    One collection, used both for the expected-digest check and for the stored
    binding. Collecting twice would open a window in which evidence changes
    between the check and the record, and the record would then describe
    evidence the decision was never checked against.
    """
    evidence = evidence_service.collect_for_incident(db, incident)
    return EvidenceSnapshot.from_items(
        evidence.items, degraded=[dict(entry) for entry in evidence.degraded]
    )


def check_expected_digest(snapshot: EvidenceSnapshot, expected: str | None) -> None:
    """Refuse the decision if the evidence is not what the caller expected.

    Opt-in, and that is a real weakening worth stating plainly: a client that
    sends nothing keeps the old behaviour and gets no protection. It is opt-in
    because making it mandatory would break every existing caller, and a
    mandatory field that clients fill in with whatever the server last said
    protects nobody anyway.
    """
    if expected is None:
        return
    stated = expected.strip()
    if not stated:
        return
    if stated != snapshot.manifest_digest:
        raise EvidenceDriftError(
            "The evidence for this incident has changed since it was last "
            "loaded, so this decision would be taken against something other "
            "than what was reviewed. Reload the evidence and decide again. "
            f"(reviewed {stated[:16]}…, current {snapshot.manifest_digest[:16]}…)"
        )


def _next_reference(db: Session, incident: Any) -> str:
    """``DEC-INC-1024-0003``. Readable, and stable once written."""
    taken = (
        db.execute(
            select(func.count(DecisionEvidenceBinding.id)).where(
                DecisionEvidenceBinding.incident_id == incident.id
            )
        ).scalar()
        or 0
    )
    return f"DEC-{incident.incident_id}-{taken + 1:04d}"


def bind(
    db: Session,
    incident: Any,
    *,
    snapshot: EvidenceSnapshot,
    from_state: str | None,
    to_state: str,
    reason: str | None,
    decided_by: str,
    decided_by_role: str | None,
    decision_type: str = INCIDENT_STATUS_CHANGE,
) -> DecisionEvidenceBinding:
    """Record what this decision was taken on.

    Called inside the caller's transaction so the binding and the decision
    commit or fail together.
    """
    binding = DecisionEvidenceBinding(
        decision_ref=_next_reference(db, incident),
        decision_type=decision_type,
        incident_id=incident.id,
        incident_ref=incident.incident_id,
        from_state=from_state,
        to_state=to_state,
        reason=reason,
        decided_by=decided_by,
        decided_by_role=decided_by_role,
        manifest_digest=snapshot.manifest_digest,
        evidence_snapshot=snapshot.to_dict(),
        evidence_count=snapshot.entry_count,
    )
    db.add(binding)
    db.flush()
    return binding


def list_for_incident(db: Session, incident: Any) -> list[DecisionEvidenceBinding]:
    """Every recorded decision for one incident, newest first."""
    return list(
        db.execute(
            select(DecisionEvidenceBinding)
            .where(DecisionEvidenceBinding.incident_id == incident.id)
            .order_by(DecisionEvidenceBinding.decided_at.desc())
        ).scalars()
    )


def get_for_incident(
    db: Session, incident: Any, decision_ref: str
) -> DecisionEvidenceBinding | None:
    """One binding, **scoped to this incident**.

    Same discipline as the evidence endpoint: a reference belonging to another
    incident resolves to nothing rather than to somebody else's decision.
    """
    return db.execute(
        select(DecisionEvidenceBinding).where(
            DecisionEvidenceBinding.incident_id == incident.id,
            DecisionEvidenceBinding.decision_ref == decision_ref,
        )
    ).scalar_one_or_none()


def verify(
    db: Session, incident: Any, binding: DecisionEvidenceBinding
) -> DriftReport:
    """Has the evidence behind this decision moved since it was taken?"""
    recorded = EvidenceSnapshot.from_dict(binding.evidence_snapshot or {})
    return classify_drift(recorded, snapshot_for(db, incident))
