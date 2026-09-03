"""The adaptation approval workflow.

Every state transition lives here, and each one refuses more than it permits.
That asymmetry is deliberate: the cost of wrongly refusing a good adaptation is
an analyst re-raising it, and the cost of wrongly permitting a bad one is a
detection engine that silently stopped working.

    pending -> approved -> deployed -> rolled_back
            -> rejected

There is no transition a machine may take on a proposal's behalf. Approval,
deployment and rollback all require a named actor passed in by the caller, and
the API layer supplies it from the authenticated user rather than from anything
the request body says.
"""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.adaptation import AdaptationProposal
from app.models.enums import ProposalStatus, ProposalType


def _now() -> datetime:
    return datetime.now(timezone.utc)


def create(
    db: Session,
    *,
    proposal_type: ProposalType,
    title: str,
    reason: str,
    affected_component: str,
    before_state: dict,
    after_state: dict,
    evidence: dict,
    proposed_by: str,
    validation: dict | None = None,
    expected_impact: dict | None = None,
    risk_assessment: str | None = None,
    candidate_model_id: int | None = None,
    feedback_dataset_id: int | None = None,
) -> AdaptationProposal:
    """Raise a proposal. Creating one changes nothing in production."""
    if not evidence:
        raise ValueError(
            "A proposal must carry evidence. Without it this is an opinion "
            "about what the platform should detect, and an approver has nothing "
            "to weigh."
        )
    if before_state == after_state:
        raise ValueError(
            "before_state and after_state are identical; this proposal changes "
            "nothing. An approval trail for a no-op is noise that makes the real "
            "changes harder to find."
        )

    proposal = AdaptationProposal(
        proposal_type=ProposalType(proposal_type).value,
        status=ProposalStatus.PENDING.value,
        title=title,
        reason=reason,
        affected_component=affected_component,
        before_state=before_state,
        after_state=after_state,
        evidence=evidence,
        validation=validation or {},
        expected_impact=expected_impact or {},
        risk_assessment=risk_assessment,
        candidate_model_id=candidate_model_id,
        feedback_dataset_id=feedback_dataset_id,
        proposed_by=proposed_by,
    )
    db.add(proposal)
    db.flush()
    return proposal


def _require(db: Session, proposal_id: int) -> AdaptationProposal:
    proposal = db.get(AdaptationProposal, proposal_id)
    if proposal is None:
        raise ValueError(f"No adaptation proposal with id {proposal_id}")
    return proposal


def approve(db: Session, proposal_id: int, *, approved_by: str) -> AdaptationProposal:
    """Sign off a pending proposal. Does not deploy it."""
    proposal = _require(db, proposal_id)

    if proposal.status == ProposalStatus.REJECTED.value:
        raise ValueError(
            f"Proposal {proposal_id} was rejected and cannot be approved. Raise a "
            "new proposal rather than reversing a recorded refusal."
        )
    if proposal.status != ProposalStatus.PENDING.value:
        raise ValueError(
            f"Proposal {proposal_id} is {proposal.status}, not pending; only a "
            "pending proposal can be approved."
        )

    gates = (proposal.validation or {}).get("gates")
    if gates is not None and gates.get("passed") is False:
        failures = ", ".join(gates.get("failures", [])) or "unspecified"
        raise ValueError(
            f"Proposal {proposal_id} failed its safety gates ({failures}) and "
            "cannot be approved. Approving past a failed gate would make the "
            "evaluation ceremonial."
        )

    proposal.status = ProposalStatus.APPROVED.value
    proposal.approved_by = approved_by
    proposal.approved_at = _now()
    # Recorded, not blocked. The three-role model allows an administrator to
    # propose and approve; surfacing it is more honest than pretending the
    # separation exists.
    proposal.self_approved = approved_by == proposal.proposed_by
    db.flush()
    return proposal


def reject(db: Session, proposal_id: int, *, rejected_by: str, reason: str) -> AdaptationProposal:
    """Refuse a proposal, with a reason that is kept."""
    if not (reason or "").strip():
        raise ValueError(
            "A rejection needs a reason. A refused proposal without one tells the "
            "next person nothing except that someone said no."
        )

    proposal = _require(db, proposal_id)
    if proposal.status not in {ProposalStatus.PENDING.value, ProposalStatus.APPROVED.value}:
        raise ValueError(
            f"Proposal {proposal_id} is {proposal.status} and can no longer be rejected."
        )

    proposal.status = ProposalStatus.REJECTED.value
    proposal.rejected_by = rejected_by
    proposal.rejection_reason = reason
    db.flush()
    return proposal


def mark_deployed(db: Session, proposal_id: int, *, deployed_by: str) -> AdaptationProposal:
    """Record that an approved proposal has been applied to production.

    Captures ``rollback_state`` from the recorded before-state at this moment,
    rather than leaving it to be reconstructed later. Reconstructing "what was it
    before" from the current configuration is precisely the operation that fails
    when it is needed most.
    """
    proposal = _require(db, proposal_id)
    if proposal.status != ProposalStatus.APPROVED.value:
        raise ValueError(
            f"Proposal {proposal_id} is {proposal.status}; only an approved "
            "proposal may be deployed. Approval is a separate, human act."
        )

    proposal.status = ProposalStatus.DEPLOYED.value
    proposal.deployed_by = deployed_by
    proposal.deployed_at = _now()
    proposal.rollback_state = dict(proposal.before_state or {})
    db.flush()
    return proposal


def mark_rolled_back(
    db: Session, proposal_id: int, *, rolled_back_by: str, reason: str
) -> AdaptationProposal:
    """Record that a deployed proposal has been withdrawn."""
    proposal = _require(db, proposal_id)
    if proposal.status != ProposalStatus.DEPLOYED.value:
        raise ValueError(
            f"Proposal {proposal_id} is {proposal.status}; only a deployed "
            "proposal can be rolled back."
        )

    proposal.status = ProposalStatus.ROLLED_BACK.value
    proposal.rolled_back_by = rolled_back_by
    proposal.rollback_reason = reason
    proposal.rolled_back_at = _now()
    db.flush()
    return proposal


def get(db: Session, proposal_id: int) -> AdaptationProposal | None:
    return db.get(AdaptationProposal, proposal_id)


def list_proposals(
    db: Session,
    *,
    status: ProposalStatus | None = None,
    proposal_type: ProposalType | None = None,
    limit: int = 100,
) -> list[AdaptationProposal]:
    """Newest first."""
    statement = select(AdaptationProposal)
    if status is not None:
        statement = statement.where(AdaptationProposal.status == ProposalStatus(status).value)
    if proposal_type is not None:
        statement = statement.where(
            AdaptationProposal.proposal_type == ProposalType(proposal_type).value
        )
    statement = statement.order_by(
        AdaptationProposal.created_at.desc(), AdaptationProposal.id.desc()
    )
    return list(db.scalars(statement.limit(limit)))
