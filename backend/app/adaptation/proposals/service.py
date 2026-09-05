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

**V7 made four-eyes real.** Until then `approve` recorded `self_approved` when
the approver was the proposer and continued anyway, so separation of duties was
a column rather than a rule. It now refuses, and the acting role is checked
against the permission matrix here rather than only in the FastAPI dependency -
the API is one caller, and a boundary enforced only at the HTTP edge is not a
boundary for any other.
"""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.adaptation import AdaptationProposal
from app.models.enums import MLModelStatus, ProposalStatus, ProposalType


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
    proposed_by_role: str | None = None,
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
        proposed_by_role=proposed_by_role,
    )
    db.add(proposal)
    db.flush()
    return proposal


def _sync_candidate_status(
    db: Session, proposal: AdaptationProposal, decision: ProposalStatus
) -> None:
    """Move a model proposal's candidate in step with the decision.

    Only for model updates, and only for the two decisions that have a model
    meaning. A threshold proposal has no candidate, and inventing a status
    transition for one would be a lie about what was decided.
    """
    if proposal.proposal_type != ProposalType.MODEL_UPDATE.value:
        return
    if proposal.candidate_model_id is None:
        return

    from app.models.ml import MLModel

    candidate = db.get(MLModel, proposal.candidate_model_id)
    if candidate is None:
        return

    if decision is ProposalStatus.APPROVED:
        candidate.status = MLModelStatus.APPROVED.value
    elif decision is ProposalStatus.REJECTED:
        candidate.status = MLModelStatus.REJECTED.value


def _require(db: Session, proposal_id: int) -> AdaptationProposal:
    proposal = db.get(AdaptationProposal, proposal_id)
    if proposal is None:
        raise ValueError(f"No adaptation proposal with id {proposal_id}")
    return proposal


# Actors that may never approve. The AI drafts proposals; letting it also
# approve one would make "human approval" a string the machine can write.
#
# **V9 fixed a real gap here.** This module compared the raw string against the
# prefixes while `_same_actor` two lines below folded case, so `AI:analyst`
# passed the non-human check and `ai:analyst` did not. Both now use the one
# definition in `app.core.actors`, which folds first.
from app.core import actors  # noqa: E402 - kept beside the note that explains it

is_human_actor = actors.is_human_actor
_same_actor = actors.same_actor


def _require_approver_authority(role: str | None) -> None:
    """Check the acting role actually grants approval.

    Enforced here rather than only at the HTTP edge. The API is one caller; an
    experiment harness, a CLI, and eventually an agent are others, and a
    security boundary that lives in a FastAPI dependency is a boundary only for
    traffic that happens to arrive over HTTP. The permission matrix is reused
    rather than restated so the two cannot drift apart.
    """
    from app.core.rbac import Permission, has_permission

    if not role:
        raise ValueError(
            "An approval must state the role it was made under. Recording a "
            "decision whose authority cannot be checked defeats the point of "
            "recording who made it."
        )
    if not has_permission(role, Permission.ADAPTATION_APPROVE):
        raise ValueError(
            f"Role {role!r} does not hold {Permission.ADAPTATION_APPROVE.value} "
            "and cannot approve an adaptation."
        )


def approve(
    db: Session, proposal_id: int, *, approved_by: str, approver_role: str
) -> AdaptationProposal:
    """Sign off a pending proposal. Does not deploy it.

    **Four-eyes is enforced here as of V7.** Through V6 this function set a
    ``self_approved`` flag when the approver was the proposer and then carried
    on, so separation of duties was a label on the row rather than a property of
    the system. It now refuses. Because production detection state is reachable
    only through ``mark_deployed`` on an approved proposal, refusing here is
    what makes the separation real rather than advisory.

    ``approver_role`` is required and not inferred: an approval whose authority
    cannot be stated is not an approval.
    """
    if not actors.is_human_actor(approved_by):
        raise ValueError(
            f"{approved_by!r} is not a human actor and cannot approve an "
            "adaptation. AI may draft a proposal; only a person may accept one."
        )

    _require_approver_authority(approver_role)

    proposal = _require(db, proposal_id)

    if _same_actor(approved_by, proposal.proposed_by):
        raise ValueError(
            f"{approved_by!r} raised proposal {proposal_id} and cannot also "
            "approve it. A change to what AEGISX detects needs a second person; "
            "one actor doing both is not review, it is paperwork. Have another "
            "authorised approver sign this off."
        )

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
    proposal.approved_by_role = approver_role
    proposal.approved_at = _now()
    # Always False from V7 onwards - the self-approval branch above returns
    # before reaching here. Set explicitly rather than left to the column
    # default so the row states the guarantee instead of merely defaulting into
    # it. Rows written before V7 keep whatever they recorded.
    proposal.self_approved = False

    # Approving a model proposal is the only route out of `candidate`. Without
    # it the deployment step would have to bypass the lifecycle gate to do its
    # job, which would make the gate decorative.
    _sync_candidate_status(db, proposal, ProposalStatus.APPROVED)

    db.flush()
    return proposal


def reject(
    db: Session,
    proposal_id: int,
    *,
    rejected_by: str,
    reason: str,
    rejector_role: str | None = None,
) -> AdaptationProposal:
    """Refuse a proposal, with a reason and a time that are both kept.

    A proposer *may* reject their own proposal - withdrawing something you
    raised needs no second pair of eyes, because the outcome is that production
    does not change. The asymmetry with ``approve`` is deliberate: four-eyes
    guards the direction of travel that alters what AEGISX detects.

    ``rejector_role`` is optional for the same reason. It is recorded when the
    caller knows it, and no authority check gates a refusal.
    """
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
    proposal.rejected_by_role = rejector_role
    proposal.rejection_reason = reason
    proposal.rejected_at = _now()
    _sync_candidate_status(db, proposal, ProposalStatus.REJECTED)
    db.flush()
    return proposal


def mark_deployed(
    db: Session,
    proposal_id: int,
    *,
    deployed_by: str,
    rollback_state: dict | None = None,
) -> AdaptationProposal:
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
    # The caller may supply a more precise target than the recorded
    # before-state - a model deployment knows exactly which version it
    # displaced, which is not always what the proposal was written against.
    proposal.rollback_state = (
        dict(rollback_state) if rollback_state is not None else dict(proposal.before_state or {})
    )
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
