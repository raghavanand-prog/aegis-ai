"""Deploying an approved proposal, and undoing it.

The ordering in ``deploy`` is the safety property. Everything that can fail is
checked *before* anything is changed, so a refusal leaves the incumbent serving
exactly as it was. §52: if adaptation fails, the current approved model remains
active.

Rollback restores the model recorded at deployment time rather than "the
previous row by timestamp". Those are the same thing right up until two
deployments happen close together, which is precisely when a rollback is most
likely to be needed.
"""

from __future__ import annotations

import logging
from pathlib import Path

from sqlalchemy.orm import Session

from app.adaptation.proposals import service as proposals
from app.ml.registry import registry
from app.models.adaptation import AdaptationProposal
from app.models.enums import MLModelStatus, ProposalStatus, ProposalType
from app.models.ml import MLModel

logger = logging.getLogger("aegisx.adaptation.deployment")


def _verified_candidate(db: Session, proposal: AdaptationProposal) -> MLModel:
    """The proposal's candidate, checked before anything is changed."""
    if proposal.candidate_model_id is None:
        raise ValueError(
            f"Proposal {proposal.id} is a model update but names no candidate model."
        )
    candidate = db.get(MLModel, proposal.candidate_model_id)
    if candidate is None:
        raise ValueError(f"Candidate model {proposal.candidate_model_id} no longer exists.")

    if not registry.verify_artifact(
        Path(candidate.artifact_path), expected_sha256=candidate.artifact_sha256
    ):
        raise ValueError(
            f"Artifact digest mismatch for {candidate.identity}: the file has "
            "changed since registration. Refusing to deploy a model that is not "
            "the one that was evaluated and approved. The current model keeps "
            "serving."
        )
    return candidate


def deploy(db: Session, proposal_id: int, *, deployed_by: str) -> AdaptationProposal:
    """Apply an approved proposal to production.

    Validation happens first and mutation second, deliberately: a failure part
    way through must not leave production in a state nobody chose.
    """
    proposal = proposals.get(db, proposal_id)
    if proposal is None:
        raise ValueError(f"No adaptation proposal with id {proposal_id}")
    if proposal.status != ProposalStatus.APPROVED.value:
        raise ValueError(
            f"Proposal {proposal_id} is {proposal.status}; only an approved "
            "proposal may be deployed."
        )

    if proposal.proposal_type == ProposalType.MODEL_UPDATE.value:
        # Checked before any state changes.
        candidate = _verified_candidate(db, proposal)
        previous = registry.get_active(db, candidate.name)

        # Captured before anything changes, so the rollback target is the model
        # that was actually displaced rather than one inferred afterwards.
        rollback_target = {
            "identity": previous.identity if previous else None,
            "modelId": previous.id if previous else None,
        }
        registry.activate_model(db, candidate)
    else:
        # Threshold, feature-configuration and recommendation proposals record
        # an approved decision; applying them is a configuration or engineering
        # act outside this service. The proposal is the durable record either
        # way, and pretending otherwise would claim an effect that is not there.
        rollback_target = dict(proposal.before_state or {})
        logger.info(
            "Adaptation proposal marked deployed without an automated change",
            extra={
                "proposal": proposal.id,
                "type": proposal.proposal_type,
                "operation": "adaptation.deploy",
            },
        )

    deployed = proposals.mark_deployed(
        db, proposal_id, deployed_by=deployed_by, rollback_state=rollback_target
    )
    db.flush()

    logger.info(
        "Adaptation deployed",
        extra={
            "proposal": deployed.id,
            "type": deployed.proposal_type,
            "by": deployed_by,
            "operation": "adaptation.deploy",
        },
    )
    return deployed


def rollback(
    db: Session, proposal_id: int, *, rolled_back_by: str, reason: str
) -> AdaptationProposal:
    """Withdraw a deployed proposal and restore what it displaced."""
    proposal = proposals.get(db, proposal_id)
    if proposal is None:
        raise ValueError(f"No adaptation proposal with id {proposal_id}")
    if proposal.status != ProposalStatus.DEPLOYED.value:
        raise ValueError(
            f"Proposal {proposal_id} is {proposal.status}; only a deployed "
            "proposal can be rolled back."
        )

    if proposal.proposal_type == ProposalType.MODEL_UPDATE.value:
        target_id = (proposal.rollback_state or {}).get("modelId")
        if target_id is None:
            raise ValueError(
                f"Proposal {proposal_id} recorded no rollback target, so there is "
                "no model to restore. Activate a known-good version explicitly "
                "rather than guessing which one was displaced."
            )
        target = db.get(MLModel, target_id)
        if target is None:
            raise ValueError(f"Rollback target model {target_id} no longer exists.")
        if not registry.verify_artifact(
            Path(target.artifact_path), expected_sha256=target.artifact_sha256
        ):
            raise ValueError(
                f"Artifact digest mismatch for rollback target {target.identity}. "
                "Refusing to restore a model that has changed on disk."
            )

        withdrawn = db.get(MLModel, proposal.candidate_model_id)
        registry.activate_model(db, target)
        if withdrawn is not None and withdrawn.id != target.id:
            # Not archived: this model failed in production, which is a
            # different fact and worth being able to see a year later.
            withdrawn.status = MLModelStatus.ROLLED_BACK.value
        db.flush()

    rolled = proposals.mark_rolled_back(
        db, proposal_id, rolled_back_by=rolled_back_by, reason=reason
    )
    logger.warning(
        "Adaptation rolled back",
        extra={
            "proposal": rolled.id,
            "type": rolled.proposal_type,
            "by": rolled_back_by,
            "reason": reason,
            "operation": "adaptation.rollback",
        },
    )
    return rolled
