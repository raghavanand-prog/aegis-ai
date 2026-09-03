"""Controlled adaptation: analyst feedback (V5).

Feedback is the input to every adaptation AEGISX will later propose, so the
rules here are about provenance rather than convenience.

**Feedback is append-only.** There is no PUT and no DELETE. A correction posts a
new claim that supersedes the earlier one, and both rows survive: months later
"why was the model trained on that label" must have an answer, including when
the label turned out to be wrong.

**There is no training endpoint**, for the same reason V4 exposed no way to
start an experiment. Training is minutes of CPU, and over HTTP that is a
resource-exhaustion primitive. Training is an operator action on the CLI.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.adaptation.active_learning import selectors
from app.adaptation.active_learning import service as active_learning
from app.adaptation.drift import monitor as drift_monitor
from app.adaptation.feedback import datasets, targets
from app.adaptation.feedback import service as feedback_service
from app.adaptation.feedback.labels import FeedbackLabel, FeedbackTargetType
from app.adaptation.proposals import service as proposals
from app.api.deps import client_ip, require
from app.core.database import get_db
from app.core.rbac import Permission
from app.models.adaptation import AnalystFeedback
from app.models.enums import AuditAction, ProposalStatus
from app.models.user import User
from app.schemas.adaptation import (
    DriftMeasurementRead,
    DriftStatusResponse,
    FeedbackCorrect,
    FeedbackDatasetRead,
    FeedbackRead,
    FeedbackSubmit,
    ProposalCreate,
    ProposalDecision,
    ProposalRead,
    ReviewCandidateRead,
    ReviewQueueResponse,
)
from app.schemas.common import Message
from app.services import audit_service

router = APIRouter(prefix="/adaptation", tags=["adaptation"])


def _read(db: Session, record: AnalystFeedback) -> FeedbackRead:
    return FeedbackRead(
        id=record.id,
        target_type=record.target_type,
        target_id=targets.public_id(
            db, target_type=record.target_type, target_id=record.target_id
        ),
        label=record.label,
        confidence=record.confidence,
        comment=record.comment,
        mitre_techniques=list(record.mitre_techniques or []),
        evidence_reference=record.evidence_reference,
        analyst=record.analyst,
        source=record.source,
        feature_schema_version=record.feature_schema_version,
        model_identity=record.model_identity,
        submitted_at=record.submitted_at,
        supersedes_id=record.supersedes_id,
        superseded_by_id=record.superseded_by_id,
        correction_reason=record.correction_reason,
    )


@router.post(
    "/feedback",
    response_model=FeedbackRead,
    status_code=status.HTTP_201_CREATED,
    summary="Submit analyst feedback",
    description=(
        "Records one analyst's claim about one detection. The claim is stored as "
        "evidence, not as ground truth: it carries the analyst, the time, the "
        "feature schema they were shown and the model that was serving."
    ),
    responses={
        403: {"model": Message, "description": "Analyst role required"},
        404: {"model": Message, "description": "Unknown target"},
        422: {"model": Message, "description": "Invalid label, confidence or technique"},
    },
)
def submit_feedback(
    payload: FeedbackSubmit,
    request: Request,
    user: User = Depends(require(Permission.FEEDBACK_SUBMIT)),
    db: Session = Depends(get_db),
) -> FeedbackRead:
    try:
        target_pk = targets.resolve(
            db, target_type=payload.target_type, public_id=payload.target_id
        )
    except targets.UnknownTargetError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc

    try:
        record = feedback_service.submit(
            db,
            target_type=payload.target_type,
            target_id=target_pk,
            label=payload.label,
            analyst=user.email,
            confidence=payload.confidence,
            comment=payload.comment,
            mitre_techniques=payload.mitre_techniques,
            evidence_reference=payload.evidence_reference,
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)
        ) from exc

    audit_service.record(
        db,
        action=AuditAction.ADAPTATION_FEEDBACK_SUBMITTED,
        user=user,
        target_type="analyst_feedback",
        target_id=str(record.id),
        ip_address=client_ip(request),
        details={
            "target": f"{payload.target_type.value}:{payload.target_id}",
            "label": record.label,
            "confidence": record.confidence,
            "featureSchemaVersion": record.feature_schema_version,
        },
    )
    db.commit()
    db.refresh(record)
    return _read(db, record)


@router.post(
    "/feedback/{feedback_id}/correct",
    response_model=FeedbackRead,
    status_code=status.HTTP_201_CREATED,
    summary="Correct earlier feedback",
    description=(
        "Supersedes an earlier claim with a new one. The original row is never "
        "edited - it records what was believed at the time, which is what makes "
        "the training-set provenance auditable."
    ),
    responses={
        403: {"model": Message, "description": "Analyst role required"},
        404: {"model": Message, "description": "Unknown feedback"},
        409: {"model": Message, "description": "Already superseded"},
    },
)
def correct_feedback(
    feedback_id: int,
    payload: FeedbackCorrect,
    request: Request,
    user: User = Depends(require(Permission.FEEDBACK_SUBMIT)),
    db: Session = Depends(get_db),
) -> FeedbackRead:
    original = db.get(AnalystFeedback, feedback_id)
    if original is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Feedback not found")

    try:
        correction = feedback_service.correct(
            db,
            feedback_id=feedback_id,
            label=payload.label,
            analyst=user.email,
            reason=payload.reason,
            confidence=payload.confidence,
            comment=payload.comment,
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc

    audit_service.record(
        db,
        action=AuditAction.ADAPTATION_FEEDBACK_CORRECTED,
        user=user,
        target_type="analyst_feedback",
        target_id=str(correction.id),
        ip_address=client_ip(request),
        details={
            "supersedes": feedback_id,
            "from": original.label,
            "to": correction.label,
            "reason": payload.reason,
        },
    )
    db.commit()
    db.refresh(correction)
    return _read(db, correction)


@router.get(
    "/feedback",
    response_model=list[FeedbackRead],
    summary="List analyst feedback",
    description=(
        "Newest first. By default only current claims are returned; superseded "
        "rows are still readable with `includeSuperseded=true`, because the "
        "history is the point."
    ),
)
def list_feedback(
    target_type: FeedbackTargetType | None = Query(default=None, alias="targetType"),
    label: FeedbackLabel | None = Query(default=None),
    include_superseded: bool = Query(default=False, alias="includeSuperseded"),
    limit: int = Query(default=100, ge=1, le=500),
    _: User = Depends(require(Permission.FEEDBACK_READ)),
    db: Session = Depends(get_db),
) -> list[FeedbackRead]:
    statement = select(AnalystFeedback)
    if target_type is not None:
        statement = statement.where(AnalystFeedback.target_type == target_type.value)
    if label is not None:
        statement = statement.where(AnalystFeedback.label == label.value)
    if not include_superseded:
        statement = statement.where(AnalystFeedback.superseded_by_id.is_(None))
    statement = statement.order_by(AnalystFeedback.submitted_at.desc(), AnalystFeedback.id.desc())
    rows = list(db.scalars(statement.limit(limit)))
    return [_read(db, row) for row in rows]


@router.get(
    "/feedback/{feedback_id}",
    response_model=FeedbackRead,
    summary="Inspect one feedback record",
    responses={404: {"model": Message, "description": "Unknown feedback"}},
)
def get_feedback(
    feedback_id: int,
    _: User = Depends(require(Permission.FEEDBACK_READ)),
    db: Session = Depends(get_db),
) -> FeedbackRead:
    record = db.get(AnalystFeedback, feedback_id)
    if record is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Feedback not found")
    return _read(db, record)


@router.get(
    "/datasets",
    response_model=list[FeedbackDatasetRead],
    summary="List feedback datasets",
    description=(
        "Immutable snapshots of analyst feedback, newest first. Each carries the "
        "fingerprint of its membership: two snapshots that share a name and "
        "version but not a fingerprint are different data and their results must "
        "never be pooled.\n\n"
        "**There is no endpoint that builds a dataset.** Fixing what a model will "
        "be trained on is an operator decision recorded against a named operator "
        "on the CLI, not something any authenticated session should do."
    ),
)
def list_feedback_datasets(
    limit: int = Query(default=100, ge=1, le=500),
    _: User = Depends(require(Permission.FEEDBACK_READ)),
    db: Session = Depends(get_db),
) -> list[FeedbackDatasetRead]:
    return [
        FeedbackDatasetRead.model_validate(dataset, from_attributes=True)
        for dataset in datasets.list_datasets(db, limit=limit)
    ]


@router.get(
    "/datasets/{dataset_id}",
    response_model=FeedbackDatasetRead,
    summary="Inspect one feedback dataset",
    responses={404: {"model": Message, "description": "Unknown dataset"}},
)
def get_feedback_dataset(
    dataset_id: int,
    _: User = Depends(require(Permission.FEEDBACK_READ)),
    db: Session = Depends(get_db),
) -> FeedbackDatasetRead:
    dataset = datasets.get(db, dataset_id)
    if dataset is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Dataset not found")
    return FeedbackDatasetRead.model_validate(dataset, from_attributes=True)


DRIFT_INTERPRETATION = (
    "These readings describe how the input distribution has moved relative to a "
    "baseline window. A changed distribution is not evidence that the model has "
    "become wrong: that is a separate claim, it requires labels, and V5 reports "
    "it separately as concept drift. Nothing here retrains or rescores anything."
)


@router.get(
    "/drift",
    response_model=DriftStatusResponse,
    summary="Current drift status",
    description=(
        "The most recent reading per feature, with the threshold bands that "
        "produced each status. Read-only: a drift signal is something an analyst "
        "acts on, never something the platform acts on by itself."
    ),
)
def drift_status(
    limit: int = Query(default=200, ge=1, le=1000),
    _: User = Depends(require(Permission.DRIFT_READ)),
    db: Session = Depends(get_db),
) -> DriftStatusResponse:
    readings = drift_monitor.latest_by_feature(db, limit=limit)
    counts: dict[str, int] = {}
    for reading in readings:
        counts[reading.status] = counts.get(reading.status, 0) + 1
    return DriftStatusResponse(
        features=[
            DriftMeasurementRead.model_validate(reading, from_attributes=True)
            for reading in readings
        ],
        counts_by_status=counts,
        interpretation=DRIFT_INTERPRETATION,
    )


@router.get(
    "/drift/history",
    response_model=list[DriftMeasurementRead],
    summary="Drift history for a feature",
    description=(
        "Readings newest first. One reading says the window differs from the "
        "baseline; the series says whether that is a trend, a spike, or noise."
    ),
)
def drift_history(
    feature: str | None = Query(default=None),
    limit: int = Query(default=100, ge=1, le=500),
    _: User = Depends(require(Permission.DRIFT_READ)),
    db: Session = Depends(get_db),
) -> list[DriftMeasurementRead]:
    return [
        DriftMeasurementRead.model_validate(reading, from_attributes=True)
        for reading in drift_monitor.history(db, feature=feature, limit=limit)
    ]


REVIEW_QUEUE_INTERPRETATION = (
    "These events are recommended for analyst review because a verdict on them "
    "would be informative - the rules and the model disagree, the score sits near "
    "the threshold, or the behaviour is rarely seen. The ranking says nothing "
    "about whether any of them is malicious, and nothing here is added to a "
    "training set. Only an analyst's own feedback enters a dataset, and only "
    "after they give it."
)


@router.get(
    "/review-queue",
    response_model=ReviewQueueResponse,
    summary="Events recommended for analyst review",
    description=(
        "Ranked by how much an analyst's verdict would be worth, with the reason "
        "for each. Events that already carry feedback are excluded.\n\n"
        "Read-only by design: this endpoint recommends where to spend attention. "
        "It cannot label anything and cannot add a sample to training."
    ),
)
def review_queue(
    limit: int = Query(default=25, ge=1, le=200),
    _: User = Depends(require(Permission.FEEDBACK_READ)),
    db: Session = Depends(get_db),
) -> ReviewQueueResponse:
    candidates = active_learning.select_candidates(db, limit=limit)
    return ReviewQueueResponse(
        candidates=[
            ReviewCandidateRead(
                event_id=candidate.public_id,
                title=candidate.title,
                priority=round(candidate.priority, 4),
                reason=candidate.reason,
                signals={name: round(value, 4) for name, value in candidate.signals.items()},
                anomaly_score=candidate.anomaly_score,
                threshold=candidate.threshold,
                rule_hit=candidate.rule_hit,
                ml_flagged=candidate.ml_flagged,
                risk_score=candidate.risk_score,
            )
            for candidate in candidates
        ],
        weights=dict(selectors.DEFAULT_WEIGHTS),
        interpretation=REVIEW_QUEUE_INTERPRETATION,
    )


def _proposal_read(proposal) -> ProposalRead:
    return ProposalRead.model_validate(proposal, from_attributes=True)


@router.post(
    "/proposals",
    response_model=ProposalRead,
    status_code=status.HTTP_201_CREATED,
    summary="Raise an adaptation proposal",
    description=(
        "Requests a change to what AEGISX detects. Creating a proposal changes "
        "nothing: it enters the queue as `pending` and reaches production only "
        "through an administrator's approval and a separate deployment step."
    ),
    responses={
        403: {"model": Message, "description": "Analyst role required"},
        422: {"model": Message, "description": "Missing evidence, or a no-op change"},
    },
)
def create_proposal(
    payload: ProposalCreate,
    request: Request,
    user: User = Depends(require(Permission.ADAPTATION_PROPOSE)),
    db: Session = Depends(get_db),
) -> ProposalRead:
    try:
        proposal = proposals.create(
            db,
            proposal_type=payload.proposal_type,
            title=payload.title,
            reason=payload.reason,
            affected_component=payload.affected_component,
            before_state=payload.before_state,
            after_state=payload.after_state,
            evidence=payload.evidence,
            expected_impact=payload.expected_impact,
            risk_assessment=payload.risk_assessment,
            candidate_model_id=payload.candidate_model_id,
            feedback_dataset_id=payload.feedback_dataset_id,
            # The proposer is the authenticated user, never a value from the
            # request body. An actor a client can choose is not an actor.
            proposed_by=user.email,
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)
        ) from exc

    audit_service.record(
        db,
        action=AuditAction.ADAPTATION_PROPOSAL_CREATED,
        user=user,
        target_type="adaptation_proposal",
        target_id=str(proposal.id),
        ip_address=client_ip(request),
        details={
            "type": proposal.proposal_type,
            "component": proposal.affected_component,
            "before": proposal.before_state,
            "after": proposal.after_state,
        },
    )
    db.commit()
    db.refresh(proposal)
    return _proposal_read(proposal)


@router.post(
    "/proposals/{proposal_id}/approve",
    response_model=ProposalRead,
    summary="Approve an adaptation proposal",
    description=(
        "Administrator only. Approval authorises the change; it does not apply "
        "it. A proposal whose safety gates failed cannot be approved."
    ),
    responses={
        403: {"model": Message, "description": "Administrator role required"},
        404: {"model": Message, "description": "Unknown proposal"},
        409: {"model": Message, "description": "Not pending, or failed its gates"},
    },
)
def approve_proposal(
    proposal_id: int,
    request: Request,
    user: User = Depends(require(Permission.ADAPTATION_APPROVE)),
    db: Session = Depends(get_db),
) -> ProposalRead:
    if proposals.get(db, proposal_id) is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Proposal not found")
    try:
        proposal = proposals.approve(db, proposal_id, approved_by=user.email)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc

    audit_service.record(
        db,
        action=AuditAction.ADAPTATION_PROPOSAL_APPROVED,
        user=user,
        target_type="adaptation_proposal",
        target_id=str(proposal.id),
        ip_address=client_ip(request),
        details={
            "proposedBy": proposal.proposed_by,
            "selfApproved": proposal.self_approved,
            "component": proposal.affected_component,
        },
    )
    db.commit()
    db.refresh(proposal)
    return _proposal_read(proposal)


@router.post(
    "/proposals/{proposal_id}/reject",
    response_model=ProposalRead,
    summary="Reject an adaptation proposal",
    description="Administrator only. A rejection needs a reason, and is kept.",
    responses={
        403: {"model": Message, "description": "Administrator role required"},
        404: {"model": Message, "description": "Unknown proposal"},
        409: {"model": Message, "description": "No longer rejectable"},
        422: {"model": Message, "description": "A reason is required"},
    },
)
def reject_proposal(
    proposal_id: int,
    payload: ProposalDecision,
    request: Request,
    user: User = Depends(require(Permission.ADAPTATION_APPROVE)),
    db: Session = Depends(get_db),
) -> ProposalRead:
    if proposals.get(db, proposal_id) is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Proposal not found")
    if not (payload.reason or "").strip():
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="A rejection needs a reason.",
        )
    try:
        proposal = proposals.reject(
            db, proposal_id, rejected_by=user.email, reason=payload.reason
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc

    audit_service.record(
        db,
        action=AuditAction.ADAPTATION_PROPOSAL_REJECTED,
        user=user,
        target_type="adaptation_proposal",
        target_id=str(proposal.id),
        ip_address=client_ip(request),
        details={"reason": payload.reason, "proposedBy": proposal.proposed_by},
    )
    db.commit()
    db.refresh(proposal)
    return _proposal_read(proposal)


@router.get(
    "/proposals",
    response_model=list[ProposalRead],
    summary="List adaptation proposals",
    description="Newest first. Rejected and rolled-back proposals are kept and listed.",
)
def list_adaptation_proposals(
    proposal_status: ProposalStatus | None = Query(default=None, alias="status"),
    limit: int = Query(default=100, ge=1, le=500),
    _: User = Depends(require(Permission.ADAPTATION_READ)),
    db: Session = Depends(get_db),
) -> list[ProposalRead]:
    return [
        _proposal_read(proposal)
        for proposal in proposals.list_proposals(db, status=proposal_status, limit=limit)
    ]


@router.get(
    "/proposals/{proposal_id}",
    response_model=ProposalRead,
    summary="Inspect one adaptation proposal",
    responses={404: {"model": Message, "description": "Unknown proposal"}},
)
def get_proposal(
    proposal_id: int,
    _: User = Depends(require(Permission.ADAPTATION_READ)),
    db: Session = Depends(get_db),
) -> ProposalRead:
    proposal = proposals.get(db, proposal_id)
    if proposal is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Proposal not found")
    return _proposal_read(proposal)
