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

from app.adaptation.drift import monitor as drift_monitor
from app.adaptation.feedback import datasets, targets
from app.adaptation.feedback import service as feedback_service
from app.adaptation.feedback.labels import FeedbackLabel, FeedbackTargetType
from app.api.deps import client_ip, require
from app.core.database import get_db
from app.core.rbac import Permission
from app.models.adaptation import AnalystFeedback
from app.models.enums import AuditAction
from app.models.user import User
from app.schemas.adaptation import (
    DriftMeasurementRead,
    DriftStatusResponse,
    FeedbackCorrect,
    FeedbackDatasetRead,
    FeedbackRead,
    FeedbackSubmit,
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
