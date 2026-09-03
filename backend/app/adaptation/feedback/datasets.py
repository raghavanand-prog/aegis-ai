"""Building versioned, fingerprinted snapshots of analyst feedback.

A model's training data must be a fixed thing with a name. If "the feedback
dataset" is a query, then correcting one label silently changes what an
already-trained model was trained on, and no result over it can be reproduced.

So ``build`` materialises membership into rows and fingerprints the result. The
fingerprint covers the ordered ``(feedback id, label)`` pairs, which is what
makes two snapshots comparable or provably different. It deliberately does *not*
cover the dataset's name or the time it was built: the same feedback selected
twice is the same data, whatever it was called.
"""

from __future__ import annotations

import hashlib
from collections import Counter

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.adaptation.feedback.labels import FeedbackLabel
from app.models.adaptation import AnalystFeedback, FeedbackDataset, FeedbackDatasetMember

#: Labels confident enough to become training examples.
TRAINING_ELIGIBLE_LABELS = tuple(
    label.value for label in FeedbackLabel if label.is_training_eligible
)


def _fingerprint(rows: list[AnalystFeedback]) -> str:
    """Stable hash over the membership.

    Ordered by feedback id so that two builds of the same rows agree regardless
    of the order the database returned them in.
    """
    digest = hashlib.sha256()
    for row in sorted(rows, key=lambda item: item.id):
        digest.update(str(row.id).encode())
        digest.update(b"\x00")
        digest.update(row.label.encode())
        digest.update(b"\x01")
    return digest.hexdigest()[:16]


def _select_feedback(
    db: Session,
    *,
    sources: list[str] | None,
    feature_schema_version: str | None,
    analysts: list[str] | None,
) -> list[AnalystFeedback]:
    statement = select(AnalystFeedback).where(
        # Superseded claims are not current, and a snapshot of current opinion
        # must not contain a label the analyst has already withdrawn.
        AnalystFeedback.superseded_by_id.is_(None),
        AnalystFeedback.label.in_(TRAINING_ELIGIBLE_LABELS),
    )
    if sources:
        statement = statement.where(AnalystFeedback.source.in_(sources))
    if feature_schema_version:
        statement = statement.where(
            AnalystFeedback.feature_schema_version == feature_schema_version
        )
    if analysts:
        statement = statement.where(AnalystFeedback.analyst.in_(analysts))
    return list(db.scalars(statement.order_by(AnalystFeedback.id.asc())))


def build(
    db: Session,
    *,
    name: str,
    version: str,
    created_by: str,
    sources: list[str] | None = None,
    feature_schema_version: str | None = None,
    analysts: list[str] | None = None,
    notes: str | None = None,
) -> FeedbackDataset:
    """Snapshot the current training-eligible feedback.

    Rebuilding an identical selection returns the existing snapshot rather than
    creating a duplicate: same data, same fingerprint, same dataset. Rebuilding
    a *different* selection under a name and version already in use is refused,
    because two different datasets cannot both be "v1.0".
    """
    rows = _select_feedback(
        db,
        sources=sources,
        feature_schema_version=feature_schema_version,
        analysts=analysts,
    )
    if not rows:
        raise ValueError(
            "Refusing to build a dataset with no training-eligible feedback. "
            "Labels such as 'suspicious' and 'uncertain' are deliberately not "
            "eligible, and superseded claims are excluded."
        )

    schemas = {row.feature_schema_version for row in rows}
    if len(schemas) > 1:
        raise ValueError(
            f"Selected feedback spans more than one feature schema {sorted(schemas)}. "
            "A label is a claim about the features the analyst was shown, so "
            "pooling across a schema change would train on inputs that never "
            "coexisted. Pass feature_schema_version to choose one."
        )
    schema_version = schemas.pop()

    fingerprint = _fingerprint(rows)

    existing = db.scalar(
        select(FeedbackDataset).where(
            FeedbackDataset.name == name,
            FeedbackDataset.version == version,
        )
    )
    if existing is not None:
        if existing.fingerprint == fingerprint:
            return existing
        raise ValueError(
            f"A dataset named {name!r} version {version!r} already exists with "
            f"fingerprint {existing.fingerprint} and the current selection hashes "
            f"to {fingerprint}. Two different snapshots cannot share a version - "
            "publish this one as a new version instead."
        )

    dataset = FeedbackDataset(
        name=name,
        version=version,
        fingerprint=fingerprint,
        sample_count=len(rows),
        label_distribution=dict(Counter(row.label for row in rows)),
        feature_schema_version=schema_version,
        selection={
            "sources": sources,
            "analysts": analysts,
            "featureSchemaVersion": feature_schema_version,
            "eligibleLabels": list(TRAINING_ELIGIBLE_LABELS),
        },
        created_by=created_by,
        notes=notes,
    )
    db.add(dataset)
    db.flush()

    for row in rows:
        binary = FeedbackLabel(row.label).binary_label
        # Unreachable for eligible labels; asserted rather than defaulted so a
        # future label added to the eligible set cannot silently become benign.
        if binary is None:  # pragma: no cover - guard
            raise ValueError(f"Label {row.label!r} has no binary projection")
        db.add(
            FeedbackDatasetMember(
                dataset_id=dataset.id,
                feedback_id=row.id,
                target_type=row.target_type,
                target_id=row.target_id,
                label=row.label,
                binary_label=binary,
            )
        )
    db.flush()
    db.refresh(dataset)
    return dataset


def get(db: Session, dataset_id: int) -> FeedbackDataset | None:
    return db.get(FeedbackDataset, dataset_id)


def list_datasets(db: Session, *, limit: int = 100) -> list[FeedbackDataset]:
    return list(
        db.scalars(
            select(FeedbackDataset).order_by(FeedbackDataset.created_at.desc()).limit(limit)
        )
    )
