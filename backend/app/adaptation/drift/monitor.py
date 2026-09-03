"""Recording drift readings, and reading their history.

A single reading says the current window differs from the baseline. Only a
series says whether that is a trend, a spike, or a noisy sensor - so every
assessment is persisted with its thresholds and its window labels.

**Nothing here retrains anything.** There is deliberately no code path from a
measurement to the model registry; a test asserts it.
"""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.adaptation.drift import metrics
from app.adaptation.drift.detector import DriftKind, assess_feature_drift
from app.models.adaptation import DriftMeasurement


def record_feature_drift(
    db: Session,
    *,
    feature: str,
    reference,
    current,
    kind: DriftKind = DriftKind.DATA,
    baseline_label: str,
    window_label: str,
    bins: int = 10,
    min_samples: int = metrics.DEFAULT_MIN_SAMPLES,
    moderate: float = metrics.DEFAULT_MODERATE_THRESHOLD,
    significant: float = metrics.DEFAULT_SIGNIFICANT_THRESHOLD,
    model_identity: str | None = None,
) -> DriftMeasurement:
    """Assess one feature and persist the reading."""
    result = assess_feature_drift(
        feature=feature,
        reference=reference,
        current=current,
        kind=kind,
        bins=bins,
        min_samples=min_samples,
        moderate=moderate,
        significant=significant,
    )

    record = DriftMeasurement(
        kind=result.kind.value,
        feature=result.feature,
        baseline_label=baseline_label,
        window_label=window_label,
        metric_name="psi",
        metric_value=result.psi,
        secondary_metric_name="wasserstein",
        secondary_metric_value=result.wasserstein_distance,
        status=result.status.value,
        moderate_threshold=moderate,
        significant_threshold=significant,
        reference_samples=result.reference_samples,
        current_samples=result.current_samples,
        detail=result.as_dict(),
        model_identity=model_identity,
    )
    db.add(record)
    db.flush()
    return record


def history(
    db: Session,
    *,
    feature: str | None = None,
    kind: DriftKind | None = None,
    limit: int = 100,
) -> list[DriftMeasurement]:
    """Readings, newest first."""
    statement = select(DriftMeasurement)
    if feature is not None:
        statement = statement.where(DriftMeasurement.feature == feature)
    if kind is not None:
        statement = statement.where(DriftMeasurement.kind == DriftKind(kind).value)
    statement = statement.order_by(
        DriftMeasurement.measured_at.desc(), DriftMeasurement.id.desc()
    )
    return list(db.scalars(statement.limit(limit)))


def latest_by_feature(db: Session, *, limit: int = 200) -> list[DriftMeasurement]:
    """Most recent reading per feature - the drift dashboard's overview."""
    seen: set[str] = set()
    newest: list[DriftMeasurement] = []
    for record in history(db, limit=limit):
        if record.feature in seen:
            continue
        seen.add(record.feature)
        newest.append(record)
    return newest
