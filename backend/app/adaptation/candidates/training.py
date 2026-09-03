"""Training a candidate model.

Deliberately separate from ``app.ml.training.train_anomaly_model``, which trains
*and activates* the production model. A candidate is trained and left inert: it
gets an artifact, a registry row, and no route to serving.

Training is an operator action on the CLI, never an HTTP request. It is minutes
of CPU, and V4 established that exposing that over HTTP hands any authenticated
user a resource-exhaustion primitive.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from sqlalchemy.orm import Session

from app.core.config import settings
from app.ml.models.isolation_forest import IsolationForestDetector
from app.ml.registry import registry
from app.ml.training.corpus import build_corpus
from app.models.enums import MLModelStatus
from app.models.ml import MLModel

logger = logging.getLogger("aegisx.adaptation.training")

#: Below this a fit is not comparable with the deployed model's.
MINIMUM_CORPUS = 200
HOLDOUT_FRACTION = 0.2

MODEL_NAME = "isolation_forest"
MODEL_TYPE = "sklearn.ensemble.IsolationForest"
TRAINING_DATASET_VERSION = "1.0"


def train_candidate(
    db: Session,
    *,
    seed: int = 4242,
    samples: int = 6000,
    span_days: int = 14,
    contamination: float | None = None,
    random_state: int | None = None,
    n_estimators: int = 200,
    directory: Path | None = None,
    created_by: str = "cli",
    notes: str | None = None,
    feedback_dataset_id: int | None = None,
) -> MLModel:
    """Train one candidate and register it as inert.

    Returns a model in ``candidate`` status. Nothing about this call activates
    it, and ``registry.activate_model`` will refuse it until it has been
    evaluated and approved.
    """
    contamination = contamination if contamination is not None else settings.ml_contamination
    random_state = random_state if random_state is not None else settings.ml_random_state

    corpus = build_corpus(seed=seed, samples=samples, span_days=span_days)
    if corpus.size < MINIMUM_CORPUS:
        raise ValueError(
            f"Corpus produced only {corpus.size} usable samples; refusing to train "
            f"a candidate on fewer than {MINIMUM_CORPUS}. A model fitted on too "
            "little data would be evaluated as though it were comparable to the "
            "deployed one."
        )

    # The same 80/20 split the production trainer uses, so a candidate's score
    # distribution is comparable with the incumbent's rather than being computed
    # over a different amount of data.
    split = int(corpus.size * (1 - HOLDOUT_FRACTION))
    fit_vectors = corpus.vectors[:split]
    holdout = corpus.vectors[split:]

    detector = IsolationForestDetector(
        feature_names=corpus.feature_names,
        contamination=contamination,
        random_state=random_state,
        n_estimators=n_estimators,
    )
    detector.fit(fit_vectors)

    # Score distribution on unseen data. Characterisation, not accuracy: the
    # corpus is unlabelled, so there is no precision or recall here and none is
    # invented. Labelled measurement is Phase G's job.
    holdout_scores = sorted(detector.anomaly_score(vector) for vector in holdout)

    version = registry.next_version(db, MODEL_NAME, directory=directory)
    # reserve_artifact_path refuses a path that already exists. Candidate
    # training runs repeatedly by design, so this is the call that stops a
    # retrain from landing on a deployed model's file.
    path = registry.reserve_artifact_path(MODEL_NAME, version, directory=directory)

    digest = detector.save(path)
    # Read it straight back. An artifact that cannot be loaded must never reach
    # the registry, candidate or not.
    IsolationForestDetector.load(path, expected_sha256=digest)

    model = registry.register(
        db,
        name=MODEL_NAME,
        version=version,
        model_type=MODEL_TYPE,
        feature_schema_version=corpus.schema_version,
        dataset_version=TRAINING_DATASET_VERSION,
        dataset_fingerprint=corpus.fingerprint(),
        training_samples=len(fit_vectors),
        parameters={
            "seed": seed,
            "samples": samples,
            "spanDays": span_days,
            "contamination": contamination,
            "randomState": random_state,
            "nEstimators": n_estimators,
            # Recorded even when absent: "trained without analyst feedback" is
            # a fact about the model, not a missing field.
            "feedbackDatasetId": feedback_dataset_id,
        },
        metrics={
            "holdoutSamples": len(holdout),
            "holdoutScoreP50": _percentile(holdout_scores, 50),
            "holdoutScoreP95": _percentile(holdout_scores, 95),
            "measured": (
                "Unsupervised fit on unlabelled synthetic telemetry. These are "
                "score distribution statistics, not detection accuracy."
            ),
        },
        feature_names=list(corpus.feature_names),
        artifact_path_str=str(path),
        artifact_sha256=digest,
        created_by=created_by,
        notes=notes,
        activate=False,
    )

    # register() defaults to ARCHIVED, which means "registered but not serving".
    # A candidate is a stronger claim than that: it has not been evaluated, and
    # the distinction is what the approval workflow reads.
    model.status = MLModelStatus.CANDIDATE.value
    db.flush()

    logger.info(
        "Candidate model trained",
        extra={
            "model": model.identity,
            "operation": "adaptation.candidate_trained",
            "digest": digest[:16],
        },
    )
    return model


def _percentile(ordered: list[float], percentile: int) -> float | None:
    """Percentile of an already-sorted list, or None where undefined."""
    if not ordered:
        return None
    index = min(len(ordered) - 1, max(0, int(round((percentile / 100) * (len(ordered) - 1)))))
    return round(ordered[index], 4)


def describe(model: MLModel) -> dict[str, Any]:
    """Candidate summary for a report or an API payload."""
    return {
        "identity": model.identity,
        "status": model.status,
        "featureSchemaVersion": model.feature_schema_version,
        "datasetFingerprint": model.dataset_fingerprint,
        "artifactSha256": model.artifact_sha256,
        "parameters": model.parameters,
        "trainedAt": model.trained_at.isoformat() if model.trained_at else None,
        "createdBy": model.created_by,
    }
