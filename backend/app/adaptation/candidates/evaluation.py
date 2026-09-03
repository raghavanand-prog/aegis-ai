"""Comparing a candidate against the model actually deployed.

Reuses V4 wholesale: the same dataset abstraction, the same production feature
extractor, the same chronological replay. A candidate measured with a second
evaluation pipeline would be compared against a number the first pipeline
produced, and the difference between them would be indistinguishable from the
difference between the models.

Both models are scored over the **same** samples in the **same** order. That is
the only reason the two confusion matrices are comparable at all.

Nothing here changes model state. Evaluation produces evidence; approval is a
separate, human act.
"""

from __future__ import annotations

import time
from typing import Any

from sqlalchemy.orm import Session

from app.adaptation.candidates import gates
from app.core.config import settings
from app.evaluation.datasets.adapters import synthetic_dataset
from app.evaluation.metrics.classification import ConfusionMatrix
from app.ml.features.extractor import FeatureExtractor
from app.ml.models.isolation_forest import IsolationForestDetector
from app.ml.registry import registry
from app.models.ml import MLModel


def _load(model: MLModel) -> IsolationForestDetector:
    """Load a registered artifact, verifying its digest.

    A model whose artifact no longer matches its recorded hash has been altered
    on disk. Evaluating it would measure something other than what was
    registered, so it is refused rather than warned about.
    """
    from pathlib import Path

    path = Path(model.artifact_path)
    if not registry.verify_artifact(path, expected_sha256=model.artifact_sha256):
        raise ValueError(
            f"Artifact for {model.identity} does not match its recorded digest. "
            "The file has been altered since registration; refusing to evaluate "
            "a model that is not the one that was registered."
        )
    return IsolationForestDetector.load(path, expected_sha256=model.artifact_sha256)


def _score_per_category(
    detector: IsolationForestDetector,
    vectors: list[tuple[float, ...]],
    labels: list[bool],
    categories: list[str],
    threshold: float,
) -> dict[str, ConfusionMatrix]:
    """One confusion matrix per attack category.

    V6 §8 measured a candidate losing 0.2026 of one category's recall while
    aggregate recall moved 0.0232 - less than its own seed noise. Aggregate
    numbers cannot see that, so the gate needs these.

    Benign samples are counted into **every** category's matrix, because a
    category's recall is about the malicious samples of that category while its
    false-positive behaviour is shared. Only recall is gated on, so this keeps
    the recall denominator per-category and correct.
    """
    matrices: dict[str, ConfusionMatrix] = {}
    for vector, is_malicious, category in zip(vectors, labels, categories, strict=True):
        if not is_malicious:
            continue
        matrix = matrices.setdefault(category, ConfusionMatrix())
        if detector.anomaly_score(vector) >= threshold:
            matrix.true_positives += 1
        else:
            matrix.false_negatives += 1
    return matrices


def _score(
    detector: IsolationForestDetector,
    vectors: list[tuple[float, ...]],
    labels: list[bool],
    threshold: float,
) -> tuple[ConfusionMatrix, float]:
    """Confusion matrix and mean per-event latency in milliseconds."""
    matrix = ConfusionMatrix()
    started = time.perf_counter()
    for vector, is_malicious in zip(vectors, labels, strict=True):
        flagged = detector.anomaly_score(vector) >= threshold
        if flagged and is_malicious:
            matrix.true_positives += 1
        elif flagged and not is_malicious:
            matrix.false_positives += 1
        elif not flagged and is_malicious:
            matrix.false_negatives += 1
        else:
            matrix.true_negatives += 1
    elapsed_ms = (time.perf_counter() - started) * 1000.0
    per_event = elapsed_ms / len(vectors) if vectors else 0.0
    return matrix, per_event


def _describe(model: MLModel | None, matrix: ConfusionMatrix | None, latency: float | None) -> dict | None:
    if model is None:
        return None
    return {
        "identity": model.identity,
        "status": model.status,
        "artifactSha256": model.artifact_sha256,
        "featureSchemaVersion": model.feature_schema_version,
        "datasetFingerprint": model.dataset_fingerprint,
        "metrics": None
        if matrix is None
        else {
            "truePositives": matrix.true_positives,
            "falsePositives": matrix.false_positives,
            "trueNegatives": matrix.true_negatives,
            "falseNegatives": matrix.false_negatives,
            # Nullable throughout: an undefined metric is reported as null,
            # never as zero. V4's rule, unchanged.
            "precision": matrix.precision,
            "recall": matrix.recall,
            "f1": matrix.f1,
            "falsePositiveRate": matrix.false_positive_rate,
        },
        "latencyMsPerEvent": None if latency is None else round(latency, 4),
    }


def evaluate_candidate(
    db: Session,
    *,
    candidate: MLModel,
    baseline: MLModel | None = ...,
    seed: int = 1337,
    samples_per_class: int | None = None,
    threshold: float | None = None,
    policy: gates.GatePolicy | None = None,
) -> dict[str, Any]:
    """Score a candidate and the deployed model over one labelled corpus.

    ``baseline`` defaults to whatever is currently active. Pass ``None``
    explicitly to evaluate without one - the report then says so and the gates
    fail, because "better than nothing" is not a promotion criterion.
    """
    if baseline is ...:
        baseline = registry.get_active(db, candidate.name)

    threshold = threshold if threshold is not None else settings.ml_anomaly_threshold

    dataset = synthetic_dataset(seed=seed, samples_per_class=samples_per_class)
    ordered = sorted(dataset.samples, key=lambda sample: sample.timestamp)

    # One extractor, one chronological pass, exactly as V4 does it: the
    # behavioural features are stateful, so replaying them per model would give
    # the second model a different view of history than the first.
    extractor = FeatureExtractor()
    vectors: list[tuple[float, ...]] = []
    labels: list[bool] = []
    categories: list[str] = []
    for sample in ordered:
        vectors.append(extractor.extract(sample.candidate, observe=True).values)
        labels.append(bool(sample.is_malicious))
        categories.append(str(sample.category))

    candidate_detector = _load(candidate)
    candidate_matrix, candidate_latency = _score(
        candidate_detector, vectors, labels, threshold
    )
    candidate_per_category = _score_per_category(
        candidate_detector, vectors, labels, categories, threshold
    )

    baseline_matrix: ConfusionMatrix | None = None
    baseline_latency: float | None = None
    baseline_per_category: dict[str, ConfusionMatrix] | None = None
    if baseline is not None:
        baseline_detector = _load(baseline)
        baseline_matrix, baseline_latency = _score(
            baseline_detector, vectors, labels, threshold
        )
        baseline_per_category = _score_per_category(
            baseline_detector, vectors, labels, categories, threshold
        )

    if baseline_matrix is None:
        gate_result = gates.GateResult(
            passed=False,
            checks=[],
            failures=[
                "baseline: no model is currently deployed, so there is nothing to "
                "compare this candidate against. A promotion decision is a "
                "comparison, and 'better than nothing' is not a criterion."
            ],
            policy={},
            rationale={},
        )
    else:
        gate_result = gates.evaluate(
            baseline=baseline_matrix,
            candidate=candidate_matrix,
            baseline_latency_ms=baseline_latency,
            candidate_latency_ms=candidate_latency,
            baseline_dataset_fingerprint=dataset.fingerprint(),
            candidate_dataset_fingerprint=dataset.fingerprint(),
            baseline_per_category=baseline_per_category,
            candidate_per_category=candidate_per_category,
            policy=policy,
        )

    per_category_report = {
        category: {
            "maliciousSamples": matrix.actual_positives,
            "candidateRecall": matrix.recall,
            "baselineRecall": (
                baseline_per_category.get(category).recall
                if baseline_per_category and baseline_per_category.get(category)
                else None
            ),
        }
        for category, matrix in sorted(candidate_per_category.items())
    }

    return {
        "perCategory": per_category_report,
        "dataset": {
            "name": dataset.name,
            "version": dataset.version,
            "fingerprint": dataset.fingerprint(),
            "samples": len(ordered),
            "malicious": sum(labels),
        },
        "threshold": threshold,
        "featureSchemaVersion": extractor.schema_version,
        "candidate": _describe(candidate, candidate_matrix, candidate_latency),
        "baseline": _describe(baseline, baseline_matrix, baseline_latency),
        "gates": gate_result.as_dict(),
        "interpretation": (
            "Both models were scored over the same samples in the same order "
            "using the production feature extractor. A passing gate result means "
            "the candidate is safe to consider; deploying it requires an "
            "administrator's approval."
        ),
    }
