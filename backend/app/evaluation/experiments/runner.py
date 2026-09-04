"""Reproducible experiment execution.

One experiment = one dataset + one split + one detector + one threshold policy.
Everything needed to reproduce it is recorded on the result, and the same
configuration must produce the same numbers.

The protocol this module exists to enforce
------------------------------------------

::

    train split      -> fit the detector (labels only where supervised)
    validation split -> sweep thresholds, choose one, FREEZE it
    test split       -> evaluate once, at the frozen threshold

The test split is touched exactly once, after the threshold is fixed. Choosing
a threshold from test results and then reporting those same results is the most
common way an evaluation reports a number it did not earn, and the structure
here makes it awkward to do by accident: ``select_threshold`` never receives the
test split, and the frozen value is recorded on the result next to the
validation metric that chose it.

Feature extraction and causality
--------------------------------

Features are extracted **once**, over the whole dataset in chronological order,
using the production extractor. This is not a shortcut: AEGISX's behavioural
features summarise what an entity did *before* the current event, so replaying
the corpus in arrival order is precisely what the ingestion path does. No
feature can see the future, and a test sample legitimately sees the history
that preceded it - as it would in production.

Extracting per-split instead would be *less* faithful: it would give a test
sample an empty history it would never have in service.
"""

from __future__ import annotations

import logging
import platform
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from app.evaluation.datasets.base import EvaluationDataset, EvaluationSample, config_digest
from app.evaluation.experiments.detectors import ORDERED_KINDS, DetectorSpec
from app.evaluation.metrics.classification import ConfusionMatrix
from app.evaluation.metrics.latency import LatencyStats
from app.evaluation.metrics.ranking import (
    balanced_accuracy,
    matthews_correlation,
    normalized_confusion,
    ranking_metrics,
)
from app.evaluation.splits import TEST, TRAIN, VALIDATION, Split, SplitPlan
from app.ml.features.extractor import FEATURE_NAMES, FeatureExtractor
from app.ml.schemas import FEATURE_SCHEMA_VERSION

logger = logging.getLogger("aegisx.evaluation.experiment")

RESULT_SCHEMA_VERSION = "1.0"

#: Objective used to pick a threshold on validation. F1 balances the two
#: failure modes; a SOC that cares more about analyst load than recall would
#: choose differently, and the choice is recorded rather than assumed.
DEFAULT_OBJECTIVE = "f1"


class ExperimentError(RuntimeError):
    """Raised when an experiment cannot be run honestly."""


# ------------------------------------------------------------------ features


def extract_features(dataset: EvaluationDataset) -> dict[str, tuple[float, ...]]:
    """Run the production extractor over the corpus in chronological order."""
    extractor = FeatureExtractor()
    ordered = sorted(dataset.samples, key=lambda sample: (sample.timestamp, sample.id))
    features: dict[str, tuple[float, ...]] = {}
    for sample in ordered:
        features[sample.id] = extractor.extract(sample.candidate, observe=True).values
    return features


# --------------------------------------------------------------- leakage audit


def leakage_audit(plan: SplitPlan, features: dict[str, tuple[float, ...]]) -> dict[str, Any]:
    """Measure residual leakage instead of asserting there is none.

    Group keys stop *known* duplicates crossing a split. They cannot stop two
    genuinely distinct records from landing on the same feature vector - which
    happens whenever the schema does not separate them, and which lets a model
    answer a test sample from memory.

    This audit reports how many test samples share an exact feature vector with
    a training sample. It is a number in every report, not a claim: a high value
    invalidates the metrics beside it, and hiding it would be the single most
    effective way to publish an inflated result.
    """
    train_vectors: dict[tuple[float, ...], int] = {}
    for sample in plan.train.samples:
        vector = features.get(sample.id)
        if vector is not None:
            train_vectors[vector] = train_vectors.get(vector, 0) + 1

    findings: dict[str, Any] = {}
    for name in (VALIDATION, TEST):
        split = plan.splits()[name]
        shared = 0
        for sample in split.samples:
            vector = features.get(sample.id)
            if vector is not None and vector in train_vectors:
                shared += 1
        findings[name] = {
            "samples": len(split),
            "sharingATrainingFeatureVector": shared,
            "share": round(shared / len(split), 6) if len(split) else None,
        }

    worst = max(
        (entry["share"] or 0.0) for entry in findings.values()
    ) if findings else 0.0
    return {
        "method": (
            "exact feature-vector match against the training split, after group-aware "
            "splitting"
        ),
        "splits": findings,
        "interpretation": (
            "0% means no test sample could be answered from a memorised training row. "
            "A non-zero share is not automatically leakage - distinct events can "
            "legitimately produce identical features - but it bounds how much of the "
            "result could be memorisation."
        ),
        "concerning": worst > 0.05,
    }


# ------------------------------------------------------------------- results


@dataclass
class SplitMetrics:
    """Everything measured on one split at one threshold."""

    split: str
    threshold: float
    confusion: ConfusionMatrix
    ranking: dict[str, Any]
    latency: LatencyStats
    alerts: int
    per_class: dict[str, dict[str, Any]]
    mcc: float | None
    balanced_accuracy: float | None

    def to_dict(self) -> dict[str, Any]:
        matrix = self.confusion
        alerts_per_thousand = (
            round(self.alerts / matrix.total * 1000, 2) if matrix.total else None
        )
        return {
            "split": self.split,
            "threshold": self.threshold,
            "confusion": matrix.to_dict(),
            "confusionNormalized": normalized_confusion(
                matrix.true_positives,
                matrix.true_negatives,
                matrix.false_positives,
                matrix.false_negatives,
            ),
            "ranking": self.ranking,
            "mcc": round(self.mcc, 4) if self.mcc is not None else None,
            "balancedAccuracy": (
                round(self.balanced_accuracy, 4) if self.balanced_accuracy is not None else None
            ),
            "latency": self.latency.to_dict(),
            "alertVolume": {
                "alerts": self.alerts,
                "events": matrix.total,
                "alertsPerThousandEvents": alerts_per_thousand,
                "trueAlerts": matrix.true_positives,
                "falseAlerts": matrix.false_positives,
                "falseAlertShare": (
                    round(matrix.false_positives / self.alerts, 4) if self.alerts else None
                ),
            },
            "perClass": self.per_class,
        }


@dataclass
class ThresholdSweepPoint:
    threshold: float
    precision: float | None
    recall: float | None
    f1: float | None
    false_positive_rate: float | None
    false_negative_rate: float | None
    alerts: int
    alerts_per_thousand: float | None

    def to_dict(self) -> dict[str, Any]:
        return {
            "threshold": self.threshold,
            "precision": self.precision,
            "recall": self.recall,
            "f1": self.f1,
            "falsePositiveRate": self.false_positive_rate,
            "falseNegativeRate": self.false_negative_rate,
            "alerts": self.alerts,
            "alertsPerThousandEvents": self.alerts_per_thousand,
        }


@dataclass
class ExperimentResult:
    """One detector's complete, traceable result."""

    experiment_id: str
    detector: dict[str, Any]
    dataset: dict[str, Any]
    split: dict[str, Any]
    threshold: float
    threshold_selection: dict[str, Any]
    validation: SplitMetrics | None
    test: SplitMetrics
    sweep: list[ThresholdSweepPoint]
    environment: dict[str, Any]
    notes: list[str] = field(default_factory=list)
    schema_version: str = RESULT_SCHEMA_VERSION
    generated_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schemaVersion": self.schema_version,
            "experimentId": self.experiment_id,
            "generatedAt": self.generated_at,
            "detector": self.detector,
            "dataset": self.dataset,
            "split": self.split,
            "threshold": self.threshold,
            "thresholdSelection": self.threshold_selection,
            "validation": self.validation.to_dict() if self.validation else None,
            "test": self.test.to_dict(),
            "thresholdSweep": [point.to_dict() for point in self.sweep],
            "environment": self.environment,
            "notes": self.notes,
        }


# ---------------------------------------------------------------- evaluation


def _per_class(
    samples: list[EvaluationSample], detected: dict[str, bool]
) -> dict[str, dict[str, Any]]:
    buckets: dict[str, dict[str, Any]] = {}
    for sample in samples:
        entry = buckets.setdefault(
            sample.category, {"total": 0, "detected": 0, "missed": 0, "detectionRate": None}
        )
        entry["total"] += 1
        if detected.get(sample.id):
            entry["detected"] += 1
        else:
            entry["missed"] += 1
    for entry in buckets.values():
        entry["detectionRate"] = (
            round(entry["detected"] / entry["total"], 4) if entry["total"] else None
        )
        entry["sufficientData"] = entry["total"] >= 20
    return dict(sorted(buckets.items()))


def _evaluate_split(
    spec: DetectorSpec,
    split: Split,
    features: dict[str, tuple[float, ...]],
    threshold: float,
) -> tuple[SplitMetrics, list[float], list[bool]]:
    matrix = ConfusionMatrix()
    latencies: list[float] = []
    scores: list[float] = []
    labels: list[bool] = []
    detected_map: dict[str, bool] = {}
    alerts = 0

    for sample in split.samples:
        prediction = spec.detector.predict(sample, features.get(sample.id), threshold)
        matrix.record(is_malicious=sample.is_malicious, detected=prediction.detected)
        latencies.append(prediction.latency_ms)
        scores.append(prediction.score)
        labels.append(sample.is_malicious)
        detected_map[sample.id] = prediction.detected
        if prediction.detected:
            alerts += 1

    ordered = spec.detector.score_kind in ORDERED_KINDS
    metrics = SplitMetrics(
        split=split.name,
        threshold=threshold,
        confusion=matrix,
        ranking=ranking_metrics(
            scores, labels, score_kind=spec.detector.score_kind, ordered=ordered
        ).to_dict(),
        latency=LatencyStats.from_samples(latencies),
        alerts=alerts,
        per_class=_per_class(split.samples, detected_map),
        mcc=matthews_correlation(
            matrix.true_positives,
            matrix.true_negatives,
            matrix.false_positives,
            matrix.false_negatives,
        ),
        balanced_accuracy=balanced_accuracy(
            matrix.true_positives,
            matrix.true_negatives,
            matrix.false_positives,
            matrix.false_negatives,
        ),
    )
    return metrics, scores, labels


def _sweep(
    scores: list[float], labels: list[bool], grid: tuple[float, ...]
) -> list[ThresholdSweepPoint]:
    """Sweep a precomputed score vector. No re-prediction, so it is exact."""
    points: list[ThresholdSweepPoint] = []
    total = len(labels)
    for threshold in grid:
        matrix = ConfusionMatrix()
        alerts = 0
        for score, label in zip(scores, labels, strict=True):
            detected = score >= threshold
            matrix.record(is_malicious=label, detected=detected)
            if detected:
                alerts += 1
        points.append(
            ThresholdSweepPoint(
                threshold=threshold,
                precision=matrix.precision,
                recall=matrix.recall,
                f1=matrix.f1,
                false_positive_rate=matrix.false_positive_rate,
                false_negative_rate=matrix.false_negative_rate,
                alerts=alerts,
                alerts_per_thousand=round(alerts / total * 1000, 2) if total else None,
            )
        )
    return points


def select_threshold(
    points: list[ThresholdSweepPoint], *, objective: str = DEFAULT_OBJECTIVE
) -> tuple[float, dict[str, Any]]:
    """Pick a threshold from **validation** results only.

    This function is never given the test split. Ties are broken toward the
    higher threshold, which is the conservative choice: fewer alerts for the
    same measured quality.
    """
    if not points:
        raise ExperimentError("cannot select a threshold from an empty sweep")

    def objective_value(point: ThresholdSweepPoint) -> float:
        value = getattr(point, objective, None)
        return -1.0 if value is None else float(value)

    best = max(points, key=lambda point: (objective_value(point), point.threshold))
    thresholds = [point.threshold for point in points]
    at_boundary = best.threshold in (min(thresholds), max(thresholds))
    return best.threshold, {
        "method": "maximise objective on the validation split, then freeze",
        "objective": objective,
        "objectiveValue": objective_value(best),
        "candidates": len(points),
        "chosenThreshold": best.threshold,
        "gridMin": min(thresholds),
        "gridMax": max(thresholds),
        "atGridBoundary": at_boundary,
        "note": (
            "The test split was not consulted. Tie-break favours the higher threshold "
            "(fewer alerts at equal measured quality)."
        ),
        "warning": (
            "The chosen threshold sits at the edge of the search grid, so the true "
            "optimum may lie outside it and this value should not be read as one."
            if at_boundary
            else None
        ),
    }


def environment_metadata() -> dict[str, Any]:
    import sklearn

    return {
        "python": sys.version.split()[0],
        "platform": platform.platform(),
        "scikitLearn": sklearn.__version__,
        "featureSchemaVersion": FEATURE_SCHEMA_VERSION,
        "featureCount": len(FEATURE_NAMES),
    }


#: Registry bookkeeping that records *when and where a row was written*, not
#: *what the model is*. A faithful reproduction re-registers the byte-identical
#: artifact into a rebuilt database and necessarily gets a new row id and new
#: timestamps; hashing those made the experiment id unstable for exactly the
#: detector whose identity matters most.
#:
#: Measured in V8: re-running the synthetic suite against the same artifact
#: (``016c6dbf37f53d03…``) reproduced every metric to the last digit while the
#: id moved ``EXP-2d582f5b6b84fcb7`` → ``EXP-b24021cee9b9a35c``. That breaks
#: this project's own reproduction check (``docs/REPRODUCIBILITY.md`` §5), and
#: it breaks it in the worst direction: a correct reproduction looked like a
#: different experiment.
#:
#: Everything that identifies the model - ``identity``, ``version``,
#: ``artifactSha256``, ``datasetFingerprint``, ``featureSchemaVersion``,
#: ``parameters`` - is deliberately still hashed. A different artifact must
#: still produce a different id.
_VOLATILE_MODEL_KEYS = frozenset({"id", "trainedAt", "activatedAt"})


def _stable_detector_description(description: dict[str, Any]) -> dict[str, Any]:
    """``description`` with per-registration bookkeeping removed.

    A no-op for fitted detectors, whose ``model`` block is ``None`` - so no
    already-published id moves.
    """
    model = description.get("model")
    if not isinstance(model, dict):
        return description
    return {
        **description,
        "model": {k: v for k, v in model.items() if k not in _VOLATILE_MODEL_KEYS},
    }


def experiment_id(
    *,
    dataset: EvaluationDataset,
    plan: SplitPlan,
    detector_description: dict[str, Any],
    objective: str,
    seed: int,
) -> str:
    """Stable identity: the same configuration always produces the same id."""
    return "EXP-" + config_digest(
        {
            "dataset": f"{dataset.name}@{dataset.version}",
            "datasetFingerprint": dataset.fingerprint(),
            "split": plan.strategy,
            "splitFingerprint": plan.fingerprint(),
            "detector": _stable_detector_description(detector_description),
            "objective": objective,
            "seed": seed,
            "featureSchema": FEATURE_SCHEMA_VERSION,
            "resultSchema": RESULT_SCHEMA_VERSION,
        }
    )


def run_experiment(
    *,
    dataset: EvaluationDataset,
    plan: SplitPlan,
    spec: DetectorSpec,
    features: dict[str, tuple[float, ...]],
    objective: str = DEFAULT_OBJECTIVE,
    seed: int = 1337,
) -> ExperimentResult:
    """Fit, select a threshold on validation, then evaluate test exactly once."""
    started = time.perf_counter()
    notes: list[str] = list(spec.notes)

    spec.detector.fit(plan.train.samples, features)

    validation_metrics: SplitMetrics | None = None
    sweep: list[ThresholdSweepPoint] = []

    if spec.sweeps_threshold:
        if not plan.validation.samples:
            raise ExperimentError(
                "threshold selection requires a validation split, and this plan has none"
            )
        # Score validation once, then sweep the precomputed scores.
        _, validation_scores, validation_labels = _evaluate_split(
            spec, plan.validation, features, spec.fixed_threshold
        )
        sweep = _sweep(validation_scores, validation_labels, spec.threshold_grid)
        threshold, selection = select_threshold(sweep, objective=objective)
        validation_metrics, _, _ = _evaluate_split(spec, plan.validation, features, threshold)
    else:
        threshold = spec.fixed_threshold
        selection = {
            "method": "not applicable",
            "objective": None,
            "chosenThreshold": threshold,
            "note": (
                f"{spec.detector.name} emits '{spec.detector.score_kind}'. There is no "
                "threshold to choose, and none was."
            ),
        }
        if plan.validation.samples:
            validation_metrics, _, _ = _evaluate_split(
                spec, plan.validation, features, threshold
            )

    # The one and only look at the test split.
    test_metrics, _, _ = _evaluate_split(spec, plan.test, features, threshold)

    description = spec.detector.describe()
    result = ExperimentResult(
        experiment_id=experiment_id(
            dataset=dataset,
            plan=plan,
            detector_description=description,
            objective=objective,
            seed=seed,
        ),
        detector=description,
        dataset=dataset.describe(),
        split=plan.to_dict(),
        threshold=threshold,
        threshold_selection=selection,
        validation=validation_metrics,
        test=test_metrics,
        sweep=sweep,
        environment=environment_metadata(),
        notes=notes,
    )
    logger.info(
        "%s %s: test F1=%s precision=%s recall=%s (%.1fs)",
        result.experiment_id,
        spec.detector.name,
        test_metrics.confusion.f1,
        test_metrics.confusion.precision,
        test_metrics.confusion.recall,
        time.perf_counter() - started,
    )
    return result


def splits_summary(plan: SplitPlan) -> dict[str, Any]:
    return {name: plan.splits()[name].to_dict() for name in (TRAIN, VALIDATION, TEST)}
