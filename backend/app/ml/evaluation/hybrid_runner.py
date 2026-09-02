"""Rule-only vs ML-only vs hybrid evaluation.

V2 measured the deterministic rules against a labelled dataset. V3 adds a
second detector, and the only question worth asking about it is: **does it
catch anything the rules do not, and what does that cost in false positives?**

Three configurations are run over the same labelled samples, in the same order,
so the numbers are directly comparable:

``rules``
    A sample counts as detected when at least one rule fires. Identical to the
    V2 measurement.

``ml``
    A sample counts as detected when its anomaly score is at or above the
    threshold. The rules do not participate.

``hybrid``
    Detected when either fires - which is what the running platform does.

Honesty constraints this runner holds to
----------------------------------------

**The model is not retrained on this dataset.** It is loaded exactly as the
running system loads it, from the registry. Fitting on the evaluation data
would make every number here meaningless.

**Behavioural features are cold.** The anomaly detector's most useful features
describe how an entity behaves *over time*, and the labelled dataset is a set
of independent samples with no shared history. The evaluation replays them
chronologically through one context, but this still understates what the model
can do on a live stream - and, more importantly, the dataset was written to
exercise rule thresholds, not to contain statistically novel behaviour. Any
ML recall figure here is a lower bound on a dataset that was never designed to
test it. That caveat is emitted with every report, and it is the reason the
report refuses to declare a winner.

**No number is invented.** If no model is registered, the report says so and
the ML and hybrid sections are omitted rather than filled with zeroes that read
like measurements.
"""

from __future__ import annotations

import platform
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from app.detection import COVERED_LABELS, evaluate
from app.evaluation.datasets.labeled_dataset import Dataset
from app.evaluation.labels import Label
from app.evaluation.metrics import (
    MIN_SAMPLES_OVERALL,
    ClassResult,
    ConfusionMatrix,
    LatencyStats,
)
from app.evaluation.runners.detection_runner import ruleset_fingerprint
from app.ml.features import FeatureExtractor
from app.ml.models.isolation_forest import IsolationForestDetector, ModelUnavailable
from app.ml.registry import registry
from app.ml.schemas import FEATURE_SCHEMA_VERSION

REPORT_SCHEMA_VERSION = "1.0"

CAVEATS = [
    (
        "The labelled dataset was built to exercise deterministic rule thresholds, "
        "not to contain statistically novel behaviour. ML recall measured on it is a "
        "lower bound and must not be quoted as the model's detection rate."
    ),
    (
        "The anomaly model's behavioural features describe how an entity acts over "
        "time. The dataset is a set of independent samples with no shared history, so "
        "those features are close to constant here and contribute little."
    ),
    (
        "The model is loaded from the registry exactly as the running system loads it. "
        "It is never fitted on this dataset."
    ),
    (
        "Anomaly scores are rankings, not probabilities. Precision and recall below "
        "are computed against a fixed threshold, and both move if the threshold moves."
    ),
]


@dataclass
class ConfigurationResult:
    """Metrics for one detection configuration over the whole dataset."""

    name: str
    description: str
    overall: ConfusionMatrix
    per_class: list[ClassResult] = field(default_factory=list)
    latency: LatencyStats | None = None
    alerts: int = 0
    #: Malicious samples this configuration caught that the rules alone missed.
    unique_detections: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "overall": self.overall.to_dict(),
            "perClass": [result.to_dict() for result in self.per_class],
            "latency": self.latency.to_dict() if self.latency else None,
            "alerts": self.alerts,
            "uniqueDetectionsVsRules": self.unique_detections[:25],
            "uniqueDetectionCount": len(self.unique_detections),
        }


@dataclass
class HybridReport:
    generated_at: str
    dataset: dict[str, Any]
    engine: dict[str, Any]
    model: dict[str, Any] | None
    configurations: list[ConfigurationResult]
    threshold: float
    score_summary: dict[str, Any]
    notes: list[str] = field(default_factory=list)
    environment: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schemaVersion": REPORT_SCHEMA_VERSION,
            "generatedAt": self.generated_at,
            "dataset": self.dataset,
            "engine": self.engine,
            "model": self.model,
            "threshold": self.threshold,
            "scoreSummary": self.score_summary,
            "configurations": [config.to_dict() for config in self.configurations],
            "notes": self.notes,
            "environment": self.environment,
        }

    def to_text(self) -> str:  # noqa: C901 - one flat report renderer
        lines: list[str] = []
        add = lines.append

        def pct(value: float | None) -> str:
            return "n/a" if value is None else f"{value * 100:.1f}%"

        add("=" * 76)
        add("AEGISX hybrid detection evaluation (rules vs ML vs both)")
        add("=" * 76)
        add(f"Generated      : {self.generated_at}")
        add(
            f"Dataset        : {self.dataset['name']} v{self.dataset['version']} "
            f"seed={self.dataset['seed']} fingerprint={self.dataset['fingerprint']}"
        )
        add(
            f"Ruleset        : {self.engine['ruleCount']} rules "
            f"fingerprint={self.engine['fingerprint']}"
        )
        if self.model:
            add(
                f"Model          : {self.model['identity']} "
                f"(feature schema v{self.model['featureSchemaVersion']}, "
                f"trained on {self.model['datasetVersion']})"
            )
            add(f"Threshold      : {self.threshold}")
        else:
            add("Model          : NONE REGISTERED - ML and hybrid rows omitted")
        add("")

        add("-- Comparison " + "-" * 61)
        add(
            f"{'configuration':<12}{'TP':>6}{'FP':>6}{'FN':>6}"
            f"{'precision':>11}{'recall':>9}{'F1':>8}{'FPR':>8}{'FNR':>8}"
        )
        for config in self.configurations:
            matrix = config.overall
            add(
                f"{config.name:<12}{matrix.true_positives:>6}{matrix.false_positives:>6}"
                f"{matrix.false_negatives:>6}{pct(matrix.precision):>11}"
                f"{pct(matrix.recall):>9}{pct(matrix.f1):>8}"
                f"{pct(matrix.false_positive_rate):>8}{pct(matrix.false_negative_rate):>8}"
            )
        add("")

        if self.model:
            add("-- What ML added over the rules " + "-" * 43)
            hybrid = next((c for c in self.configurations if c.name == "hybrid"), None)
            ml = next((c for c in self.configurations if c.name == "ml"), None)
            rules = next((c for c in self.configurations if c.name == "rules"), None)
            if hybrid and rules and ml:
                extra_tp = hybrid.overall.true_positives - rules.overall.true_positives
                extra_fp = hybrid.overall.false_positives - rules.overall.false_positives
                add(f"Additional true positives  : {extra_tp}")
                add(f"Additional false positives : {extra_fp}")
                if extra_tp == 0:
                    add(
                        "  -> On THIS dataset the model caught nothing the rules missed. "
                        "See the caveats: the dataset was not built to contain novelty."
                    )
                if ml.unique_detections:
                    add(f"Caught only by ML          : {', '.join(ml.unique_detections[:8])}")
            add("")

            add("-- Anomaly score distribution " + "-" * 45)
            summary = self.score_summary
            add(
                f"min {summary['min']}  p50 {summary['p50']}  p90 {summary['p90']}  "
                f"p95 {summary['p95']}  p99 {summary['p99']}  max {summary['max']}"
            )
            add(
                f"malicious mean {summary['maliciousMean']}   "
                f"benign mean {summary['benignMean']}   "
                f"separation {summary['separation']}"
            )
            add("")

        add("-- Per class detection rate " + "-" * 47)
        header = f"{'label':<24}{'n':>5}"
        for config in self.configurations:
            header += f"{config.name:>10}"
        add(header + "  covered by rules")
        by_label: dict[str, dict[str, ClassResult]] = {}
        for config in self.configurations:
            for result in config.per_class:
                by_label.setdefault(result.label, {})[config.name] = result
        for label in sorted(by_label):
            first = next(iter(by_label[label].values()))
            row = f"{label:<24}{first.total:>5}"
            for config in self.configurations:
                result = by_label[label].get(config.name)
                row += f"{pct(result.detection_rate) if result else 'n/a':>10}"
            add(row + f"  {'yes' if first.covered_by_rules else 'NO RULE'}")
        add("")

        add("-- Caveats " + "-" * 64)
        for note in self.notes:
            add(f"  - {note}")
        add("=" * 76)
        return "\n".join(lines)


def _percentile(values: list[float], percentile: int) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    index = min(int(len(ordered) * percentile / 100), len(ordered) - 1)
    return round(ordered[index], 4)


def _class_result(label: str) -> ClassResult:
    return ClassResult(
        label=label,
        covered_by_rules=(label in COVERED_LABELS) or label == Label.BENIGN.value,
    )


def load_registered_model(db) -> tuple[IsolationForestDetector | None, dict | None, str | None]:  # noqa: ANN001
    """Load the active model exactly as the running system does."""
    record = registry.get_active(db, "isolation_forest")
    if record is None:
        return None, None, (
            "No active anomaly model is registered. Train one with "
            "`python -m app.ml.training.train_anomaly_model`."
        )
    try:
        detector = IsolationForestDetector.load(
            Path(record.artifact_path), expected_sha256=record.artifact_sha256
        )
    except ModelUnavailable as exc:
        return None, registry.to_dict(record), str(exc)

    if detector.feature_schema_version != FEATURE_SCHEMA_VERSION:
        return None, registry.to_dict(record), (
            f"{record.identity} speaks feature schema {detector.feature_schema_version}, "
            f"this build produces {FEATURE_SCHEMA_VERSION}."
        )
    return detector, registry.to_dict(record), None


def run_hybrid_evaluation(
    dataset: Dataset,
    detector: IsolationForestDetector | None,
    model_info: dict | None,
    *,
    threshold: float,
    unavailable_reason: str | None = None,
) -> HybridReport:
    """Evaluate rules, ML and both over one labelled dataset."""
    configs: dict[str, ConfigurationResult] = {
        "rules": ConfigurationResult(
            name="rules",
            description="At least one deterministic rule fired (the V2 measurement).",
            overall=ConfusionMatrix(),
        )
    }
    if detector is not None:
        configs["ml"] = ConfigurationResult(
            name="ml",
            description="Anomaly score at or above the threshold. Rules not consulted.",
            overall=ConfusionMatrix(),
        )
        configs["hybrid"] = ConfigurationResult(
            name="hybrid",
            description="Either a rule fired or the score crossed the threshold.",
            overall=ConfusionMatrix(),
        )

    per_class: dict[str, dict[str, ClassResult]] = {name: {} for name in configs}

    # One extractor, replayed chronologically, so the behavioural context builds
    # up the same way it does during ingestion.
    extractor = FeatureExtractor()
    samples = sorted(
        dataset.samples, key=lambda item: item.candidate.get("timestamp") or datetime.min
    )

    rule_latencies: list[float] = []
    ml_latencies: list[float] = []
    scores: list[float] = []
    malicious_scores: list[float] = []
    benign_scores: list[float] = []
    rule_detected_ids: set[str] = set()
    ml_detected_ids: set[str] = set()

    from time import perf_counter

    for sample in samples:
        label = sample.label.value
        candidate = sample.candidate

        result = evaluate(candidate, base_severity=candidate.get("severity", "Low"))
        rule_latencies.append(result.duration_ms)
        rule_hit = result.matched
        if rule_hit:
            rule_detected_ids.add(sample.id)

        ml_hit = False
        if detector is not None:
            started = perf_counter()
            vector = extractor.extract(candidate, observe=True)
            score = detector.anomaly_score(vector.values)
            ml_latencies.append((perf_counter() - started) * 1000.0)
            scores.append(score)
            (malicious_scores if sample.is_malicious else benign_scores).append(score)
            ml_hit = score >= threshold
            if ml_hit:
                ml_detected_ids.add(sample.id)
        else:
            extractor.observe(candidate)

        outcomes = {"rules": rule_hit}
        if detector is not None:
            outcomes["ml"] = ml_hit
            outcomes["hybrid"] = rule_hit or ml_hit

        for name, detected in outcomes.items():
            config = configs[name]
            config.overall.record(is_malicious=sample.is_malicious, detected=detected)
            if detected:
                config.alerts += 1
            entry = per_class[name].setdefault(label, _class_result(label))
            entry.total += 1
            if detected:
                entry.detected += 1
            else:
                entry.missed += 1

    for name, config in configs.items():
        config.per_class = sorted(per_class[name].values(), key=lambda item: item.label)

    configs["rules"].latency = LatencyStats.from_samples(rule_latencies)
    if detector is not None:
        configs["ml"].latency = LatencyStats.from_samples(ml_latencies)
        configs["hybrid"].latency = LatencyStats.from_samples(
            [r + m for r, m in zip(rule_latencies, ml_latencies, strict=False)]
        )
        # Malicious samples the model caught and the rules did not: the only
        # thing that justifies adding a second detector.
        malicious_ids = {s.id for s in samples if s.is_malicious}
        configs["ml"].unique_detections = sorted(
            (ml_detected_ids & malicious_ids) - rule_detected_ids
        )
        configs["hybrid"].unique_detections = configs["ml"].unique_detections

    notes = list(CAVEATS)
    if unavailable_reason:
        notes.insert(0, unavailable_reason)
    if configs["rules"].overall.total < MIN_SAMPLES_OVERALL:
        notes.append(
            f"Fewer than {MIN_SAMPLES_OVERALL} samples were evaluated; treat every "
            "figure as indicative only."
        )

    def mean(values: list[float]) -> float:
        return round(sum(values) / len(values), 4) if values else 0.0

    score_summary = {
        "count": len(scores),
        "min": round(min(scores), 4) if scores else None,
        "p50": _percentile(scores, 50),
        "p90": _percentile(scores, 90),
        "p95": _percentile(scores, 95),
        "p99": _percentile(scores, 99),
        "max": round(max(scores), 4) if scores else None,
        "maliciousMean": mean(malicious_scores),
        "benignMean": mean(benign_scores),
        # Positive means malicious samples score higher than benign ones. Near
        # zero means the model is not separating the two on this data.
        "separation": round(mean(malicious_scores) - mean(benign_scores), 4),
    }

    return HybridReport(
        generated_at=datetime.now(timezone.utc).isoformat(),
        dataset={
            "name": dataset.name,
            "version": dataset.version,
            "seed": dataset.seed,
            "fingerprint": dataset.fingerprint(),
            "totalEvents": len(dataset.samples),
            "maliciousEvents": dataset.malicious_count,
            "benignEvents": dataset.benign_count,
            "classCounts": dataset.class_counts(),
        },
        engine={
            "type": "hybrid",
            "ruleCount": len(COVERED_LABELS),
            "fingerprint": ruleset_fingerprint(),
        },
        model=model_info,
        configurations=[configs[name] for name in ("rules", "ml", "hybrid") if name in configs],
        threshold=threshold,
        score_summary=score_summary,
        notes=notes,
        environment={
            "python": sys.version.split()[0],
            "platform": platform.platform(),
        },
    )
