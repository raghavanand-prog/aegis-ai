"""Detection evaluation runner.

Pushes every labelled sample through the production detection engine and
compares what fired against the ground-truth label.

    labelled sample -> normalizer -> detection engine -> compare to label

Nothing here is tuned to make the numbers look good: the engine is called
exactly as the ingestion pipeline calls it, and a sample counts as "detected"
when at least one rule fires - the same condition that raises an alert in
production.
"""

from __future__ import annotations

import hashlib
import platform
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from app.detection import COVERED_LABELS, RULES, evaluate
from app.evaluation.datasets.labeled_dataset import Dataset
from app.evaluation.labels import Label
from app.evaluation.metrics import (
    MIN_SAMPLES_OVERALL,
    MIN_SAMPLES_PER_CLASS,
    ClassResult,
    ConfusionMatrix,
    LatencyStats,
    RuleResult,
)
from app.models.enums import Severity

REPORT_SCHEMA_VERSION = "1.0"

#: Severities that would raise a notification and therefore become an incident
#: candidate in the running system.
INCIDENT_SEVERITIES = {Severity.HIGH.value, Severity.CRITICAL.value}


def ruleset_fingerprint() -> str:
    """Hash of rule identities, versions and risk weights.

    Two reports with the same dataset fingerprint but different ruleset
    fingerprints are measuring different engines - which is exactly what you
    want to know when a metric moves.
    """
    digest = hashlib.sha256()
    for rule in RULES:
        digest.update(
            f"{rule.id}:{rule.version}:{rule.severity.value}:{rule.risk}:"
            f"{','.join(rule.mitre)}".encode()
        )
    return digest.hexdigest()[:16]


@dataclass
class EvaluationReport:
    generated_at: str
    dataset: dict[str, Any]
    engine: dict[str, Any]
    overall: ConfusionMatrix
    per_class: list[ClassResult]
    per_rule: list[RuleResult]
    latency: LatencyStats
    volume: dict[str, int]
    coverage: dict[str, Any]
    environment: dict[str, str]
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schemaVersion": REPORT_SCHEMA_VERSION,
            "generatedAt": self.generated_at,
            "dataset": self.dataset,
            "engine": self.engine,
            "overall": self.overall.to_dict(),
            "perClass": [result.to_dict() for result in self.per_class],
            "perRule": [result.to_dict() for result in self.per_rule],
            "latency": self.latency.to_dict(),
            "volume": self.volume,
            "coverage": self.coverage,
            "environment": self.environment,
            "notes": self.notes,
        }

    def to_text(self) -> str:
        """Human readable summary for the terminal and CI logs."""
        overall = self.overall
        lines: list[str] = []
        add = lines.append

        def pct(value: float | None) -> str:
            return "n/a" if value is None else f"{value * 100:.1f}%"

        add("=" * 72)
        add("AEGISX detection engine evaluation (deterministic rules, no ML)")
        add("=" * 72)
        add(f"Generated      : {self.generated_at}")
        add(
            f"Dataset        : {self.dataset['name']} v{self.dataset['version']} "
            f"seed={self.dataset['seed']} fingerprint={self.dataset['fingerprint']}"
        )
        add(
            f"Ruleset        : {self.engine['ruleCount']} rules "
            f"fingerprint={self.engine['fingerprint']}"
        )
        add("")
        add("-- Volume " + "-" * 62)
        add(f"Events evaluated      : {self.volume['eventsProcessed']}")
        add(f"  malicious           : {self.volume['maliciousEvents']}")
        add(f"  benign              : {self.volume['benignEvents']}")
        add(f"Alerts generated      : {self.volume['alertsGenerated']}")
        add(f"Detections fired      : {self.volume['detectionsTotal']}")
        add(f"Incident candidates   : {self.volume['incidentCandidates']} (High/Critical)")
        add("")
        add("-- Overall (flagged vs not flagged) " + "-" * 36)
        add(
            f"TP {overall.true_positives:<6} FP {overall.false_positives:<6} "
            f"TN {overall.true_negatives:<6} FN {overall.false_negatives:<6}"
        )
        add(f"Precision             : {pct(overall.precision)}")
        add(f"Recall                : {pct(overall.recall)}")
        add(f"F1 score              : {pct(overall.f1)}")
        add(f"False positive rate   : {pct(overall.false_positive_rate)}")
        add(f"False negative rate   : {pct(overall.false_negative_rate)}")
        add(f"Accuracy              : {pct(overall.accuracy)}")
        if not overall.sufficient_data:
            add(f"WARNING: fewer than {MIN_SAMPLES_OVERALL} samples - treat these as indicative only")
        add("")
        add("-- Per class " + "-" * 59)
        add(f"{'label':<24}{'n':>6}{'detected':>10}{'rate':>10}  covered")
        for result in self.per_class:
            covered = "yes" if result.covered_by_rules else "NO RULE"
            flag = "" if result.sufficient_data else "  (low n)"
            add(
                f"{result.label:<24}{result.total:>6}{result.detected:>10}"
                f"{pct(result.detection_rate):>10}  {covered}{flag}"
            )
        add("")
        add("-- Per rule " + "-" * 60)
        add(f"{'rule':<16}{'fires':>7}{'malicious':>11}{'benign':>8}{'precision':>11}  name")
        for result in self.per_rule:
            add(
                f"{result.rule_id:<16}{result.fires:>7}{result.on_malicious:>11}"
                f"{result.on_benign:>8}{pct(result.rule_precision):>11}  {result.rule_name}"
            )
        add("")
        add("-- Latency (detection engine only) " + "-" * 37)
        latency = self.latency.to_dict()
        add(
            f"mean {latency['meanMs']}ms  p50 {latency['p50Ms']}ms  p95 {latency['p95Ms']}ms  "
            f"p99 {latency['p99Ms']}ms  max {latency['maxMs']}ms"
        )
        add(f"throughput            : {latency['eventsPerSecond']} events/sec (single process)")
        if self.coverage["uncoveredLabels"]:
            add("")
            add("-- Known blind spots " + "-" * 51)
            for label in self.coverage["uncoveredLabels"]:
                add(f"  {label}: no rule targets this class; every sample is a false negative")
        if self.notes:
            add("")
            add("-- Notes " + "-" * 63)
            for note in self.notes:
                add(f"  - {note}")
        add("=" * 72)
        return "\n".join(lines)


def run_detection_evaluation(dataset: Dataset) -> EvaluationReport:
    """Evaluate the current detection engine against a labelled dataset."""
    overall = ConfusionMatrix()
    per_class: dict[str, ClassResult] = {}
    per_rule: dict[str, RuleResult] = {
        rule.id: RuleResult(rule_id=rule.id, rule_version=rule.version, rule_name=rule.name)
        for rule in RULES
    }
    rule_labels = {rule.id: set(rule.labels) for rule in RULES}

    latencies: list[float] = []
    detections_total = 0
    alerts = 0
    incident_candidates = 0

    for sample in dataset.samples:
        label = sample.label.value
        result = evaluate(sample.candidate, base_severity=sample.candidate.get("severity", "Low"))
        latencies.append(result.duration_ms)

        detected = result.matched
        overall.record(is_malicious=sample.is_malicious, detected=detected)

        entry = per_class.setdefault(
            label,
            ClassResult(
                label=label,
                covered_by_rules=(label in COVERED_LABELS) or label == Label.BENIGN.value,
            ),
        )
        entry.total += 1
        if detected:
            entry.detected += 1
            alerts += 1
        else:
            entry.missed += 1

        detections_total += len(result.detections)
        if detected and result.severity in INCIDENT_SEVERITIES:
            incident_candidates += 1

        for detection in result.detections:
            rule_id = detection.rule_id
            entry.rule_hits[rule_id] = entry.rule_hits.get(rule_id, 0) + 1

            rule_result = per_rule[rule_id]
            rule_result.fires += 1
            if sample.is_malicious:
                rule_result.on_malicious += 1
                if label in rule_labels.get(rule_id, set()):
                    rule_result.correct_class += 1
                else:
                    rule_result.wrong_class += 1
            else:
                rule_result.on_benign += 1

    dataset_labels = set(per_class)
    uncovered = sorted(
        label
        for label in dataset_labels
        if label != Label.BENIGN.value and label not in COVERED_LABELS
    )

    notes = [
        "Ground truth comes from the dataset generator, never from the engine's own output.",
        "A sample counts as detected when at least one rule fires - the same condition that "
        "raises an alert in production.",
        "Benign samples deliberately include near-threshold and awkward cases "
        "(admin certutil, backup transfers), so the false positive rate is not flattered.",
        "These are metrics for deterministic rules. No model, no training, no learning.",
    ]
    if uncovered:
        notes.append(
            "Classes without a matching rule are included on purpose so recall reflects the "
            "engine's real coverage."
        )

    return EvaluationReport(
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
            "generator": "app.evaluation.datasets.labeled_dataset.build_dataset",
        },
        engine={
            "type": "deterministic-rules",
            "ruleCount": len(RULES),
            "fingerprint": ruleset_fingerprint(),
            "rules": [
                {"id": rule.id, "version": rule.version, "legacyId": rule.legacy_id}
                for rule in RULES
            ],
        },
        overall=overall,
        per_class=[per_class[key] for key in sorted(per_class)],
        per_rule=[per_rule[key] for key in sorted(per_rule)],
        latency=LatencyStats.from_samples(latencies),
        volume={
            "eventsProcessed": len(dataset.samples),
            "maliciousEvents": dataset.malicious_count,
            "benignEvents": dataset.benign_count,
            "alertsGenerated": alerts,
            "detectionsTotal": detections_total,
            "incidentCandidates": incident_candidates,
        },
        coverage={
            "coveredLabels": sorted(COVERED_LABELS),
            "uncoveredLabels": uncovered,
            "minSamplesOverall": MIN_SAMPLES_OVERALL,
            "minSamplesPerClass": MIN_SAMPLES_PER_CLASS,
        },
        environment={
            "python": sys.version.split()[0],
            "platform": platform.platform(),
        },
        notes=notes,
    )
