"""Detection evaluation framework tests.

These cover the measurement machinery itself: if the metrics are wrong, every
number reported downstream is wrong in the same direction and nobody notices.
"""

from __future__ import annotations

import json

import pytest

from app.evaluation.datasets import build_dataset
from app.evaluation.labels import MALICIOUS_LABELS, Label
from app.evaluation.metrics import ClassResult, ConfusionMatrix, LatencyStats, safe_ratio
from app.evaluation.reports.store import list_reports, load_latest, write_report
from app.evaluation.run_detection_eval import main as run_cli
from app.evaluation.runners.detection_runner import (
    ruleset_fingerprint,
    run_detection_evaluation,
)


# --------------------------------------------------------------------- metrics
def test_confusion_matrix_formulas() -> None:
    matrix = ConfusionMatrix(
        true_positives=80, false_positives=10, true_negatives=150, false_negatives=20
    )
    assert matrix.precision == pytest.approx(80 / 90)
    assert matrix.recall == pytest.approx(80 / 100)
    assert matrix.f1 == pytest.approx(2 * (80 / 90) * 0.8 / ((80 / 90) + 0.8))
    assert matrix.false_positive_rate == pytest.approx(10 / 160)
    assert matrix.false_negative_rate == pytest.approx(20 / 100)
    assert matrix.specificity == pytest.approx(150 / 160)
    assert matrix.accuracy == pytest.approx(230 / 260)


def test_undefined_rates_are_none_not_zero() -> None:
    """'No data' and 'zero' must not look the same on a dashboard."""
    empty = ConfusionMatrix()
    assert empty.precision is None
    assert empty.recall is None
    assert empty.f1 is None
    assert empty.false_positive_rate is None
    assert safe_ratio(1, 0) is None


def test_small_samples_are_flagged_as_insufficient() -> None:
    matrix = ConfusionMatrix(true_positives=5, false_negatives=1)
    assert matrix.sufficient_data is False
    assert ClassResult(label="BRUTE_FORCE", total=3).sufficient_data is False
    assert ClassResult(label="BRUTE_FORCE", total=40).sufficient_data is True


def test_confusion_matrix_records_each_quadrant() -> None:
    matrix = ConfusionMatrix()
    matrix.record(is_malicious=True, detected=True)
    matrix.record(is_malicious=True, detected=False)
    matrix.record(is_malicious=False, detected=True)
    matrix.record(is_malicious=False, detected=False)
    assert (matrix.true_positives, matrix.false_negatives) == (1, 1)
    assert (matrix.false_positives, matrix.true_negatives) == (1, 1)


def test_latency_percentiles() -> None:
    stats = LatencyStats.from_samples([1.0, 2.0, 3.0, 4.0, 100.0])
    assert stats.count == 5
    assert stats.p50_ms == 3.0
    assert stats.max_ms == 100.0
    assert stats.events_per_second > 0
    assert LatencyStats.from_samples([]).count == 0


# --------------------------------------------------------------------- dataset
def test_dataset_is_deterministic_for_a_seed() -> None:
    first = build_dataset(seed=99, samples_per_class=5)
    second = build_dataset(seed=99, samples_per_class=5)
    assert first.fingerprint() == second.fingerprint()
    assert [s.label for s in first.samples] == [s.label for s in second.samples]


def test_different_seeds_produce_different_data() -> None:
    assert (
        build_dataset(seed=1, samples_per_class=5).fingerprint()
        != build_dataset(seed=2, samples_per_class=5).fingerprint()
    )


def test_dataset_covers_every_label_and_is_benign_heavy() -> None:
    dataset = build_dataset(samples_per_class=10)
    counts = dataset.class_counts()

    for label in MALICIOUS_LABELS:
        assert counts.get(label.value, 0) == 10, f"missing samples for {label.value}"

    assert counts[Label.BENIGN.value] > dataset.malicious_count, (
        "a benign-heavy mix is what makes precision and FPR meaningful"
    )


def test_every_sample_is_normalized_through_the_real_pipeline() -> None:
    dataset = build_dataset(samples_per_class=3)
    for sample in dataset.samples:
        assert sample.candidate, "samples must be normalized"
        assert sample.candidate["source"] == sample.record.source
        assert sample.candidate["event_type"]
        assert sample.note


def test_ground_truth_is_independent_of_the_engine() -> None:
    dataset = build_dataset(samples_per_class=3)
    for sample in dataset.samples:
        assert sample.label.is_malicious == (sample.label is not Label.BENIGN)


# ---------------------------------------------------------------------- runner
@pytest.fixture(scope="module")
def report():
    return run_detection_evaluation(build_dataset(samples_per_class=20))


def test_report_counts_add_up(report) -> None:
    overall = report.overall
    assert overall.total == report.volume["eventsProcessed"]
    assert overall.actual_positives == report.volume["maliciousEvents"]
    assert overall.actual_negatives == report.volume["benignEvents"]
    assert overall.predicted_positives == report.volume["alertsGenerated"]


def test_engine_detects_the_classes_it_claims_to_cover(report) -> None:
    by_label = {result.label: result for result in report.per_class}
    for label in ("BRUTE_FORCE", "SUSPICIOUS_POWERSHELL", "CREDENTIAL_ACCESS", "RANSOMWARE"):
        assert by_label[label].detection_rate == 1.0, f"{label} should be fully detected"


def test_uncovered_class_is_reported_as_a_blind_spot(report) -> None:
    """LATERAL_MOVEMENT has no rule; the report must say so rather than hide it."""
    assert "LATERAL_MOVEMENT" in report.coverage["uncoveredLabels"]

    lateral = next(r for r in report.per_class if r.label == "LATERAL_MOVEMENT")
    assert lateral.covered_by_rules is False
    assert lateral.detected == 0
    assert report.overall.false_negatives >= lateral.total


def test_false_positives_are_measured_not_assumed_zero(report) -> None:
    """The benign set contains cases the rules genuinely misfire on."""
    assert report.overall.false_positives > 0
    assert report.overall.false_positive_rate is not None
    benign = next(r for r in report.per_class if r.label == "BENIGN")
    assert benign.detected == report.overall.false_positives


def test_rule_attribution_is_tracked(report) -> None:
    by_rule = {result.rule_id: result for result in report.per_rule}
    powershell = by_rule["DET-PS-001"]
    assert powershell.fires > 0
    assert powershell.correct_class == powershell.on_malicious

    lolbin = by_rule["DET-EXEC-002"]
    assert lolbin.on_benign > 0, "admin certutil usage is an expected false positive"
    assert lolbin.rule_precision is not None and lolbin.rule_precision < 1.0


def test_latency_and_fingerprints_are_reported(report) -> None:
    payload = report.to_dict()
    assert payload["latency"]["samples"] == payload["volume"]["eventsProcessed"]
    assert payload["latency"]["meanMs"] >= 0
    assert payload["engine"]["fingerprint"] == ruleset_fingerprint()
    assert payload["engine"]["type"] == "deterministic-rules"
    assert payload["dataset"]["fingerprint"]


def test_report_is_json_serializable_and_readable(report) -> None:
    payload = report.to_dict()
    assert json.loads(json.dumps(payload))["schemaVersion"] == "1.0"

    text = report.to_text()
    assert "Precision" in text and "False positive rate" in text
    assert "no ML" in text


# ------------------------------------------------------------------- reporting
def test_reports_are_written_and_read_back(tmp_path) -> None:
    report = run_detection_evaluation(build_dataset(samples_per_class=2))
    detailed, latest = write_report(report.to_dict(), tmp_path)

    assert detailed.exists() and latest.exists()
    assert list_reports(tmp_path) == [detailed.name]

    loaded = load_latest(tmp_path)
    assert loaded is not None
    assert loaded["engine"]["ruleCount"] == report.engine["ruleCount"]


def test_missing_report_returns_none_rather_than_fake_data(tmp_path) -> None:
    assert load_latest(tmp_path / "nothing") is None


# ------------------------------------------------------------------------- CLI
def test_cli_writes_a_report(tmp_path) -> None:
    exit_code = run_cli(["--samples-per-class", "2", "--output-dir", str(tmp_path), "--quiet"])
    assert exit_code == 0
    assert load_latest(tmp_path) is not None


def test_cli_gate_fails_on_an_impossible_threshold(tmp_path, capsys) -> None:
    exit_code = run_cli(
        [
            "--samples-per-class",
            "2",
            "--output-dir",
            str(tmp_path),
            "--quiet",
            "--fail-under-f1",
            "1.01",
        ]
    )
    assert exit_code == 1
    assert "FAIL" in capsys.readouterr().err


def test_cli_gate_passes_on_a_reachable_threshold(tmp_path) -> None:
    assert (
        run_cli(
            [
                "--samples-per-class",
                "5",
                "--output-dir",
                str(tmp_path),
                "--quiet",
                "--fail-under-f1",
                "0.5",
                "--fail-over-fpr",
                "0.5",
            ]
        )
        == 0
    )
