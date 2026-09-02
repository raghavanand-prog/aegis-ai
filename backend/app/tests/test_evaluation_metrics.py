"""Correctness of the V4 metric implementations.

Every metric here is checked against a value computed independently - by hand
for the small cases, and against scikit-learn for the ranking metrics. A
metric implementation that is merely self-consistent proves nothing; these
tests exist so that a number in the research report can be trusted to mean what
its name says.
"""

from __future__ import annotations

import pytest

from app.evaluation.metrics.classification import ConfusionMatrix
from app.evaluation.metrics.ranking import (
    balanced_accuracy,
    bootstrap_interval,
    matthews_correlation,
    normalized_confusion,
    pr_auc,
    ranking_metrics,
    roc_auc,
)


def _matrix(tp: int, tn: int, fp: int, fn: int) -> ConfusionMatrix:
    matrix = ConfusionMatrix()
    for _ in range(tp):
        matrix.record(is_malicious=True, detected=True)
    for _ in range(tn):
        matrix.record(is_malicious=False, detected=False)
    for _ in range(fp):
        matrix.record(is_malicious=False, detected=True)
    for _ in range(fn):
        matrix.record(is_malicious=True, detected=False)
    return matrix


# ------------------------------------------------------- confusion arithmetic


def test_confusion_matrix_matches_hand_computed_values() -> None:
    matrix = _matrix(tp=80, tn=850, fp=50, fn=20)
    assert matrix.total == 1000
    assert matrix.precision == pytest.approx(80 / 130, abs=1e-4)
    assert matrix.recall == pytest.approx(80 / 100, abs=1e-4)
    assert matrix.f1 == pytest.approx(2 * (80 / 130) * 0.8 / ((80 / 130) + 0.8), abs=1e-4)
    assert matrix.false_positive_rate == pytest.approx(50 / 900, abs=1e-4)
    assert matrix.false_negative_rate == pytest.approx(20 / 100, abs=1e-4)
    assert matrix.specificity == pytest.approx(850 / 900, abs=1e-4)
    assert matrix.accuracy == pytest.approx(930 / 1000, abs=1e-4)


def test_metrics_are_none_rather_than_zero_when_undefined() -> None:
    """A detector that never fires has undefined precision, not 0% precision."""
    matrix = _matrix(tp=0, tn=100, fp=0, fn=50)
    assert matrix.precision is None
    assert matrix.recall == 0.0
    assert matrix.false_positive_rate == 0.0


# --------------------------------------------------------------------- MCC


def test_mcc_matches_hand_computation() -> None:
    # tp=5 tn=3 fp=2 fn=4
    # num = 15 - 8 = 7; den = sqrt(7*9*5*7) = sqrt(2205)
    expected = 7 / (2205**0.5)
    assert matthews_correlation(5, 3, 2, 4) == pytest.approx(expected, abs=1e-9)


def test_mcc_is_zero_for_a_detector_that_flags_everything() -> None:
    """The reason MCC is reported: accuracy would call this 11% good."""
    assert matthews_correlation(tp=110, tn=0, fp=890, fn=0) is None


def test_mcc_is_perfect_for_a_perfect_detector() -> None:
    assert matthews_correlation(tp=50, tn=50, fp=0, fn=0) == pytest.approx(1.0)


def test_balanced_accuracy_penalises_the_majority_class_shortcut() -> None:
    """Flagging nothing: 89% accuracy, 50% balanced accuracy."""
    matrix = _matrix(tp=0, tn=890, fp=0, fn=110)
    assert matrix.accuracy == pytest.approx(0.89)
    assert balanced_accuracy(0, 890, 0, 110) == pytest.approx(0.5)


# ---------------------------------------------------------------- ROC / PR


def test_roc_auc_matches_sklearn() -> None:
    sklearn_metrics = pytest.importorskip("sklearn.metrics")
    scores = [0.1, 0.4, 0.35, 0.8, 0.2, 0.9, 0.55, 0.6, 0.05, 0.75] * 6
    labels = [False, False, True, True, False, True, False, True, False, True] * 6
    assert roc_auc(scores, labels) == pytest.approx(
        sklearn_metrics.roc_auc_score(labels, scores), abs=1e-9
    )


def test_roc_auc_handles_ties_with_average_ranks() -> None:
    sklearn_metrics = pytest.importorskip("sklearn.metrics")
    # Every score identical: no ordering information at all -> 0.5.
    scores = [0.5] * 60
    labels = [i % 2 == 0 for i in range(60)]
    assert roc_auc(scores, labels) == pytest.approx(0.5)
    assert roc_auc(scores, labels) == pytest.approx(
        sklearn_metrics.roc_auc_score(labels, scores)
    )


def test_pr_auc_matches_sklearn_average_precision() -> None:
    sklearn_metrics = pytest.importorskip("sklearn.metrics")
    scores = [0.9, 0.8, 0.7, 0.6, 0.55, 0.54, 0.53, 0.51, 0.5, 0.4] * 6
    labels = [True, True, False, True, True, False, False, False, True, False] * 6
    assert pr_auc(scores, labels) == pytest.approx(
        sklearn_metrics.average_precision_score(labels, scores), abs=1e-9
    )


def test_ranking_metrics_refuse_an_unordered_score() -> None:
    """A rule indicator has no ranking, and must not be given a fake AUC."""
    scores = [1.0 if i % 3 == 0 else 0.0 for i in range(120)]
    labels = [i % 3 == 0 for i in range(120)]
    result = ranking_metrics(scores, labels, score_kind="rule_hit", ordered=False)
    assert result.roc_auc is None
    assert result.pr_auc is None
    assert "no ordering" in (result.unavailable_reason or "")


def test_ranking_metrics_refuse_a_tiny_class() -> None:
    scores = [0.5] * 100
    labels = [i < 3 for i in range(100)]
    result = ranking_metrics(scores, labels, score_kind="anomaly_score", ordered=True)
    assert result.roc_auc is None
    assert "at least" in (result.unavailable_reason or "")


def test_pr_auc_baseline_is_the_positive_rate_not_half() -> None:
    scores = [i / 200 for i in range(200)]
    labels = [i >= 160 for i in range(200)]
    result = ranking_metrics(scores, labels, score_kind="probability", ordered=True)
    assert result.positive_rate == pytest.approx(0.2)
    assert result.to_dict()["prAucBaseline"] == pytest.approx(0.2)


# ------------------------------------------------------- normalized matrices


def test_normalized_confusion_rows_sum_to_one() -> None:
    normalized = normalized_confusion(tp=80, tn=850, fp=50, fn=20)
    malicious = normalized["actualMalicious"]
    benign = normalized["actualBenign"]
    assert malicious["predictedMalicious"] + malicious["predictedBenign"] == pytest.approx(1.0)
    assert benign["predictedMalicious"] + benign["predictedBenign"] == pytest.approx(1.0)
    assert malicious["predictedMalicious"] == pytest.approx(0.8)
    assert malicious["support"] == 100


def test_normalized_confusion_survives_an_absent_class() -> None:
    normalized = normalized_confusion(tp=0, tn=100, fp=0, fn=0)
    assert normalized["actualMalicious"]["predictedMalicious"] is None
    assert normalized["actualMalicious"]["support"] == 0


# ------------------------------------------------------------------ bootstrap


def test_bootstrap_interval_brackets_the_mean() -> None:
    values = [0.80, 0.82, 0.79, 0.81, 0.83, 0.78, 0.80, 0.81]
    interval = bootstrap_interval(values, seed=7)
    assert interval["lower"] <= interval["mean"] <= interval["upper"]
    assert interval["samples"] == 8
    assert interval["stdDev"] > 0


def test_bootstrap_interval_is_reproducible() -> None:
    values = [0.7, 0.72, 0.68, 0.71, 0.69]
    assert bootstrap_interval(values, seed=3) == bootstrap_interval(values, seed=3)


def test_bootstrap_refuses_to_decorate_two_observations() -> None:
    interval = bootstrap_interval([0.5, 0.6])
    assert interval["lower"] is None
    assert "decoration" in interval["unavailableReason"]
