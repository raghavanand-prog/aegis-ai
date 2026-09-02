"""Metrics that need a score, not just a verdict.

V3's :mod:`app.evaluation.metrics.classification` covers everything derivable
from a confusion matrix. This module adds the metrics that require an ordering
over samples, plus the two threshold-free summaries, and it is deliberately
strict about when they mean nothing:

* **ROC-AUC and PR-AUC need a ranking.** A binary rule indicator has none. Asked
  for one anyway, these functions return ``None`` rather than the 0.5 that a
  naive implementation reports - a number which looks like a measurement and is
  not one.
* **PR-AUC depends on class balance**, ROC-AUC does not. On an 11%-positive
  corpus the two tell different stories and both are reported.
* **MCC is reported because accuracy is misleading here.** A detector that flags
  nothing scores 89% accuracy on this corpus; MCC scores it 0.

Implemented directly rather than via scikit-learn's ``metrics`` module so the
computation is auditable in place, and so the evaluation package does not
depend on sklearn being importable to produce a report.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Any

#: Below this many samples of either class, ranking metrics are noise.
MIN_PER_CLASS = 20


def _rounded(value: float | None, digits: int = 4) -> float | None:
    return None if value is None else round(value, digits)


def roc_auc(scores: list[float], labels: list[bool]) -> float | None:
    """Area under the ROC curve, via the rank-sum identity.

    Ties are handled with average ranks, which is what makes this correct for
    detectors that emit many identical scores.
    """
    positives = sum(1 for label in labels if label)
    negatives = len(labels) - positives
    if positives < MIN_PER_CLASS or negatives < MIN_PER_CLASS:
        return None

    order = sorted(range(len(scores)), key=lambda index: scores[index])
    ranks = [0.0] * len(scores)
    position = 0
    while position < len(order):
        end = position
        while end + 1 < len(order) and scores[order[end + 1]] == scores[order[position]]:
            end += 1
        average = (position + end) / 2.0 + 1.0
        for index in range(position, end + 1):
            ranks[order[index]] = average
        position = end + 1

    positive_rank_sum = sum(ranks[index] for index, label in enumerate(labels) if label)
    statistic = positive_rank_sum - positives * (positives + 1) / 2.0
    return statistic / (positives * negatives)


def pr_auc(scores: list[float], labels: list[bool]) -> float | None:
    """Average precision: the step-wise area under the precision-recall curve.

    This is the interpolation-free definition (sum of precision at each
    threshold weighted by the recall gained), which does not overstate the
    curve the way trapezoidal interpolation does on sparse positives.
    """
    positives = sum(1 for label in labels if label)
    negatives = len(labels) - positives
    if positives < MIN_PER_CLASS or negatives < MIN_PER_CLASS:
        return None

    order = sorted(range(len(scores)), key=lambda index: -scores[index])
    true_positives = 0
    false_positives = 0
    previous_recall = 0.0
    total = 0.0
    index = 0
    while index < len(order):
        # Consume every sample sharing this score: a threshold cannot separate
        # them, so they must be counted as one step.
        end = index
        while end + 1 < len(order) and scores[order[end + 1]] == scores[order[index]]:
            end += 1
        for position in range(index, end + 1):
            if labels[order[position]]:
                true_positives += 1
            else:
                false_positives += 1
        recall = true_positives / positives
        precision = true_positives / (true_positives + false_positives)
        total += precision * (recall - previous_recall)
        previous_recall = recall
        index = end + 1
    return total


def matthews_correlation(tp: int, tn: int, fp: int, fn: int) -> float | None:
    """MCC: the balanced-classes-agnostic summary of a confusion matrix."""
    numerator = (tp * tn) - (fp * fn)
    denominator = math.sqrt(
        float(tp + fp) * float(tp + fn) * float(tn + fp) * float(tn + fn)
    )
    if denominator == 0:
        return None
    return numerator / denominator


def balanced_accuracy(tp: int, tn: int, fp: int, fn: int) -> float | None:
    """Mean of recall and specificity. Undefined if a class is absent."""
    if (tp + fn) == 0 or (tn + fp) == 0:
        return None
    return 0.5 * (tp / (tp + fn) + tn / (tn + fp))


@dataclass
class RankingMetrics:
    """Threshold-free summaries of a detector's ordering."""

    #: ``None`` when the detector emits no ordering, or a class is too small.
    roc_auc: float | None
    pr_auc: float | None
    #: The rate a detector that flags everything would achieve. PR-AUC must be
    #: read against this, never against 0.5.
    positive_rate: float | None
    unavailable_reason: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "rocAuc": _rounded(self.roc_auc),
            "prAuc": _rounded(self.pr_auc),
            "prAucBaseline": _rounded(self.positive_rate),
            "unavailableReason": self.unavailable_reason,
        }


def ranking_metrics(
    scores: list[float], labels: list[bool], *, score_kind: str, ordered: bool
) -> RankingMetrics:
    """Compute ranking metrics, or say precisely why they are unavailable."""
    positives = sum(1 for label in labels if label)
    negatives = len(labels) - positives
    positive_rate = positives / len(labels) if labels else None

    if not ordered:
        return RankingMetrics(
            roc_auc=None,
            pr_auc=None,
            positive_rate=positive_rate,
            unavailable_reason=(
                f"'{score_kind}' has no ordering, so ROC-AUC and PR-AUC are undefined. "
                "Reporting 0.5 here would present an artefact of the metric as a result."
            ),
        )
    if positives < MIN_PER_CLASS or negatives < MIN_PER_CLASS:
        return RankingMetrics(
            roc_auc=None,
            pr_auc=None,
            positive_rate=positive_rate,
            unavailable_reason=(
                f"needs at least {MIN_PER_CLASS} samples per class; this split has "
                f"{positives} malicious and {negatives} benign"
            ),
        )
    return RankingMetrics(
        roc_auc=roc_auc(scores, labels),
        pr_auc=pr_auc(scores, labels),
        positive_rate=positive_rate,
    )


def normalized_confusion(tp: int, tn: int, fp: int, fn: int) -> dict[str, Any]:
    """Row-normalized confusion matrix (each true class sums to 1.0).

    Row normalization is the one that answers "of the actual attacks, what
    fraction did we catch" - the question an analyst is asking. Column
    normalization answers a different question and is reported as precision
    elsewhere; conflating them is a common way to overstate a detector.
    """
    actual_positive = tp + fn
    actual_negative = tn + fp
    return {
        "normalization": "row (by true class)",
        "actualMalicious": {
            "predictedMalicious": _rounded(tp / actual_positive) if actual_positive else None,
            "predictedBenign": _rounded(fn / actual_positive) if actual_positive else None,
            "support": actual_positive,
        },
        "actualBenign": {
            "predictedMalicious": _rounded(fp / actual_negative) if actual_negative else None,
            "predictedBenign": _rounded(tn / actual_negative) if actual_negative else None,
            "support": actual_negative,
        },
    }


def bootstrap_interval(
    values: list[float], *, confidence: float = 0.95, resamples: int = 1000, seed: int = 1337
) -> dict[str, Any]:
    """Percentile bootstrap interval for the mean of ``values``.

    Used for metrics measured across repeated seeds. With fewer than three
    observations the interval is not reported: a "confidence interval" over two
    points is decoration, not statistics.
    """
    import random

    usable = [value for value in values if value is not None]
    if len(usable) < 3:
        return {
            "mean": _rounded(sum(usable) / len(usable)) if usable else None,
            "lower": None,
            "upper": None,
            "samples": len(usable),
            "unavailableReason": (
                "a bootstrap interval over fewer than three observations would be "
                "decoration rather than a measurement"
            ),
        }

    rng = random.Random(seed)  # noqa: S311 - resampling, not security
    means: list[float] = []
    size = len(usable)
    for _ in range(resamples):
        means.append(sum(rng.choice(usable) for _ in range(size)) / size)
    means.sort()
    tail = (1.0 - confidence) / 2.0
    lower = means[int(tail * resamples)]
    upper = means[min(resamples - 1, int((1.0 - tail) * resamples))]
    mean = sum(usable) / size
    variance = sum((value - mean) ** 2 for value in usable) / (size - 1)
    return {
        "mean": _rounded(mean),
        "lower": _rounded(lower),
        "upper": _rounded(upper),
        "stdDev": _rounded(math.sqrt(variance)),
        "samples": size,
        "confidence": confidence,
        "resamples": resamples,
        "method": "percentile bootstrap over repeated-seed observations",
    }
