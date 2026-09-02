"""Classification metrics.

Deliberately implemented by hand rather than pulled from scikit-learn: the
formulas are three lines each, the dependency would be the only heavy one in
the backend, and an ML library in a repository that claims to contain no ML is
exactly the sort of thing that misleads a reader.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

#: Below this many samples a rate is noise, and the report says so instead of
#: printing a confident-looking number.
MIN_SAMPLES_OVERALL = 100
MIN_SAMPLES_PER_CLASS = 20


def safe_ratio(numerator: int, denominator: int) -> float | None:
    """Return numerator/denominator, or None when it is undefined.

    None is used rather than 0.0 on purpose: "no data" and "zero" mean very
    different things, and collapsing them is how misleading dashboards start.
    """
    if denominator <= 0:
        return None
    return numerator / denominator


def _rounded(value: float | None, digits: int = 4) -> float | None:
    return None if value is None else round(value, digits)


@dataclass
class ConfusionMatrix:
    """Binary confusion matrix: did the engine flag this event at all?

    * positive = the detection engine produced at least one detection
    * ground truth positive = the sample's label is malicious
    """

    true_positives: int = 0
    false_positives: int = 0
    true_negatives: int = 0
    false_negatives: int = 0

    @property
    def total(self) -> int:
        return (
            self.true_positives
            + self.false_positives
            + self.true_negatives
            + self.false_negatives
        )

    @property
    def actual_positives(self) -> int:
        return self.true_positives + self.false_negatives

    @property
    def actual_negatives(self) -> int:
        return self.true_negatives + self.false_positives

    @property
    def predicted_positives(self) -> int:
        return self.true_positives + self.false_positives

    @property
    def precision(self) -> float | None:
        """Of everything flagged, how much was really malicious."""
        return safe_ratio(self.true_positives, self.predicted_positives)

    @property
    def recall(self) -> float | None:
        """Of everything malicious, how much was flagged."""
        return safe_ratio(self.true_positives, self.actual_positives)

    @property
    def f1(self) -> float | None:
        precision, recall = self.precision, self.recall
        if precision is None or recall is None or (precision + recall) == 0:
            return None
        return 2 * precision * recall / (precision + recall)

    @property
    def false_positive_rate(self) -> float | None:
        """Of everything benign, how much was wrongly flagged.

        This is the number that decides whether analysts can live with the
        system, and the one tutorial projects usually skip.
        """
        return safe_ratio(self.false_positives, self.actual_negatives)

    @property
    def false_negative_rate(self) -> float | None:
        """Of everything malicious, how much was missed."""
        return safe_ratio(self.false_negatives, self.actual_positives)

    @property
    def accuracy(self) -> float | None:
        return safe_ratio(self.true_positives + self.true_negatives, self.total)

    @property
    def specificity(self) -> float | None:
        return safe_ratio(self.true_negatives, self.actual_negatives)

    @property
    def sufficient_data(self) -> bool:
        return self.total >= MIN_SAMPLES_OVERALL

    def record(self, *, is_malicious: bool, detected: bool) -> None:
        if is_malicious and detected:
            self.true_positives += 1
        elif is_malicious and not detected:
            self.false_negatives += 1
        elif not is_malicious and detected:
            self.false_positives += 1
        else:
            self.true_negatives += 1

    def to_dict(self) -> dict[str, Any]:
        return {
            "truePositives": self.true_positives,
            "falsePositives": self.false_positives,
            "trueNegatives": self.true_negatives,
            "falseNegatives": self.false_negatives,
            "total": self.total,
            "precision": _rounded(self.precision),
            "recall": _rounded(self.recall),
            "f1": _rounded(self.f1),
            "falsePositiveRate": _rounded(self.false_positive_rate),
            "falseNegativeRate": _rounded(self.false_negative_rate),
            "accuracy": _rounded(self.accuracy),
            "specificity": _rounded(self.specificity),
            "sufficientData": self.sufficient_data,
        }


@dataclass
class ClassResult:
    """Per-label outcome, so a strong average cannot hide a blind class."""

    label: str
    total: int = 0
    detected: int = 0
    missed: int = 0
    #: rule id -> how often it fired on this class
    rule_hits: dict[str, int] = None  # type: ignore[assignment]
    covered_by_rules: bool = True

    def __post_init__(self) -> None:
        if self.rule_hits is None:
            self.rule_hits = {}

    @property
    def detection_rate(self) -> float | None:
        """Recall for a malicious class; false positive rate for BENIGN."""
        return safe_ratio(self.detected, self.total)

    @property
    def sufficient_data(self) -> bool:
        return self.total >= MIN_SAMPLES_PER_CLASS

    def to_dict(self) -> dict[str, Any]:
        return {
            "label": self.label,
            "total": self.total,
            "detected": self.detected,
            "missed": self.missed,
            "detectionRate": _rounded(self.detection_rate),
            "coveredByRules": self.covered_by_rules,
            "sufficientData": self.sufficient_data,
            "ruleHits": dict(sorted(self.rule_hits.items())),
        }


@dataclass
class RuleResult:
    """Per-rule attribution: did this rule fire on what it claims to catch?"""

    rule_id: str
    rule_version: str
    rule_name: str
    fires: int = 0
    on_malicious: int = 0
    on_benign: int = 0
    correct_class: int = 0
    wrong_class: int = 0

    @property
    def rule_precision(self) -> float | None:
        """Share of this rule's fires that landed on a malicious sample."""
        return safe_ratio(self.on_malicious, self.fires)

    @property
    def attribution_accuracy(self) -> float | None:
        """Share of malicious fires that landed on the class the rule targets."""
        return safe_ratio(self.correct_class, self.on_malicious)

    def to_dict(self) -> dict[str, Any]:
        return {
            "ruleId": self.rule_id,
            "ruleVersion": self.rule_version,
            "ruleName": self.rule_name,
            "fires": self.fires,
            "onMalicious": self.on_malicious,
            "onBenign": self.on_benign,
            "correctClass": self.correct_class,
            "wrongClass": self.wrong_class,
            "rulePrecision": _rounded(self.rule_precision),
            "attributionAccuracy": _rounded(self.attribution_accuracy),
        }
