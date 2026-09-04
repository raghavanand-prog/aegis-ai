"""V5's comparison, re-run without the frozen-threshold confound.

V6 §15 classified ten of eleven comparison sites as confounded: they compare
models fitted on different data at one frozen 0.65, and §14 measured that such a
threshold names a different operating point per model, because ``anomaly_score``
is calibrated to the median of each model's own training scores.

**V5's headline is the most affected**, because its adapted arms refit while the
static baseline does not. §14 measured that moving to a model's own best
threshold is worth up to +0.53 F1 on this data - larger than the entire
adaptation effect V5 reported.

This re-runs the same arms through the same ``run_condition`` code path and
scores them three ways that a calibration shift cannot flatter:

``rocAuc``
    Capability with no operating point. Rank-based.
``bestF1``
    Each model at its own optimum. Comparable, but an optimistic ceiling chosen
    with knowledge of the labels that no operator gets.
``recallAtMatchedBudget``
    Every model allowed the same number of alerts. The operationally honest
    match - a SOC has fixed analyst capacity, and a model that "wins" by
    flagging five times as much has not won.

The random-label control is retained (V5 decision 27). It is what decides
whether any surviving effect is attributable to feedback content.
"""

from __future__ import annotations

import statistics
from typing import Any

from app.adaptation.experiments import scenarios
from app.adaptation.experiments.scenarios import DEFAULT_THRESHOLD, _matrix, _metrics
from app.evaluation.metrics.ranking import roc_auc

DEFAULT_CONDITIONS = (
    "static_v4",
    "threshold_only",
    "curation_only",
    "both_arms",
    "random_feedback",
    "no_feedback_retrain",
)


def _best_f1(scores: list[float], labels: list[bool]) -> tuple[float, float | None]:
    best_value, best_threshold = 0.0, None
    for candidate in sorted({round(score, 3) for score in scores}):
        metrics = _metrics(_matrix(scores, labels, candidate), candidate)
        if metrics["f1"] is not None and metrics["f1"] > best_value:
            best_value, best_threshold = metrics["f1"], candidate
    return best_value, best_threshold


def _recall_at_budget(
    scores: list[float], labels: list[bool], budget: int
) -> tuple[float, int]:
    """Recall when the model is allowed exactly ``budget`` alerts.

    Ranks by score and takes the top ``budget``, so every condition spends the
    same analyst capacity. Ties at the boundary are included, which can push the
    realised count slightly above the budget - reported rather than truncated,
    because silently breaking a tie would make the comparison depend on sort
    order.
    """
    ranked = sorted(range(len(scores)), key=lambda i: scores[i], reverse=True)
    if budget >= len(ranked):
        cutoff = float("-inf")
    else:
        cutoff = scores[ranked[budget - 1]]
    flagged = [i for i in range(len(scores)) if scores[i] >= cutoff]
    positives = sum(1 for label in labels if label)
    hits = sum(1 for i in flagged if labels[i])
    return (hits / positives if positives else 0.0), len(flagged)


def run(
    *,
    seed: int,
    conditions: tuple[str, ...] = DEFAULT_CONDITIONS,
    budget: int | None = None,
    noise_rate: float = 0.05,
    coverage: float = 0.5,
) -> dict[str, Any]:
    """Score every condition at matched operating points."""
    corpus = scenarios.prepare_corpus(seed=seed)
    if budget is not None and budget > len(corpus.test_vectors):
        raise ValueError(
            f"alert budget {budget} exceeds the {len(corpus.test_vectors)}-sample "
            "test set; a budget larger than the data is not an operating point"
        )

    results = {
        condition: scenarios.run_condition(
            corpus,
            condition=condition,
            seed=seed,
            noise_rate=noise_rate,
            coverage=coverage,
        )
        for condition in conditions
    }

    # Default budget: what the static baseline spends at the frozen threshold.
    # Comparing every arm against the incumbent's own alert volume is the
    # question a SOC actually faces.
    if budget is None:
        static = results.get("static_v4")
        budget = int(static.metrics["alertVolume"]) if static else 10
        budget = max(budget, 1)

    rows: dict[str, Any] = {}
    for condition, result in results.items():
        scores, labels = result.scores, result.labels
        best_f1, best_threshold = _best_f1(scores, labels)
        recall_at_budget, realised = _recall_at_budget(scores, labels, budget)
        below = sum(1 for score in scores if score < DEFAULT_THRESHOLD)
        rows[condition] = {
            # As V5 reported it, for comparison.
            "f1AtFrozen": result.metrics["f1"],
            "recallAtFrozen": result.metrics["recall"],
            "frozenPercentile": round(100.0 * below / len(scores), 2),
            # Matched.
            "rocAuc": roc_auc(scores, labels),
            "bestF1": round(best_f1, 6),
            "bestThreshold": best_threshold,
            "recallAtMatchedBudget": round(recall_at_budget, 6),
            "alertsAtBudget": realised,
        }

    return {
        "seed": seed,
        "budget": budget,
        "testSamples": len(corpus.test_vectors),
        "testMalicious": sum(corpus.test_labels),
        "datasetFingerprint": corpus.fingerprint,
        "splitFingerprint": corpus.split_fingerprint,
        "conditions": rows,
    }


def aggregate(results: list[dict[str, Any]]) -> dict[str, Any]:
    """Mean each measure across seeds, per condition."""
    conditions = results[0]["conditions"].keys()
    out: dict[str, Any] = {}
    for condition in conditions:
        rows = [r["conditions"][condition] for r in results]
        out[condition] = {
            key: round(statistics.fmean([row[key] for row in rows if row[key] is not None]), 6)
            for key in (
                "f1AtFrozen",
                "recallAtFrozen",
                "frozenPercentile",
                "rocAuc",
                "bestF1",
                "recallAtMatchedBudget",
            )
        }
    return out
