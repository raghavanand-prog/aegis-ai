"""Promotion gates: is it safe to put this candidate in front of live traffic?

Deliberately not "is it better". Better on one metric is how a detector trades
half its recall for a prettier false-positive rate and ships, because the
summary line improved. A gate is a veto, not a score.

Four properties this module holds:

**An unmeasured metric never passes a gate.** V4's rule - a metric that was not
measured is reported as unavailable, never as zero and never as fine. A gate
that cannot see a number reports ``not_measured`` and does not count as a pass.

**Regressions are absolute, not relative.** A candidate is compared against the
model actually deployed, on the same dataset, and the drop that matters is the
drop a SOC would experience.

**Thresholds are configuration with a stated rationale.** Every default here is
a judgement, and a reviewer must be able to argue with the number rather than
find it embedded in a source file. ``GatePolicy.rationale()`` explains each.

**Passing every gate promotes nothing.** The result is evidence for a human
decision. It is not the decision, and nothing in this module writes model state.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from app.evaluation.metrics.classification import ConfusionMatrix


@dataclass(frozen=True)
class GatePolicy:
    """Numerical limits on what a candidate may regress.

    The defaults are a starting policy for a rules-first SOC with a
    high-false-positive anomaly detector, which is what V4 measured this
    platform to be. They are not universal and not derived from any published
    standard - they are stated so they can be argued with.
    """

    #: Recall is the metric a SOC cannot buy back. A candidate that misses
    #: attacks the incumbent caught is a regression no precision gain offsets,
    #: so this is the tightest bound.
    max_recall_drop: float = 0.05

    #: False positives are the analyst's time. V4 measured the deployed model at
    #: 33.3% FPR on the synthetic corpus, so the SOC already absorbs a great
    #: deal; the bound is on making it materially worse, not on perfection.
    max_fpr_increase: float = 0.05

    #: Precision may fall somewhat if recall rises - that trade is legitimate
    #: and sometimes wanted. It may not collapse.
    max_precision_drop: float = 0.10

    #: F1 is the summary check, and it is deliberately the loosest: it exists to
    #: catch a candidate that is worse on every axis, not to adjudicate trades
    #: the specific gates above already rule on.
    max_f1_drop: float = 0.05

    #: Scoring sits on the ingestion path. A model that doubles per-event
    #: latency changes the platform's throughput, whatever its metrics say.
    max_latency_increase_ratio: float = 2.0

    #: Aggregate recall hides a single-category collapse. V6 §8 measured a
    #: candidate losing 0.2026 of one attack category's recall while aggregate
    #: recall moved 0.0232 - less than half its own seed noise of 0.0426. Every
    #: aggregate gate passed that candidate. This bound is per category.
    #:
    #: Looser than ``max_recall_drop`` on purpose: per-category recall is
    #: measured over far fewer samples, so its own variance is higher (V6 §8.5
    #: measured intervals as wide as [0.334, 0.836]). A tighter bound would
    #: veto on noise.
    max_per_category_recall_drop: float = 0.10

    #: Below this many malicious samples a per-category recall figure is noise,
    #: and the category is reported as unmeasured rather than judged.
    min_category_samples: int = 10

    #: Below this many samples a comparison is noise dressed as evidence.
    min_evaluation_samples: int = 100

    def rationale(self) -> dict[str, str]:
        """Why each threshold is what it is. Shown next to every gate result."""
        return {
            "max_recall_drop": (
                "Recall is what a SOC cannot buy back: an attack the incumbent "
                "caught and the candidate misses is not offset by any precision "
                "gain. Tightest bound in the policy."
            ),
            "max_fpr_increase": (
                "False positives are analyst time. The deployed model was "
                "measured at 33.3% FPR on the synthetic corpus, so the bound is "
                "on making an already-costly rate materially worse."
            ),
            "max_precision_drop": (
                "Precision may fall if recall rises - that trade is sometimes "
                "wanted. It may not collapse."
            ),
            "max_per_category_recall_drop": (
                "Aggregate recall divides a single-category collapse by the "
                "number of categories. V6 §8 measured a candidate losing 0.2026 "
                "of one category's recall while the aggregate moved 0.0232 - "
                "below its own seed noise of 0.0426 - and every aggregate gate "
                "passed it. Looser than the aggregate bound because per-category "
                "recall is measured over far fewer samples and is noisier."
            ),
            "min_category_samples": (
                "Below this many malicious samples a per-category recall figure "
                "is noise. Such a category is reported unmeasured, not judged."
            ),
            "max_f1_drop": (
                "A summary backstop for a candidate that is worse on every axis. "
                "Deliberately loose: the specific gates adjudicate real trades."
            ),
            "max_latency_increase_ratio": (
                "Scoring is on the ingestion path. Doubling per-event latency "
                "changes platform throughput whatever the metrics say."
            ),
            "min_evaluation_samples": (
                "Below this a comparison is noise dressed as evidence."
            ),
        }


@dataclass(frozen=True)
class GateCheck:
    """One gate, its threshold, and what was actually observed."""

    name: str
    description: str
    passed: bool
    #: ``ok`` | ``failed`` | ``not_measured``
    status: str
    threshold: float | None = None
    observed: float | None = None
    #: An advisory check reports a concern without vetoing. Used where a metric
    #: is genuinely absent rather than bad - the absence is surfaced to the
    #: approver instead of being silently treated as a pass.
    advisory: bool = False


@dataclass(frozen=True)
class GateResult:
    """The verdict, and every check behind it."""

    passed: bool
    checks: list[GateCheck] = field(default_factory=list)
    failures: list[str] = field(default_factory=list)
    policy: dict[str, float] = field(default_factory=dict)
    rationale: dict[str, str] = field(default_factory=dict)

    def as_dict(self) -> dict:
        return {
            "passed": self.passed,
            "checks": [
                {
                    "name": check.name,
                    "description": check.description,
                    "passed": check.passed,
                    "status": check.status,
                    "threshold": check.threshold,
                    "observed": check.observed,
                    "advisory": check.advisory,
                }
                for check in self.checks
            ],
            "failures": list(self.failures),
            "policy": dict(self.policy),
            "rationale": dict(self.rationale),
            "interpretation": (
                "A passing result means this candidate is safe to consider, not "
                "that it should be deployed. Promotion requires an "
                "administrator's approval."
            ),
        }


def _regression_check(
    *,
    name: str,
    description: str,
    baseline_value: float | None,
    candidate_value: float | None,
    limit: float,
    higher_is_better: bool,
) -> GateCheck:
    """One metric, compared against the incumbent within a bound."""
    if baseline_value is None or candidate_value is None:
        return GateCheck(
            name=name,
            description=(
                f"{description} Not measured on one or both models, so this gate "
                "cannot be evaluated. An unmeasured metric is not a passing one."
            ),
            passed=False,
            status="not_measured",
        )

    change = (
        baseline_value - candidate_value if higher_is_better
        else candidate_value - baseline_value
    )
    return GateCheck(
        name=name,
        description=description,
        passed=change <= limit,
        status="ok" if change <= limit else "failed",
        threshold=limit,
        observed=round(change, 6),
    )


def _per_category_check(
    *,
    baseline: dict[str, ConfusionMatrix] | None,
    candidate: dict[str, ConfusionMatrix] | None,
    policy: GatePolicy,
) -> tuple[GateCheck, list[str]]:
    """The gate aggregate metrics cannot see.

    When no per-category data is supplied this is **advisory**, not a veto.
    Every pre-V6 caller passes none, so vetoing would reject every candidate;
    but the absence is surfaced to the approver rather than counted as a pass,
    which is what ``advisory`` is for. Supplying the data makes it a hard gate.
    """
    name = "per_category_recall"
    description = (
        "Recall per attack category, against the incumbent. Aggregate recall "
        "divides a single-category collapse by the number of categories and can "
        "hide it beneath its own seed noise (V6 §8)."
    )

    if baseline is None or candidate is None:
        return (
            GateCheck(
                name=name,
                description=(
                    f"{description} Not supplied for this evaluation, so a "
                    "single-category regression cannot be ruled out. Advisory: "
                    "surfaced to the approver rather than treated as a pass."
                ),
                passed=True,
                status="not_measured",
                advisory=True,
            ),
            [],
        )

    failures: list[str] = []
    worst_drop: float | None = None
    for category, baseline_matrix in sorted(baseline.items()):
        if baseline_matrix.actual_positives < policy.min_category_samples:
            continue  # too few to judge; reported by the caller, not guessed at

        candidate_matrix = candidate.get(category)
        if candidate_matrix is None:
            failures.append(
                f"per-category recall: {category} was measured on the incumbent "
                "but not on the candidate, so the candidate has not been shown "
                "safe on it"
            )
            continue

        baseline_recall = baseline_matrix.recall
        candidate_recall = candidate_matrix.recall
        if baseline_recall is None or candidate_recall is None:
            continue

        drop = baseline_recall - candidate_recall
        worst_drop = drop if worst_drop is None else max(worst_drop, drop)
        if drop > policy.max_per_category_recall_drop:
            failures.append(
                f"per-category recall: {category} fell {drop:.4f} "
                f"({baseline_recall:.4f} -> {candidate_recall:.4f}), above the "
                f"{policy.max_per_category_recall_drop} bound"
            )

    if worst_drop is None and not failures:
        return (
            GateCheck(
                name=name,
                description=(
                    f"{description} No category had enough malicious samples to "
                    "judge. Advisory rather than a pass."
                ),
                passed=True,
                status="not_measured",
                advisory=True,
            ),
            [],
        )

    return (
        GateCheck(
            name=name,
            description=description,
            passed=not failures,
            status="ok" if not failures else "failed",
            threshold=policy.max_per_category_recall_drop,
            observed=round(worst_drop, 6) if worst_drop is not None else None,
        ),
        failures,
    )


def evaluate(
    *,
    baseline: ConfusionMatrix,
    candidate: ConfusionMatrix,
    baseline_latency_ms: float | None = None,
    candidate_latency_ms: float | None = None,
    baseline_dataset_fingerprint: str | None = None,
    candidate_dataset_fingerprint: str | None = None,
    baseline_per_category: dict[str, ConfusionMatrix] | None = None,
    candidate_per_category: dict[str, ConfusionMatrix] | None = None,
    policy: GatePolicy | None = None,
) -> GateResult:
    """Run every gate. Writes nothing and promotes nothing."""
    policy = policy or GatePolicy()

    if (
        baseline_dataset_fingerprint is not None
        and candidate_dataset_fingerprint is not None
        and baseline_dataset_fingerprint != candidate_dataset_fingerprint
    ):
        raise ValueError(
            "Refusing to compare results produced on different dataset "
            f"fingerprints ({baseline_dataset_fingerprint} vs "
            f"{candidate_dataset_fingerprint}). Two numbers over different data "
            "were never comparable, and a promotion decision is a comparison."
        )

    checks: list[GateCheck] = [
        _regression_check(
            name="recall",
            description="Attacks the incumbent caught that the candidate misses.",
            baseline_value=baseline.recall,
            candidate_value=candidate.recall,
            limit=policy.max_recall_drop,
            higher_is_better=True,
        ),
        _regression_check(
            name="false_positive_rate",
            description="Additional benign traffic the candidate flags.",
            baseline_value=baseline.false_positive_rate,
            candidate_value=candidate.false_positive_rate,
            limit=policy.max_fpr_increase,
            higher_is_better=False,
        ),
        _regression_check(
            name="precision",
            description="Share of flagged events that are genuinely malicious.",
            baseline_value=baseline.precision,
            candidate_value=candidate.precision,
            limit=policy.max_precision_drop,
            higher_is_better=True,
        ),
        _regression_check(
            name="f1",
            description="Summary backstop against a candidate worse on every axis.",
            baseline_value=baseline.f1,
            candidate_value=candidate.f1,
            limit=policy.max_f1_drop,
            higher_is_better=True,
        ),
    ]

    per_category_check, per_category_failures = _per_category_check(
        baseline=baseline_per_category,
        candidate=candidate_per_category,
        policy=policy,
    )
    checks.append(per_category_check)

    # Sample-size gate: a comparison over too little data is not evidence.
    checks.append(
        GateCheck(
            name="evaluation_samples",
            description="Samples the candidate was evaluated over.",
            passed=candidate.total >= policy.min_evaluation_samples,
            status="ok" if candidate.total >= policy.min_evaluation_samples else "failed",
            threshold=float(policy.min_evaluation_samples),
            observed=float(candidate.total),
        )
    )

    # Latency: advisory when absent rather than assumed. Reported to the
    # approver as a known gap instead of quietly counting as a pass.
    if baseline_latency_ms is None or candidate_latency_ms is None:
        checks.append(
            GateCheck(
                name="latency",
                description=(
                    "Per-event scoring latency was not measured for one or both "
                    "models. Surfaced to the approver rather than assumed."
                ),
                passed=False,
                status="not_measured",
                advisory=True,
            )
        )
    else:
        ratio = (
            candidate_latency_ms / baseline_latency_ms if baseline_latency_ms > 0 else float("inf")
        )
        checks.append(
            GateCheck(
                name="latency",
                description="Per-event scoring latency relative to the incumbent.",
                passed=ratio <= policy.max_latency_increase_ratio,
                status="ok" if ratio <= policy.max_latency_increase_ratio else "failed",
                threshold=policy.max_latency_increase_ratio,
                observed=round(ratio, 4),
            )
        )

    # Human-readable: a failure list is read by an approver deciding whether to
    # sign something off, not by a parser.
    failures = [
        f"{check.name.replace('_', ' ')}: {check.description}"
        for check in checks
        if not check.passed and not check.advisory
    ]
    # Per-category failures name the category, which a generic check description
    # cannot. An approver needs to know *which* attack class regressed.
    failures.extend(per_category_failures)

    return GateResult(
        passed=not failures,
        checks=checks,
        failures=failures,
        policy={
            "maxRecallDrop": policy.max_recall_drop,
            "maxFprIncrease": policy.max_fpr_increase,
            "maxPrecisionDrop": policy.max_precision_drop,
            "maxF1Drop": policy.max_f1_drop,
            "maxPerCategoryRecallDrop": policy.max_per_category_recall_drop,
            "minCategorySamples": float(policy.min_category_samples),
            "maxLatencyIncreaseRatio": policy.max_latency_increase_ratio,
            "minEvaluationSamples": float(policy.min_evaluation_samples),
        },
        rationale=policy.rationale(),
    )
