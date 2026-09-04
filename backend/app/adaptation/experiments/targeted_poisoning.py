"""Targeted poisoning of the redesigned Arm 2.

§7 measured *diffuse* poisoning and found the feedback cap bounded it: 83.5
mislabelled rows in ~6,490 sat inside what a density estimate tolerates. It also
found that false-positive rate, F1 and ROC-AUC all **improve** under benign bias
while recall falls, so recall was the only aggregate metric exposing it.

A targeted adversary differs in kind. Instead of spreading errors across the
corpus they label **one attack category** benign, so the damage concentrates in
that category's recall. Thirteen categories share the aggregate, so a collapse
in one is divided by thirteen before a gate ever sees it.

**The threat model.** A compromised, coerced or simply careless analyst with
ordinary feedback permissions - no privileged access, no code execution, nothing
that the RBAC model would refuse. They label events of their chosen category
benign and let the adaptation pipeline carry it into the fit set. Every existing
control is respected: only benign-projecting labels are admitted, the cap holds,
approval is still required to deploy. The question is whether those controls are
*sufficient*.

**Nothing here deploys.** This measures a candidate fit set built under attack.
"""

from __future__ import annotations

import random
from collections import Counter
from functools import lru_cache
from typing import Any

from app.adaptation.experiments import arm2, simulation
from app.adaptation.experiments.scenarios import (
    DEFAULT_THRESHOLD,
    _fit,
    _matrix,
    _metrics,
)
from app.adaptation.feedback import caps as feedback_caps
from app.adaptation.feedback.labels import FeedbackLabel
from app.evaluation.datasets.adapters import synthetic_dataset
from app.evaluation.metrics.ranking import roc_auc
from app.evaluation.splits import STRATIFIED_GROUP, build_split
from app.ml.features.extractor import FEATURE_NAMES, FeatureExtractor
from app.ml.training.corpus import DEFAULT_SAMPLES, DEFAULT_SPAN_DAYS, build_corpus

#: The field feedback is grouped by. Produced by the normalizer before any
#: detection or labelling, so a cap keyed on it is implementable in production.
#: Deliberately not the ground-truth attack category, which production lacks.
GROUP_FIELD = "event_type"


def _group_of(sample) -> str:
    return str(sample.candidate.get(GROUP_FIELD) or "unknown")


def honest_baseline_rates(*, seeds: tuple[int, ...], noise_rate: float = 0.05,
                          coverage: float = 0.5,
                          substrate: str = "rule-testing") -> dict[str, float]:
    """Mean admitted-benign rows per group under **honest** feedback.

    Computed from seeds other than the one under attack. A baseline learned from
    the attacked stream would learn the attack as normal, which is the obvious
    way to get this wrong.
    """
    totals: Counter[str] = Counter()
    for seed in seeds:
        _, fit_samples, _ = _prepare(seed, None, substrate, 6000)
        labels = [bool(s.is_malicious) for s in fit_samples]
        verdicts = simulation.simulate_feedback(
            labels, seed=seed, noise_rate=noise_rate, coverage=coverage
        )
        for verdict in verdicts:
            if arm2._admissible(verdict.label):
                totals[_group_of(fit_samples[verdict.index])] += 1
    return {group: count / len(seeds) for group, count in totals.items()}


@lru_cache(maxsize=16)
def _prepare(
    seed: int,
    samples_per_class: int | None = None,
    substrate: str = "rule-testing",
    samples: int = 6000,
):
    """Corpus with categories retained, so damage can be located per category.

    ``substrate`` selects the corpus (V6 §19). On the rebuilt telemetry corpus
    the category is the generator scenario, and several scenarios collapse onto
    one ``event_type`` - which is the grouping key the §9 cap uses, and the
    condition §9.3 warned would blunt it.
    """
    if substrate == "telemetry":
        from app.evaluation.datasets.telemetry_labelled import (
            telemetry_labelled_dataset,
        )

        dataset = telemetry_labelled_dataset(seed=seed, samples=samples)
    else:
        dataset = synthetic_dataset(seed=seed, samples_per_class=samples_per_class)
    ordered = sorted(dataset.samples, key=lambda sample: sample.timestamp)
    extractor = FeatureExtractor()
    features = {
        sample.id: extractor.extract(sample.candidate, observe=True).values
        for sample in ordered
    }
    plan = build_split(dataset, strategy=STRATIFIED_GROUP, seed=seed)
    fit_samples = sorted(
        list(plan.train.samples) + list(plan.validation.samples),
        key=lambda sample: sample.timestamp,
    )
    test_samples = sorted(plan.test.samples, key=lambda sample: sample.timestamp)
    return features, fit_samples, test_samples


def measure(
    *,
    seed: int,
    target_category: str,
    adversary_reach: float = 1.0,
    noise_rate: float = 0.05,
    coverage: float = 0.5,
    max_feedback_fraction: float = arm2.DEFAULT_MAX_FEEDBACK_FRACTION,
    cap_policy: str = feedback_caps.POLICY_GLOBAL,
    baseline_rates: dict[str, float] | None = None,
    per_group_ceiling: int | None = None,
    samples: int = DEFAULT_SAMPLES,
    span_days: int = DEFAULT_SPAN_DAYS,
    samples_per_class: int | None = None,
    substrate: str = "rule-testing",
) -> dict[str, Any]:
    """Poison one category's feedback; measure where the damage actually lands.

    ``samples_per_class`` enlarges the corpus. V4's ``roc_auc`` refuses fewer
    than 20 observations a side, and the default corpus leaves too few held-out
    samples of one category for a threshold-free figure - so ``targetAuc`` is
    ``None`` unless this is raised. The guard is respected rather than weakened.

    ``adversary_reach`` is the share of the target category's reviewed events the
    adversary manages to mislabel - their budget, not their intent.
    """
    features, fit_samples, test_samples = _prepare(
        seed, samples_per_class, substrate, samples
    )

    if not any(s.category == target_category for s in fit_samples):
        raise ValueError(
            f"no fit-split samples of {target_category!r}; the attack cannot be staged"
        )
    if not any(s.category == target_category for s in test_samples):
        raise ValueError(
            f"no test-split samples of {target_category!r}; the damage could not be seen"
        )

    fit_vectors = [features[s.id] for s in fit_samples]
    fit_labels = [bool(s.is_malicious) for s in fit_samples]

    honest = simulation.simulate_feedback(
        fit_labels, seed=seed, noise_rate=noise_rate, coverage=coverage
    )

    # noqa justification: reproducibility, not secrecy.
    rng = random.Random(seed + 7)  # noqa: S311
    attacked: list[simulation.SimulatedVerdict] = []
    for verdict in honest:
        label = verdict.label
        sample = fit_samples[verdict.index]
        if sample.category == target_category and rng.random() < adversary_reach:
            # The attack: this category is always "ordinary activity".
            label = FeedbackLabel.BENIGN
        attacked.append(
            simulation.SimulatedVerdict(
                index=verdict.index,
                label=label,
                is_erroneous=(
                    label.binary_label is not None
                    and label.binary_label is not fit_labels[verdict.index]
                ),
            )
        )

    telemetry = [tuple(vector) for vector in build_corpus(
        seed=seed, samples=samples, span_days=span_days
    ).vectors]
    ceiling = int(len(telemetry) * max_feedback_fraction / (1 - max_feedback_fraction))

    def admit(verdicts: list[simulation.SimulatedVerdict]) -> list[simulation.SimulatedVerdict]:
        eligible = [v for v in verdicts if arm2._admissible(v.label)]
        kept = feedback_caps.apply(
            [
                feedback_caps.CapCandidate(
                    index=v.index, group=_group_of(fit_samples[v.index])
                )
                for v in eligible
            ],
            policy=cap_policy,
            global_ceiling=ceiling,
            per_group_ceiling=per_group_ceiling,
            baseline_rates=baseline_rates,
        )
        allowed = {candidate.index for candidate in kept}
        return [v for v in eligible if v.index in allowed]

    honest_admitted = admit(honest)
    attacked_admitted = admit(attacked)

    def target_auc(detector) -> float | None:
        """Threshold-free separation of the targeted category from benign.

        V6 §15 established that comparing differently-fitted models at a frozen
        threshold compares their calibrations. The honest and poisoned arms are
        fitted on different feedback, so recall alone cannot say whether the
        attack cost capability or merely moved the operating point.
        """
        malicious = [
            s for s in test_samples if s.is_malicious and s.category == target_category
        ]
        benign = [s for s in test_samples if not s.is_malicious]
        if len(malicious) < 2 or len(benign) < 2:
            return None
        scores = [detector.anomaly_score(features[s.id]) for s in malicious + benign]
        labels = [True] * len(malicious) + [False] * len(benign)
        return roc_auc(scores, labels)

    def recall_for(detector, predicate) -> float | None:
        chosen = [s for s in test_samples if predicate(s)]
        malicious = [s for s in chosen if s.is_malicious]
        if not malicious:
            return None
        hits = sum(
            1
            for s in malicious
            if detector.anomaly_score(features[s.id]) >= DEFAULT_THRESHOLD
        )
        return hits / len(malicious)

    def evaluate(admitted: list[simulation.SimulatedVerdict]) -> dict[str, Any]:
        vectors = telemetry + [fit_vectors[v.index] for v in admitted]
        detector = _fit(vectors, tuple(FEATURE_NAMES), seed)
        scores = [detector.anomaly_score(features[s.id]) for s in test_samples]
        labels = [bool(s.is_malicious) for s in test_samples]
        aggregate = _metrics(_matrix(scores, labels, DEFAULT_THRESHOLD), DEFAULT_THRESHOLD)
        aggregate["rocAuc"] = roc_auc(scores, labels)
        return {
            "aggregate": aggregate,
            "targetAuc": target_auc(detector),
            "targetRecall": recall_for(detector, lambda s: s.category == target_category),
            "nonTargetRecall": recall_for(
                detector, lambda s: s.category != target_category
            ),
            "feedbackRows": len(admitted),
        }

    clean = evaluate(honest_admitted)
    poisoned = evaluate(attacked_admitted)
    poisoned_rows = sum(
        1 for v in attacked_admitted if fit_labels[v.index]
        and fit_samples[v.index].category == target_category
    )

    return {
        "seed": seed,
        "targetCategory": target_category,
        "adversaryReach": adversary_reach,
        "capPolicy": cap_policy,
        "poisonedCategories": sorted(
            {
                fit_samples[v.index].category
                for v in attacked_admitted
                if fit_labels[v.index]
                and fit_samples[v.index].category == target_category
            }
        ),
        "poisonedRows": poisoned_rows,
        "feedbackRows": poisoned["feedbackRows"],
        "feedbackFraction": round(
            poisoned["feedbackRows"] / (len(telemetry) + poisoned["feedbackRows"]), 6
        ),
        # What a gate would see.
        "aggregate": {"baseline": clean["aggregate"], "poisoned": poisoned["aggregate"]},
        # Where the damage actually is.
        "targetRecall": {
            "baseline": clean["targetRecall"],
            "poisoned": poisoned["targetRecall"],
        },
        # Threshold-free: whether the attack cost capability, or only moved the
        # operating point (V6 §15).
        "targetAuc": {
            "baseline": clean["targetAuc"],
            "poisoned": poisoned["targetAuc"],
        },
        "nonTargetRecall": {
            "baseline": clean["nonTargetRecall"],
            "poisoned": poisoned["nonTargetRecall"],
        },
    }
