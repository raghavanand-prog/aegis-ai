"""The patient adversary: raising the baseline instead of fighting it.

V6 §9's defence caps a group's admitted-benign rows at ``tolerance x baseline``,
where the baseline is the mean admitted per group over **prior** feedback
datasets. §8's smash-and-grab lands 22 rows in one batch and is clipped to 4.

§9.3 named the obvious way around that and did not test it. A patient adversary
does not fight the cap - it **feeds** it. Each cycle it contributes as much as
the ceiling allows, which every batch passes by construction; the next cycle's
baseline is computed from a history that now contains that contribution, so the
ceiling rises. The attack is a ratchet, and the question is how fast it turns.

This became more load-bearing when ``baseline_relative`` became the default cap
policy, because the baseline is now consulted on every run.

**Threat model, unchanged from §8.** An analyst with ordinary feedback
permissions and patience. No privileged access, no code execution. Every control
is respected: only benign-projecting labels are admitted, the cap is applied
every cycle, and each individual batch is within policy.

**The campaign starts from honest history**, because production refuses a cold
start (§10.3). Modelling an attack that begins at cycle zero would be modelling
something the system does not permit.

**The control is the point.** An honest campaign of the same length must not
ratchet, or the effect is an artefact of the simulation.
"""

from __future__ import annotations

import random
import statistics
from collections import Counter
from typing import Any

from app.adaptation.experiments import arm2, simulation
from app.adaptation.experiments.scenarios import (
    DEFAULT_THRESHOLD,
    _fit,
)
from app.adaptation.experiments.targeted_poisoning import _group_of, _prepare
from app.adaptation.feedback import caps
from app.adaptation.feedback.labels import FeedbackLabel
from app.ml.features.extractor import FEATURE_NAMES
from app.ml.training.corpus import DEFAULT_SAMPLES, DEFAULT_SPAN_DAYS, build_corpus

#: Honest feedback cycles before the adversary starts. Production refuses a
#: cold start, so a campaign must begin from an established baseline.
DEFAULT_HONEST_HISTORY = 3


def _admitted_groups(
    verdicts: list[simulation.SimulatedVerdict], fit_samples: list
) -> list[tuple[int, str]]:
    """(index, group) for verdicts the arm would admit, before the cap."""
    return [
        (verdict.index, _group_of(fit_samples[verdict.index]))
        for verdict in verdicts
        if arm2._admissible(verdict.label)
    ]


def _honest_cycle(
    fit_labels: list[bool], *, seed: int, noise_rate: float, coverage: float
) -> list[simulation.SimulatedVerdict]:
    return simulation.simulate_feedback(
        fit_labels, seed=seed, noise_rate=noise_rate, coverage=coverage
    )


def _attack(
    verdicts: list[simulation.SimulatedVerdict],
    fit_samples: list,
    fit_labels: list[bool],
    *,
    target_category: str,
    reach: float,
    rng: random.Random,
) -> list[simulation.SimulatedVerdict]:
    """Relabel the target category benign, up to the adversary's reach."""
    out: list[simulation.SimulatedVerdict] = []
    for verdict in verdicts:
        label = verdict.label
        if (
            fit_samples[verdict.index].category == target_category
            and rng.random() < reach
        ):
            label = FeedbackLabel.BENIGN
        out.append(
            simulation.SimulatedVerdict(
                index=verdict.index,
                label=label,
                is_erroneous=(
                    label.binary_label is not None
                    and label.binary_label is not fit_labels[verdict.index]
                ),
            )
        )
    return out


def run_campaign(
    *,
    seed: int,
    target_category: str,
    cycles: int,
    adversary_reach: float,
    honest_history: int = DEFAULT_HONEST_HISTORY,
    tolerance: float = caps.DEFAULT_TOLERANCE,
    floor: int = caps.DEFAULT_FLOOR,
    noise_rate: float = 0.05,
    coverage: float = 0.5,
    global_ceiling: int = 10_000,
) -> dict[str, Any]:
    """Run a multi-cycle feedback campaign and record what the ceiling does."""
    if honest_history < 1:
        raise ValueError(
            "a campaign needs at least one cycle of honest history; production "
            "refuses a cold start, so an attack beginning at cycle zero would "
            "model something the system does not permit"
        )

    _, fit_samples, _ = _prepare(seed)
    fit_labels = [bool(sample.is_malicious) for sample in fit_samples]

    # History of admitted group counts, one entry per completed cycle. The
    # baseline is the mean over this, and it never includes the live cycle.
    history: list[Counter[str]] = []

    for index in range(honest_history):
        verdicts = _honest_cycle(
            fit_labels, seed=seed + index, noise_rate=noise_rate, coverage=coverage
        )
        history.append(Counter(group for _, group in _admitted_groups(verdicts, fit_samples)))

    honest_baseline = statistics.fmean(
        [counter.get(_target_group(fit_samples, target_category), 0) for counter in history]
    )

    rng = random.Random(seed + 11)  # noqa: S311 - reproducibility, not secrecy
    target_group = _target_group(fit_samples, target_category)
    records: list[dict[str, Any]] = []
    last_kept: list[tuple[int, str]] = []

    for cycle in range(cycles):
        verdicts = _honest_cycle(
            fit_labels,
            seed=seed + honest_history + cycle,
            noise_rate=noise_rate,
            coverage=coverage,
        )
        if adversary_reach > 0:
            verdicts = _attack(
                verdicts,
                fit_samples,
                fit_labels,
                target_category=target_category,
                reach=adversary_reach,
                rng=rng,
            )

        eligible = _admitted_groups(verdicts, fit_samples)

        # Baseline from prior cycles only. Including the live cycle would let a
        # batch sanction itself.
        rates = {
            group: statistics.fmean([counter.get(group, 0) for counter in history])
            for group in {g for counter in history for g in counter}
        }
        baseline_rate = rates.get(target_group, 0.0)
        allowance = max(baseline_rate * tolerance, floor)

        kept = caps.apply(
            [caps.CapCandidate(index=i, group=g) for i, g in eligible],
            policy=caps.POLICY_BASELINE_RELATIVE,
            global_ceiling=global_ceiling,
            baseline_rates=rates,
            tolerance=tolerance,
            floor=floor,
        )
        allowed = {candidate.index for candidate in kept}
        kept_pairs = [(i, g) for i, g in eligible if i in allowed]

        # Two different quantities, deliberately not merged. Honest feedback at
        # a realistic noise rate *always* admits some genuinely malicious rows -
        # measured at 14.2 in §6 - so a count of all admitted-malicious rows is
        # dominated by noise and cannot show an attack. What the adversary moves
        # is the malicious rows **of the group it is targeting**.
        malicious_admitted = sum(1 for i, _ in kept_pairs if fit_labels[i])
        poison = sum(
            1 for i, g in kept_pairs if fit_labels[i] and g == target_group
        )

        records.append(
            {
                "cycle": cycle,
                "baselineRate": round(baseline_rate, 4),
                "targetAllowance": round(allowance, 4),
                # Pre-cap: what the analyst *submitted* for this group. The cap
                # clamps `targetAdmitted`, so monitoring that signal cannot see
                # an attack the cap is successfully suppressing - measured, and
                # the reason the growth monitor reads this field instead.
                "targetEligible": sum(1 for _, g in eligible if g == target_group),
                "targetAdmitted": sum(1 for _, g in kept_pairs if g == target_group),
                # Malicious rows admitted *in the targeted group*: the attack.
                "poisonLanded": poison,
                # Malicious rows admitted anywhere: mostly honest label noise.
                "maliciousAdmitted": malicious_admitted,
                "totalAdmitted": len(kept_pairs),
            }
        )

        history.append(Counter(group for _, group in kept_pairs))
        last_kept = kept_pairs

    return {
        "seed": seed,
        "targetCategory": target_category,
        "targetGroup": target_group,
        "adversaryReach": adversary_reach,
        "honestHistory": honest_history,
        "honestBaselineRate": round(honest_baseline, 4),
        "tolerance": tolerance,
        "cycles": records,
        "finalKept": last_kept,
    }


def _target_group(fit_samples: list, target_category: str) -> str:
    """The observable group the target category presents as."""
    for sample in fit_samples:
        if sample.category == target_category:
            return _group_of(sample)
    raise ValueError(f"no fit-split samples of {target_category!r}")


def measure_damage(
    *,
    seed: int,
    target_category: str,
    cycles: int,
    adversary_reach: float,
    honest_history: int = DEFAULT_HONEST_HISTORY,
    samples: int = DEFAULT_SAMPLES,
    span_days: int = DEFAULT_SPAN_DAYS,
    **kwargs: Any,
) -> dict[str, Any]:
    """Train on the campaign's final batch and measure what it cost."""
    features, fit_samples, test_samples = _prepare(seed)
    telemetry = [
        tuple(vector)
        for vector in build_corpus(seed=seed, samples=samples, span_days=span_days).vectors
    ]

    attacked = run_campaign(
        seed=seed,
        target_category=target_category,
        cycles=cycles,
        adversary_reach=adversary_reach,
        honest_history=honest_history,
        **kwargs,
    )
    honest = run_campaign(
        seed=seed,
        target_category=target_category,
        cycles=cycles,
        adversary_reach=0.0,
        honest_history=honest_history,
        **kwargs,
    )

    def recall(kept: list[tuple[int, str]]) -> float | None:
        vectors = telemetry + [features[fit_samples[i].id] for i, _ in kept]
        detector = _fit(vectors, tuple(FEATURE_NAMES), seed)
        malicious = [
            sample
            for sample in test_samples
            if sample.is_malicious and sample.category == target_category
        ]
        if not malicious:
            return None
        hits = sum(
            1
            for sample in malicious
            if detector.anomaly_score(features[sample.id]) >= DEFAULT_THRESHOLD
        )
        return hits / len(malicious)

    return {
        "seed": seed,
        "targetCategory": target_category,
        "cycles": cycles,
        "finalPoisonLanded": attacked["cycles"][-1]["poisonLanded"],
        "poisonByCycle": [c["poisonLanded"] for c in attacked["cycles"]],
        "allowanceByCycle": [c["targetAllowance"] for c in attacked["cycles"]],
        "targetRecall": {
            "honest": recall(honest["finalKept"]),
            "poisoned": recall(attacked["finalKept"]),
        },
    }
