"""Track 2: feedback-quality conditions for the redesigned Arm 2.

Track 2 was designed against V5's Arm 2, which §6 replaced. That changes what the
question means, and narrows it usefully. The redesigned arm admits analyst-
verified **benign** rows into training data, so the conditions that matter most
are the ones pushing analysts toward "benign" - simultaneously a quality problem
and a poisoning vector. A condition that makes analysts over-report *malicious*
is comparatively harmless here: it starves the arm rather than corrupting it.

Every condition is a variation of the V5 simulator rather than a replacement, so
``nominal`` reproduces the settings Track 1 used and remains the control.

**The three streams stay separate**, as V5 required: ``ground_truth`` is
independent, analyst verdicts are opinions about it that may be wrong, and model
predictions are computed later from the fitted detector. ``is_erroneous`` records
where a verdict disagrees with truth - knowable only in simulation, which is what
lets a report state realised rather than requested noise.
"""

from __future__ import annotations

import random
from dataclasses import dataclass
from typing import Any

from app.adaptation.experiments import arm2, simulation
from app.adaptation.experiments.scenarios import (
    DEFAULT_THRESHOLD,
    _fit,
    _matrix,
    _metrics,
    prepare_corpus,
)
from app.adaptation.feedback.labels import FeedbackLabel
from app.evaluation.metrics.ranking import roc_auc
from app.ml.training.corpus import DEFAULT_SAMPLES, DEFAULT_SPAN_DAYS, build_corpus


@dataclass(frozen=True)
class ConditionSpec:
    name: str
    description: str
    noise_rate: float = 0.05
    coverage: float = 0.5
    abstention_rate: float = 0.10
    #: Probability a benign event is reported as a false positive rather than
    #: plain benign. Both project benign, so this changes vocabulary, not volume.
    false_positive_bias: float = 0.2
    #: Probability a *malicious* event is nonetheless called benign. The
    #: poisoning vector for an arm that admits benign rows.
    benign_bias: float = 0.0
    #: Probability a *benign* event is called malicious. Starves the arm.
    malicious_bias: float = 0.0
    #: Fraction of the (chronological) event stream the analyst has reached.
    reviewed_prefix: float = 1.0
    #: Whether a share of verdicts are later corrected, superseding the first.
    correction_rate: float = 0.0


CONDITIONS: dict[str, ConditionSpec] = {
    spec.name: spec
    for spec in (
        ConditionSpec(
            name="nominal",
            description=(
                "The V5 / Track 1 settings. The control every other condition is "
                "read against."
            ),
        ),
        ConditionSpec(
            name="clean",
            description="An unrealistic ceiling: no label noise, no abstention.",
            noise_rate=0.0,
            abstention_rate=0.0,
        ),
        ConditionSpec(
            name="high_noise",
            description="A bad week: 15% of verdicts are simply wrong.",
            noise_rate=0.15,
        ),
        ConditionSpec(
            name="severe_noise",
            description="Beyond anything V5 tested: 30% of verdicts are wrong.",
            noise_rate=0.30,
        ),
        ConditionSpec(
            name="benign_biased",
            description=(
                "Analysts under pressure clear alerts: 25% of genuinely malicious "
                "events are called benign. The poisoning vector for an arm that "
                "admits benign rows into training data."
            ),
            benign_bias=0.25,
        ),
        ConditionSpec(
            name="malicious_biased",
            description=(
                "Cautious analysts escalate: 25% of benign events are called "
                "malicious. Starves the arm rather than corrupting it."
            ),
            malicious_bias=0.25,
        ),
        ConditionSpec(
            name="sparse",
            description="Only 10% of the queue is reviewed at all.",
            coverage=0.10,
        ),
        ConditionSpec(
            name="delayed",
            description=(
                "Feedback lags the stream: only the earlier 60% of events have "
                "been reached, so recent behaviour is unreviewed."
            ),
            reviewed_prefix=0.60,
        ),
        ConditionSpec(
            name="uncertain_heavy",
            description=(
                "An unfamiliar environment: 40% of reviews end undecided. Tests "
                "that hesitation is recorded and never counted."
            ),
            abstention_rate=0.40,
        ),
        ConditionSpec(
            name="conflicting",
            description=(
                "30% of verdicts are later corrected. Feedback is append-only and "
                "the correction supersedes, so a consumer sees one verdict per "
                "event."
            ),
            correction_rate=0.30,
        ),
    )
}


def ground_truth(*, seed: int, substrate: str = "rule-testing") -> list[bool]:
    """The independent truth stream. Never written by an analyst."""
    return list(prepare_corpus(seed=seed, substrate=substrate).fit_labels)


def generate(
    *, condition: str, seed: int, substrate: str = "rule-testing"
) -> tuple[list[simulation.SimulatedVerdict], list[bool]]:
    """Analyst verdicts under one condition, plus the truth they refer to."""
    try:
        spec = CONDITIONS[condition]
    except KeyError:
        raise KeyError(
            f"unknown condition {condition!r}; known: {sorted(CONDITIONS)}"
        ) from None

    truth = ground_truth(seed=seed, substrate=substrate)
    reviewable = int(len(truth) * spec.reviewed_prefix)

    verdicts = simulation.simulate_feedback(
        truth[:reviewable],
        seed=seed,
        noise_rate=spec.noise_rate,
        coverage=spec.coverage,
        abstention_rate=spec.abstention_rate,
        false_positive_bias=spec.false_positive_bias,
    )

    # noqa justification: reproducibility, not secrecy.
    rng = random.Random(seed + 1)  # noqa: S311
    adjusted: list[simulation.SimulatedVerdict] = []
    for verdict in verdicts:
        label = verdict.label
        is_malicious = truth[verdict.index]

        if label is not FeedbackLabel.UNCERTAIN:
            if is_malicious and rng.random() < spec.benign_bias:
                label = FeedbackLabel.BENIGN
            elif not is_malicious and rng.random() < spec.malicious_bias:
                label = FeedbackLabel.CONFIRMED_MALICIOUS

        # A correction supersedes the earlier verdict rather than adding a row:
        # the vocabulary is append-only, but a consumer sees only the latest.
        if spec.correction_rate and rng.random() < spec.correction_rate:
            label = (
                FeedbackLabel.CONFIRMED_MALICIOUS
                if is_malicious
                else FeedbackLabel.BENIGN
            )

        adjusted.append(
            simulation.SimulatedVerdict(
                index=verdict.index,
                label=label,
                is_erroneous=(
                    label.binary_label is not None
                    and label.binary_label is not is_malicious
                ),
            )
        )

    return adjusted, truth


def admissible_count(verdicts: list[simulation.SimulatedVerdict]) -> int:
    """How many verdicts the redesigned Arm 2 would let into training data."""
    return sum(1 for verdict in verdicts if arm2._admissible(verdict.label))


def measure(
    *,
    condition: str,
    seed: int,
    max_feedback_fraction: float = arm2.DEFAULT_MAX_FEEDBACK_FRACTION,
    samples: int = DEFAULT_SAMPLES,
    span_days: int = DEFAULT_SPAN_DAYS,
    substrate: str = "rule-testing",
) -> dict[str, Any]:
    """Fit with and without this condition's feedback; score the same test split."""
    verdicts, truth = generate(condition=condition, seed=seed, substrate=substrate)
    observed = prepare_corpus(seed=seed, substrate=substrate)
    telemetry = build_corpus(seed=seed, samples=samples, span_days=span_days)
    telemetry_vectors = [tuple(vector) for vector in telemetry.vectors]

    admitted = [verdict for verdict in verdicts if arm2._admissible(verdict.label)]
    ceiling = int(
        len(telemetry_vectors) * max_feedback_fraction / (1 - max_feedback_fraction)
    )
    if len(admitted) > ceiling:
        rng = random.Random(seed)  # noqa: S311
        admitted = rng.sample(admitted, ceiling)

    feedback_vectors = [observed.fit_vectors[verdict.index] for verdict in admitted]
    poisoned = sum(1 for verdict in admitted if truth[verdict.index])

    def score(vectors: list[tuple[float, ...]]) -> dict[str, Any]:
        detector = _fit(vectors, observed.feature_names, seed)
        scores = [detector.anomaly_score(vector) for vector in observed.test_vectors]
        metrics = _metrics(
            _matrix(scores, observed.test_labels, DEFAULT_THRESHOLD), DEFAULT_THRESHOLD
        )
        metrics["rocAuc"] = roc_auc(scores, observed.test_labels)
        return metrics

    return {
        "condition": condition,
        "seed": seed,
        "verdicts": len(verdicts),
        "feedbackRows": len(feedback_vectors),
        "feedbackFraction": round(
            len(feedback_vectors) / (len(telemetry_vectors) + len(feedback_vectors)), 6
        ),
        # Rows admitted as benign that were in fact malicious. Under
        # `benign_biased` this is the poisoning actually delivered.
        "poisonedRows": poisoned,
        "realisedErrorRate": round(
            sum(1 for v in verdicts if v.is_erroneous) / len(verdicts), 6
        )
        if verdicts
        else None,
        "baseline": score(telemetry_vectors),
        "augmented": score(telemetry_vectors + feedback_vectors),
    }
