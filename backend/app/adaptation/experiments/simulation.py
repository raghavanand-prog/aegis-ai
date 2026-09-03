"""Simulated analysts, and the two mechanisms feedback can legitimately drive.

**The design problem.** The production detector is an Isolation Forest, which is
unsupervised. Analyst feedback is labels. Labels do not train an unsupervised
model, so "feedback-driven adaptation" cannot mean the obvious thing, and
quietly substituting a supervised model would be the central dishonesty
available to this project.

Two mechanisms use labels in ways this detector can actually consume:

``choose_threshold`` (Arm 1)
    Labels choose an operating point on the existing score distribution. The
    model is untouched; only the decision boundary moves, clamped to the
    configured safety step.

``curate_fit_set`` (Arm 2)
    Isolation Forest assumes its fitting data is mostly normal. Contaminate that
    and it degrades. Feedback says which observed events were genuinely
    malicious, so it can purify the fit set.

Neither turns the detector into a supervised model.

**The simulated analyst** is deliberately not ground truth renamed. It gets
things wrong, reviews only part of the queue, abstains, and is biased toward the
alerts that annoy it - which is what real analysts do and what a feedback loop
has to survive.
"""

from __future__ import annotations

import random
from dataclasses import dataclass

from app.adaptation.feedback.labels import FeedbackLabel


@dataclass(frozen=True)
class SimulatedVerdict:
    """One simulated analyst decision about one sample."""

    #: Position in the corpus this verdict refers to.
    index: int
    label: FeedbackLabel
    #: Whether this particular verdict is wrong. Known only in simulation - it
    #: is what lets the report state the true noise rate rather than the
    #: requested one.
    is_erroneous: bool


def _label_for(is_malicious: bool) -> FeedbackLabel:
    return (
        FeedbackLabel.CONFIRMED_MALICIOUS if is_malicious else FeedbackLabel.BENIGN
    )


def simulate_feedback(
    ground_truth: list[bool],
    *,
    seed: int,
    noise_rate: float = 0.05,
    coverage: float = 1.0,
    abstention_rate: float = 0.10,
    false_positive_bias: float = 0.0,
    shuffle_labels: bool = False,
) -> list[SimulatedVerdict]:
    """Generate analyst verdicts over a corpus.

    ``shuffle_labels`` produces the control condition: the same volume of
    feedback with the label signal destroyed. If adaptation improves under it,
    the improvement did not come from feedback.
    """
    # noqa justification: this RNG must be *reproducible*, which is the
    # opposite of what a cryptographic generator provides. Nothing here touches
    # a secret; it draws simulated analyst mistakes, and a result that cannot be
    # regenerated from its seed is not a result.
    rng = random.Random(seed)  # noqa: S311 - reproducibility, not secrecy
    verdicts: list[SimulatedVerdict] = []

    for index, is_malicious in enumerate(ground_truth):
        if rng.random() > coverage:
            continue  # not reviewed

        if rng.random() < abstention_rate:
            # Recorded, never counted. The vocabulary refuses to treat
            # hesitation as a verdict, and the loop must handle that.
            verdicts.append(
                SimulatedVerdict(index=index, label=FeedbackLabel.UNCERTAIN, is_erroneous=False)
            )
            continue

        believed = is_malicious
        if shuffle_labels:
            believed = rng.random() < 0.5
        else:
            if rng.random() < noise_rate:
                believed = not believed
            # Analysts label what annoys them: a benign event that fired an
            # alert is disproportionately likely to be reported as a false
            # positive, which is the realistic bias in a feedback set.
            elif not is_malicious and rng.random() < false_positive_bias:
                believed = False

        label = (
            FeedbackLabel.FALSE_POSITIVE
            if (not believed and not shuffle_labels and rng.random() < 0.5)
            else _label_for(believed)
        )
        verdicts.append(
            SimulatedVerdict(
                index=index,
                label=label,
                is_erroneous=label.binary_label is not is_malicious,
            )
        )

    return verdicts


def choose_threshold(
    scores: list[float],
    labels: list[bool],
    *,
    current: float,
    max_step: float,
    objective: str = "f1",
) -> float:
    """Arm 1: pick an operating point from labelled data, bounded by the step.

    The clamp is the safety property, not the search. V4 measured what happens
    when this threshold is chased freely on flow telemetry: 987 alerts per
    1,000 events.
    """
    if not scores or not labels or len(scores) != len(labels):
        raise ValueError(
            "Cannot choose a threshold without labelled data on both sides. "
            "An operating point selected from nothing is not a measurement."
        )

    low = max(0.0, current - max_step)
    high = min(1.0, current + max_step)

    best_threshold = current
    best_score = -1.0
    # 0.005 steps across the permitted band: fine enough to matter, coarse
    # enough not to fit noise in a few hundred labelled samples.
    steps = int(round((high - low) / 0.005)) + 1
    for step in range(steps):
        candidate = round(low + step * 0.005, 4)
        tp = sum(1 for s, y in zip(scores, labels, strict=True) if s >= candidate and y)
        fp = sum(1 for s, y in zip(scores, labels, strict=True) if s >= candidate and not y)
        fn = sum(1 for s, y in zip(scores, labels, strict=True) if s < candidate and y)

        precision = tp / (tp + fp) if (tp + fp) else 0.0
        recall = tp / (tp + fn) if (tp + fn) else 0.0
        if objective == "precision":
            value = precision
        elif objective == "recall":
            value = recall
        else:
            value = (
                2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
            )

        if value > best_score:
            best_score = value
            best_threshold = candidate

    return best_threshold


def curate_fit_set(
    vectors: list[tuple[float, ...]],
    verdicts: dict[int, bool],
) -> list[tuple[float, ...]]:
    """Arm 2: remove events analysts confirmed malicious from the fit set.

    Only *confirmed malicious* rows are dropped. An unreviewed event is not
    evidence of anything, and dropping unreviewed data would shrink the corpus
    for no reason while making the result depend on review coverage rather than
    on review content.
    """
    kept = [
        vector for index, vector in enumerate(vectors) if not verdicts.get(index, False)
    ]
    if not kept:
        raise ValueError(
            "Curation removed every sample; refusing to return an empty fit set. "
            "A model fitted on nothing is not a model, and the failure would "
            "surface much later as an unexplained score distribution."
        )
    return kept
