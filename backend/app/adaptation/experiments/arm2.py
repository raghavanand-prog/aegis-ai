"""Arm 2, redesigned to act in the configuration production actually uses.

**Why V5's Arm 2 could not run.** Curation purified the fit set by dropping rows
analysts called malicious. That presumes the fit set *is* the observed event
stream. V6 §5 measured that in production it is not: ``train_anomaly_model``
fits unlabelled runtime telemetry, so analyst labels have nothing there to
purify. In V5's experiments the two happened to be the same collection, which is
why curation appeared to work - it was removing the 40% contamination §4
identified, not learning from feedback.

**The redesign inverts the direction.** Rather than removing analyst-identified
malicious rows from a corpus of observed events, it *adds* analyst-verified
**benign** observed events to the telemetry corpus. An Isolation Forest consumes
"here is more traffic that is normal" natively; that is what its fit set is. And
it targets the weakness §5 measured - a **34% false-positive rate** - using the
most abundant real signal a SOC produces, false-positive triage.

    telemetry corpus (unlabelled)
      + observed events an analyst verified benign
      - anything an analyst called malicious, suspicious or uncertain
      bounded by max_feedback_fraction

**This is a poisoning surface and is treated as one.** Analyst-supplied rows
enter training data, so a mistaken or hostile analyst could teach the model that
an attack is normal. Three bounds, each asserted by test:

1. **Admission is positive-listed.** A row enters only if its label is
   training-eligible *and* projects to benign. ``confirmed_malicious`` and
   ``true_positive`` are refused; so are ``suspicious`` and ``uncertain``, which
   describe a state of investigation rather than a class.
2. **The feedback share is capped.** Feedback rows can never exceed
   ``max_feedback_fraction`` of the final corpus, which bounds the blast radius
   of bad labels regardless of how many arrive.
3. **The telemetry corpus is augmented, never replaced.**

**Nothing here deploys.** This builds and measures a candidate fit set. Reaching
production still requires the approved-proposal path and ``activate_model``.
"""

from __future__ import annotations

import random
from typing import Any

from app.adaptation.experiments import simulation
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

FIT_CORPUS = "runtime-telemetry-generator + verified-benign feedback"

#: Default ceiling on the share of the fit set that may come from analyst
#: feedback. Not tuned - chosen as a conservative bound before measuring, so the
#: safety property is not a function of the result it produced.
DEFAULT_MAX_FEEDBACK_FRACTION = 0.20


def _admissible(label: FeedbackLabel) -> bool:
    """Positive list. Only confident, benign-projecting verdicts may train."""
    return label.is_training_eligible and label.binary_label is False


def build_augmented_corpus(
    *,
    seed: int,
    noise_rate: float = 0.05,
    coverage: float = 0.5,
    max_feedback_fraction: float = DEFAULT_MAX_FEEDBACK_FRACTION,
    samples: int = DEFAULT_SAMPLES,
    span_days: int = DEFAULT_SPAN_DAYS,
    all_benign_attack: bool = False,
) -> dict[str, Any]:
    """Build the candidate fit set: telemetry plus verified-benign feedback.

    ``all_benign_attack`` is the adversarial scenario - every verdict is
    "benign", including on genuinely malicious events. It exists to measure that
    the cap bounds the damage, and is never a normal operating mode.
    """
    if not 0.0 <= max_feedback_fraction < 1.0:
        raise ValueError(
            f"max_feedback_fraction must be between 0 and 1, got {max_feedback_fraction}"
        )

    telemetry = build_corpus(seed=seed, samples=samples, span_days=span_days)
    telemetry_vectors = [tuple(vector) for vector in telemetry.vectors]

    # Observed events an analyst reviewed. The fit split stands in for the
    # production event stream; the test split is never touched.
    observed = prepare_corpus(seed=seed)

    if all_benign_attack:
        verdicts = [
            simulation.SimulatedVerdict(
                index=index, label=FeedbackLabel.BENIGN, is_erroneous=is_malicious
            )
            for index, is_malicious in enumerate(observed.fit_labels)
        ]
    else:
        verdicts = simulation.simulate_feedback(
            observed.fit_labels, seed=seed, noise_rate=noise_rate, coverage=coverage
        )

    admitted = [verdict for verdict in verdicts if _admissible(verdict.label)]

    # The cap is applied to the *final* corpus size, so feedback can never
    # exceed the configured share however much of it arrives.
    ceiling = int(len(telemetry_vectors) * max_feedback_fraction / (1 - max_feedback_fraction))
    if len(admitted) > ceiling:
        # noqa justification: reproducibility, not secrecy.
        rng = random.Random(seed)  # noqa: S311
        admitted = rng.sample(admitted, ceiling)

    feedback_vectors = [observed.fit_vectors[verdict.index] for verdict in admitted]
    fit_vectors = telemetry_vectors + feedback_vectors
    poisoned = sum(1 for verdict in admitted if observed.fit_labels[verdict.index])

    return {
        "size": len(fit_vectors),
        "telemetryRows": len(telemetry_vectors),
        "feedbackRows": len(feedback_vectors),
        "feedbackFraction": (
            len(feedback_vectors) / len(fit_vectors) if fit_vectors else 0.0
        ),
        "admittedLabels": sorted({verdict.label.value for verdict in admitted}),
        # Rows an analyst called benign that were in fact malicious. In normal
        # operation this is label noise; under `all_benign_attack` it is the
        # poisoning being bounded.
        "poisonedRows": poisoned,
        "fitVectors": fit_vectors,
        "admittedIndices": [verdict.index for verdict in admitted],
        "observed": observed,
    }


def measure(
    *,
    seed: int,
    noise_rate: float = 0.05,
    coverage: float = 0.5,
    max_feedback_fraction: float = DEFAULT_MAX_FEEDBACK_FRACTION,
) -> dict[str, Any]:
    """Fit with and without the feedback augmentation; score the same test split."""
    built = build_augmented_corpus(
        seed=seed,
        noise_rate=noise_rate,
        coverage=coverage,
        max_feedback_fraction=max_feedback_fraction,
    )
    observed = built["observed"]
    test_vectors = observed.test_vectors
    test_labels = observed.test_labels

    def score(vectors: list[tuple[float, ...]]) -> dict[str, Any]:
        detector = _fit(vectors, observed.feature_names, seed)
        scores = [detector.anomaly_score(vector) for vector in test_vectors]
        metrics = _metrics(
            _matrix(scores, test_labels, DEFAULT_THRESHOLD), DEFAULT_THRESHOLD
        )
        metrics["rocAuc"] = roc_auc(scores, test_labels)
        return metrics

    baseline_vectors = built["fitVectors"][: built["telemetryRows"]]
    admitted_vectors = {
        observed.fit_vectors[index] for index in built["admittedIndices"]
    }

    return {
        "seed": seed,
        "fitCorpus": FIT_CORPUS,
        "telemetryRows": built["telemetryRows"],
        "feedbackRows": built["feedbackRows"],
        "feedbackFraction": round(built["feedbackFraction"], 6),
        "poisonedRows": built["poisonedRows"],
        "datasetFingerprint": observed.fingerprint,
        "splitFingerprint": observed.split_fingerprint,
        # Every admitted row indexes the *fit* split, and the splitter makes
        # fit and test sample-disjoint (test_no_sample_appears_in_two_splits),
        # so no scored sample can be trained on. Reported so that is checkable.
        "admittedOutsideFitSplit": sum(
            1
            for index in built["admittedIndices"]
            if not 0 <= index < len(observed.fit_vectors)
        ),
        # Not leakage: distinct events can share a feature vector (V6 §2.7
        # measured 5.1% of test rows). Reported rather than hidden, because a
        # reader would otherwise discover it and assume the worse explanation.
        "admittedVectorsAlsoSeenInScoringSet": len(
            admitted_vectors & set(test_vectors)
        ),
        "baseline": score(baseline_vectors),
        "augmented": score(built["fitVectors"]),
    }
