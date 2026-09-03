"""The detection baseline, measured in the configuration production actually uses.

**Why this exists.** V4 and V5 established their static baseline by re-fitting an
Isolation Forest on the *labelled evaluation corpus*, whose fit split is 40%
malicious (V6 §4). Production does not do that. ``train_anomaly_model`` fits the
**runtime telemetry generator's** corpus - 6,000 unlabelled vectors over 14
simulated days, roughly 12% suspicious scenarios - and the labelled corpus is
used only for scoring.

The gap was visible in V5 and went unacted upon: ``docs/V5_EXPERIMENTAL_DESIGN.md``
records the deployed artifact at **F1 0.663** on this corpus, while V5's own
experiments reported a static baseline of **F1 0.038** from the refit. V5 noted
the discrepancy only as a reason to withdraw prediction P1, rather than as
evidence that the experimental baseline was misconfigured.

**What is held constant.** Scoring uses the same labelled corpus, the same V4
``stratified_group`` split and the same frozen 0.65 threshold as Track 1, so the
number is directly comparable to the static baseline it replaces. Only the
fitting data changes - which is the entire point.

**On the two adaptation arms.** Arm 1, threshold adaptation, chooses an operating
point from labelled observed events and works whatever the model was fitted on.
Arm 2, curation, purifies the *fit set* - and production's fit set is unlabelled
telemetry, not observed events, so analyst labels have nothing there to purify.
That is reported as inapplicable rather than quietly skipped; it is a real
constraint on V5's design, not an omission here.

**Nothing here is deployed.** This measures a configuration; it does not register
a model or touch the production registry.
"""

from __future__ import annotations

from typing import Any

from app.adaptation.experiments import simulation
from app.adaptation.experiments.scenarios import (
    DEFAULT_THRESHOLD,
    MAX_THRESHOLD_STEP,
    _fit,
    _matrix,
    _metrics,
    prepare_corpus,
)
from app.evaluation.metrics.ranking import roc_auc
from app.ml.training.corpus import DEFAULT_SAMPLES, DEFAULT_SPAN_DAYS, build_corpus

FIT_CORPUS = "runtime-telemetry-generator"
SCORED_ON = "aegisx-detection-eval test split"


def measure(
    *,
    seed: int,
    samples: int = DEFAULT_SAMPLES,
    span_days: int = DEFAULT_SPAN_DAYS,
    noise_rate: float = 0.05,
    coverage: float = 0.5,
) -> dict[str, Any]:
    """Fit as production fits; score as Track 1 scores."""
    training = build_corpus(seed=seed, samples=samples, span_days=span_days)
    labelled = prepare_corpus(seed=seed)

    fit_vectors = [tuple(vector) for vector in training.vectors]
    detector = _fit(fit_vectors, labelled.feature_names, seed)

    test_vectors = labelled.test_vectors
    test_labels = labelled.test_labels
    scores = [detector.anomaly_score(vector) for vector in test_vectors]

    # Arm 1 remains available: it reads labelled observed events, not the fit
    # set. Applied to the *fit* split's labels so nothing tunes on the test set.
    verdicts = simulation.simulate_feedback(
        labelled.fit_labels, seed=seed, noise_rate=noise_rate, coverage=coverage
    )
    believed = {
        v.index: v.label.binary_label
        for v in verdicts
        if v.label.is_training_eligible and v.label.binary_label is not None
    }
    adapted_threshold = DEFAULT_THRESHOLD
    labelled_indices = sorted(believed)
    if labelled_indices:
        adapted_threshold = simulation.choose_threshold(
            [detector.anomaly_score(labelled.fit_vectors[i]) for i in labelled_indices],
            [believed[i] for i in labelled_indices],
            current=DEFAULT_THRESHOLD,
            max_step=MAX_THRESHOLD_STEP,
        )

    return {
        "seed": seed,
        "fitCorpus": FIT_CORPUS,
        "fitSamples": len(fit_vectors),
        "fitFingerprint": training.fingerprint(),
        "scoredOn": SCORED_ON,
        "datasetFingerprint": labelled.fingerprint,
        "splitFingerprint": labelled.split_fingerprint,
        # The two corpora are generated independently; reported so the claim is
        # checkable rather than asserted.
        "fitScoringOverlap": len(set(fit_vectors) & set(test_vectors)),
        "rocAuc": roc_auc(scores, test_labels),
        "frozenThreshold": _metrics(
            _matrix(scores, test_labels, DEFAULT_THRESHOLD), DEFAULT_THRESHOLD
        ),
        "adaptedThreshold": _metrics(
            _matrix(scores, test_labels, adapted_threshold), adapted_threshold
        ),
        "arms": {
            "thresholdAdaptation": {
                "applicable": True,
                "threshold": adapted_threshold,
                "reason": (
                    "Chooses an operating point from labelled observed events; "
                    "independent of what the model was fitted on."
                ),
            },
            "curation": {
                "applicable": False,
                "reason": (
                    "Curation purifies the fit set. Production's fit set is the "
                    "unlabelled runtime telemetry corpus, not observed events, "
                    "so analyst labels have nothing there to purify. V5's Arm 2 "
                    "assumes the fit set and the observed event stream are the "
                    "same collection; in production they are not."
                ),
            },
        },
    }
