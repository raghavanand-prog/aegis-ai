"""Why V6 §5's gap exists: a fixed threshold is not portable between models.

§5 measured a model fitted on the telemetry corpus reaching **F1 0.6526** on the
eval test split while one refitted on the eval corpus reached **0.0389** - a 17x
gap. §13.2 established that contamination cannot explain it, since both corpora
are around 40% malicious, and left the question open. This answers it.

**The score scale is relative to each model's own fit set.**
``IsolationForestDetector.anomaly_score`` is a logistic squash of the raw score
about ``_raw_offset``, and ``_raw_offset`` is the **median of the training
scores**. So 0.5 means "typical of *this model's* training data", not "half as
anomalous as the maximum". A frozen 0.65 therefore names a different operating
point for every model, and comparing two differently-fitted models at one fixed
threshold compares their calibrations at least as much as their detection.

Measured on the eval test split: 0.65 sits at the **53.6th percentile** of the
telemetry-fitted model's scores and the **99.2nd** of the eval-fitted one. The
second flags almost nothing, which is the entire "near-inert baseline".

**The irony worth stating.** The telemetry-fitted model scores well at 0.65
partly *because the eval corpus is out of distribution for it*: everything looks
somewhat unusual, its whole score distribution shifts up, and 0.65 lands
usefully mid-range. Its apparent superiority at that threshold is in part an
artefact of the corpus being unfamiliar to it.

**What this does not overturn.** §4's contamination finding is threshold-free at
its core - ROC-AUC moves 0.53 to 0.93 and best-achievable F1 moves 0.571 to
0.841 as contamination falls. Contamination genuinely degrades discrimination.
What §4's *F1 column* does is understate the effect, because 0.65 is badly
placed at every level of that sweep.
"""

from __future__ import annotations

import statistics
from typing import Any

from app.adaptation.experiments.scenarios import (
    DEFAULT_THRESHOLD,
    _fit,
    _matrix,
    _metrics,
    prepare_corpus,
)
from app.evaluation.metrics.ranking import roc_auc
from app.ml.training.corpus import DEFAULT_SPAN_DAYS, build_corpus


def _best_f1(scores: list[float], labels: list[bool]) -> tuple[float, float | None]:
    """Highest F1 any threshold could reach, and where.

    This is the model's discriminative ceiling on this data, independent of
    where anyone happened to freeze the operating point.
    """
    best_value, best_threshold = 0.0, None
    for candidate in sorted({round(score, 3) for score in scores}):
        metrics = _metrics(_matrix(scores, labels, candidate), candidate)
        if metrics["f1"] is not None and metrics["f1"] > best_value:
            best_value, best_threshold = metrics["f1"], candidate
    return best_value, best_threshold


def _profile(detector, vectors, labels) -> dict[str, Any]:
    scores = [detector.anomaly_score(vector) for vector in vectors]
    frozen = _metrics(_matrix(scores, labels, DEFAULT_THRESHOLD), DEFAULT_THRESHOLD)
    best_f1, best_threshold = _best_f1(scores, labels)
    below = sum(1 for score in scores if score < DEFAULT_THRESHOLD)
    return {
        "rocAuc": roc_auc(scores, labels),
        "f1AtFrozen": frozen["f1"],
        "recallAtFrozen": frozen["recall"],
        "bestF1": round(best_f1, 6),
        "bestThreshold": best_threshold,
        # Where the frozen threshold actually sits in this model's own output.
        "frozenPercentile": round(100.0 * below / len(scores), 2),
        "scoreMedian": round(statistics.median(scores), 6),
    }


def training_median_score(*, seed: int = 1337, samples: int = 2000) -> float:
    """Score the fit set assigns to its own median. Should be ~0.5 by construction."""
    corpus = prepare_corpus(seed=seed)
    detector = _fit(corpus.fit_vectors, corpus.feature_names, seed)
    scores = [detector.anomaly_score(vector) for vector in corpus.fit_vectors]
    return statistics.median(scores)


def compare(
    *, seed: int = 1337, samples: int = 6000, span_days: int = DEFAULT_SPAN_DAYS
) -> dict[str, Any]:
    """Decompose §5's gap into threshold placement and discrimination."""
    corpus = prepare_corpus(seed=seed)
    telemetry = [
        tuple(vector)
        for vector in build_corpus(seed=seed, samples=samples, span_days=span_days).vectors
    ]

    arms = {
        "telemetryFit": _profile(
            _fit(telemetry, corpus.feature_names, seed),
            corpus.test_vectors,
            corpus.test_labels,
        ),
        "evalCorpusFit": _profile(
            _fit(corpus.fit_vectors, corpus.feature_names, seed),
            corpus.test_vectors,
            corpus.test_labels,
        ),
    }

    frozen_ratio = arms["telemetryFit"]["f1AtFrozen"] / max(
        arms["evalCorpusFit"]["f1AtFrozen"], 1e-9
    )
    best_ratio = arms["telemetryFit"]["bestF1"] / max(arms["evalCorpusFit"]["bestF1"], 1e-9)

    # How much of the observed gap disappears once each model is allowed its own
    # operating point. The remainder is genuine discriminative difference.
    frozen_gap = arms["telemetryFit"]["f1AtFrozen"] - arms["evalCorpusFit"]["f1AtFrozen"]
    best_gap = arms["telemetryFit"]["bestF1"] - arms["evalCorpusFit"]["bestF1"]
    share = (frozen_gap - best_gap) / frozen_gap if frozen_gap > 0 else None

    return {
        "seed": seed,
        "scoredOn": "aegisx-detection-eval test split",
        "frozenThreshold": DEFAULT_THRESHOLD,
        **{"telemetryFit": arms["telemetryFit"], "evalCorpusFit": arms["evalCorpusFit"]},
        "frozenRatio": round(frozen_ratio, 4),
        "bestRatio": round(best_ratio, 4),
        "shareFromThresholdPlacement": round(share, 4) if share is not None else None,
        "interpretation": (
            "anomaly_score is calibrated to the median of each model's own "
            "training scores, so a frozen threshold names a different operating "
            "point per model. Most of the gap is where 0.65 falls, not how well "
            "either model separates."
        ),
    }


def contamination_sweep(
    *, seed: int = 1337, levels: tuple[float, ...] = (0.40, 0.20, 0.08, 0.04)
) -> dict[float, dict[str, Any]]:
    """§4's sweep, re-measured with threshold-free figures beside the frozen one."""
    from app.adaptation.experiments import contamination

    out: dict[float, dict[str, Any]] = {}
    for level in levels:
        built = contamination.build_fit_set(seed=seed, malicious_fraction=level, size=900)
        detector = _fit(built["fitVectors"], built["featureNames"], seed)
        out[level] = _profile(detector, built["testVectors"], built["testLabels"])
    return out
