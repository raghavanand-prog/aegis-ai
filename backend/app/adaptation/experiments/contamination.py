"""Does fit-set contamination explain the V4/V5 detection baseline?

**The finding this module exists to test.** The labelled evaluation corpus's fit
split is **40% malicious** (624 of 1,560 at the Track 1 size). The production
anomaly model is not trained on it: ``train_anomaly_model`` fits the runtime
telemetry generator's corpus, whose suspicious scenarios run at about **12%**.
The labelled corpus's own provenance says as much - *"out of distribution for the
anomaly model trained on the runtime telemetry generator - ML metrics on this
corpus are a lower bound."*

V4 and V5 nonetheless re-fitted an Isolation Forest on that 40%-malicious split
and reported the result as the **static baseline** against which every
adaptation gain is measured. An unsupervised density estimator fitted on data
where two fifths of the mass is attack traffic has learned attacks as normal.

**A correction to how this was first described.** V6 §3.3 called it a violation
of the ``contamination`` parameter "by a factor of five". The direction is right
but the mechanism named was wrong: ``contamination`` never reaches
``anomaly_score``, which is a logistic squash of the raw score about
``_raw_offset``, the **median of the training scores**. The parameter only sets
scikit-learn's ``offset_`` for ``predict()``. The binding problem is the fitting
data itself - it shapes the trees, and it sets the median that every score is
measured against.

**One variable.** The fit set is resampled to a fixed size at each contamination
level, so sample count cannot be confounded with contamination, and the test set
never moves.
"""

from __future__ import annotations

import random
from typing import Any

from app.adaptation.experiments.scenarios import (
    CONTAMINATION,
    DEFAULT_THRESHOLD,
    N_ESTIMATORS,
    _fit,
    _matrix,
    _metrics,
    prepare_corpus,
)
from app.evaluation.metrics.ranking import roc_auc

#: Fit-set size held constant across the sweep. The largest round number the
#: Track 1 corpus can supply at every level from 0% to 40% malicious.
DEFAULT_FIT_SIZE = 900

#: The levels of record. 0.40 is the corpus as V4/V5 used it; 0.12 approximates
#: the production telemetry generator; 0.08 is the configured contamination.
LEVELS = (0.40, 0.30, 0.20, 0.12, 0.08, 0.04, 0.0)

__all__ = ["CONTAMINATION", "N_ESTIMATORS", "build_fit_set", "measure", "LEVELS"]


def build_fit_set(
    *, seed: int, malicious_fraction: float, size: int = DEFAULT_FIT_SIZE
) -> dict[str, Any]:
    """Resample the fit split to ``size`` rows at the requested contamination."""
    corpus = prepare_corpus(seed=seed)

    benign = [
        vector
        for vector, label in zip(corpus.fit_vectors, corpus.fit_labels, strict=True)
        if not label
    ]
    malicious = [
        vector
        for vector, label in zip(corpus.fit_vectors, corpus.fit_labels, strict=True)
        if label
    ]

    wanted_malicious = round(size * malicious_fraction)
    wanted_benign = size - wanted_malicious
    if wanted_malicious > len(malicious) or wanted_benign > len(benign):
        raise ValueError(
            f"the corpus cannot supply {wanted_benign} benign and "
            f"{wanted_malicious} malicious rows at size {size}; it holds "
            f"{len(benign)} and {len(malicious)}"
        )

    # noqa justification: reproducibility, not secrecy - the same argument the
    # feedback simulator and the seed plan carry.
    rng = random.Random(seed)  # noqa: S311
    fit_vectors = rng.sample(benign, wanted_benign) + rng.sample(
        malicious, wanted_malicious
    )
    fit_labels = [False] * wanted_benign + [True] * wanted_malicious
    order = list(range(size))
    rng.shuffle(order)

    return {
        "size": size,
        "maliciousFraction": round(wanted_malicious / size, 6),
        "fitVectors": [fit_vectors[index] for index in order],
        "fitLabels": [fit_labels[index] for index in order],
        # Never resampled. The scoring set must not move when the fit set does.
        "testVectors": corpus.test_vectors,
        "testLabels": corpus.test_labels,
        "featureNames": corpus.feature_names,
        "fingerprint": corpus.fingerprint,
        "splitFingerprint": corpus.split_fingerprint,
    }


def measure(
    *, seed: int, malicious_fraction: float, size: int = DEFAULT_FIT_SIZE
) -> dict[str, Any]:
    """Fit at one contamination level and score the untouched test set."""
    built = build_fit_set(seed=seed, malicious_fraction=malicious_fraction, size=size)
    detector = _fit(built["fitVectors"], built["featureNames"], seed)

    scores = [detector.anomaly_score(vector) for vector in built["testVectors"]]
    labels = built["testLabels"]

    return {
        "seed": seed,
        "maliciousFraction": built["maliciousFraction"],
        "fitSize": built["size"],
        "datasetFingerprint": built["fingerprint"],
        "splitFingerprint": built["splitFingerprint"],
        # Threshold-free: separability, independent of any operating point.
        "rocAuc": roc_auc(scores, labels),
        # At the frozen threshold V5 reported its static baseline from.
        "metrics": _metrics(_matrix(scores, labels, DEFAULT_THRESHOLD), DEFAULT_THRESHOLD),
    }
