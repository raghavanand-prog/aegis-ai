"""Experimental detector comparison for V6 Track 3, hypothesis 5.

Track 3 measured that nine of thirteen withheld attack categories are
unreachable at any threshold under the production Isolation Forest: they score
inside, or below, the benign mass. That is either a fact about **Isolation
Forest** or a fact about the **feature space**, and the two imply completely
different work - swap the detector, or engineer features. This module exists to
tell them apart.

**Separability is measured threshold-free, as ROC-AUC.** Track 3 also showed
that recall in this experiment is dominated by the ``MAX_THRESHOLD_STEP`` clamp,
which saturated in 256 of 260 runs. Comparing detectors by recall would compare
operating points. AUC is rank-based, which additionally means the detectors'
scores never need to be put on a common scale - only their orderings are used.

**The supervised entry is a diagnostic ceiling, not a candidate.** The
production detector is unsupervised; V5 explicitly refused to substitute a
supervised model and call the result adaptation, and nothing here reverses that.
It answers one question: does the feature space contain enough information to
separate this unseen category from benign traffic *at all*, given every label
available? If even that fails, the detector class is not the binding constraint
and hypothesis 5 is wrong. It is marked ``deployable=False`` and asserted so by
test.

**Nothing here can reach production.** This module never imports the model
registry, writes an artifact, or creates a database row; a test asserts that
against the source. The only write into production detection state remains
``activate_model`` behind an approved proposal.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass
from functools import lru_cache
from typing import Any

from app.adaptation.experiments.scenarios import CONTAMINATION, N_ESTIMATORS
from app.evaluation.datasets.adapters import synthetic_dataset
from app.evaluation.metrics.ranking import roc_auc
from app.evaluation.splits import STRATIFIED_GROUP, build_split
from app.ml.features.extractor import FEATURE_NAMES, FeatureExtractor
from app.ml.models.isolation_forest import IsolationForestDetector

MATURITY_PRODUCTION = "production"
MATURITY_CANDIDATE = "candidate"
MATURITY_EXPERIMENTAL = "experimental"
MATURITIES = frozenset({MATURITY_PRODUCTION, MATURITY_CANDIDATE, MATURITY_EXPERIMENTAL})

#: Attack samples per category. Chosen so every category clears V4's
#: MIN_PER_CLASS = 20 guard in the held-out split (24 at the smallest), which the
#: default corpus does not.
SAMPLES_PER_CLASS = 160

Vector = tuple[float, ...]
#: A fitted detector, reduced to the only thing the comparison needs: an
#: ordering over vectors where higher means "more anomalous".
Scorer = Callable[[Sequence[Vector]], list[float]]


@dataclass(frozen=True)
class DetectorSpec:
    name: str
    maturity: str
    #: True where the detector consumes labels. Such a detector is a diagnostic
    #: here, never a deployment candidate - the production detector is
    #: unsupervised and V5's refusal to quietly change that still stands.
    requires_labels: bool
    deployable: bool
    build: Callable[[list[Vector], list[bool], int], Scorer]
    notes: str


def _build_isolation_forest(vectors: list[Vector], labels: list[bool], seed: int) -> Scorer:
    detector = IsolationForestDetector(
        feature_names=tuple(FEATURE_NAMES),
        contamination=CONTAMINATION,
        random_state=seed,
        n_estimators=N_ESTIMATORS,
    )
    detector.fit(vectors)
    return lambda batch: [detector.anomaly_score(vector) for vector in batch]


def _build_local_outlier_factor(vectors: list[Vector], labels: list[bool], seed: int) -> Scorer:
    from sklearn.neighbors import LocalOutlierFactor

    model = LocalOutlierFactor(n_neighbors=20, novelty=True, contamination=CONTAMINATION)
    model.fit(vectors)
    # `score_samples` is higher for inliers; negate so higher means anomalous,
    # matching every other detector's direction.
    return lambda batch: [-float(value) for value in model.score_samples(list(batch))]


def _build_one_class_svm(vectors: list[Vector], labels: list[bool], seed: int) -> Scorer:
    from sklearn.svm import OneClassSVM

    model = OneClassSVM(kernel="rbf", gamma="scale", nu=CONTAMINATION)
    model.fit(vectors)
    return lambda batch: [-float(value) for value in model.score_samples(list(batch))]


def _build_supervised_ceiling(vectors: list[Vector], labels: list[bool], seed: int) -> Scorer:
    from sklearn.ensemble import RandomForestClassifier

    model = RandomForestClassifier(n_estimators=200, random_state=seed, n_jobs=1)
    model.fit(vectors, labels)
    return lambda batch: [float(row[1]) for row in model.predict_proba(list(batch))]


REGISTRY: dict[str, DetectorSpec] = {
    spec.name: spec
    for spec in (
        DetectorSpec(
            name="isolation_forest",
            maturity=MATURITY_PRODUCTION,
            requires_labels=False,
            deployable=True,
            build=_build_isolation_forest,
            notes="The incumbent, at the deployed configuration. The comparison of record.",
        ),
        DetectorSpec(
            name="local_outlier_factor",
            maturity=MATURITY_CANDIDATE,
            requires_labels=False,
            deployable=True,
            build=_build_local_outlier_factor,
            notes=(
                "Local density rather than global partitioning. The natural "
                "contrast if Isolation Forest's axis-aligned splits are what "
                "hide a novel category inside the benign mass."
            ),
        ),
        DetectorSpec(
            name="one_class_svm",
            maturity=MATURITY_CANDIDATE,
            requires_labels=False,
            deployable=True,
            build=_build_one_class_svm,
            notes="A kernel boundary around normality rather than a density estimate.",
        ),
        DetectorSpec(
            name="supervised_ceiling",
            maturity=MATURITY_EXPERIMENTAL,
            requires_labels=True,
            deployable=False,
            build=_build_supervised_ceiling,
            notes=(
                "DIAGNOSTIC ONLY, never deployable. Bounds what the feature "
                "space can support given every available label. If this cannot "
                "separate a withheld category either, the features are the "
                "limit and hypothesis 5 is wrong."
            ),
        ),
    )
}


@lru_cache(maxsize=8)
def _prepare(seed: int, samples_per_class: int | None):
    """Extract features and split, once per corpus.

    Every detector for a given seed faces the identical fit and test sets, which
    is what makes the comparison one-variable. Caching is safe because both
    steps are deterministic in the seed - and without it the comparison spends
    most of its time re-extracting the same features.
    """
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
    return features, fit_samples, test_samples, dataset.fingerprint(), plan.fingerprint()


def measure_separability(
    *,
    seed: int,
    withheld_category: str,
    detector: str,
    samples_per_class: int | None = SAMPLES_PER_CLASS,
) -> dict[str, Any]:
    """How well does ``detector`` rank an unseen attack category above benign?

    The category is withheld from the fit set for every detector, the supervised
    ceiling included, so all of them face the same unseen behaviour.

    **This runs on a larger corpus than Track 1.** V4's ``roc_auc`` refuses to
    report an interval with fewer than ``MIN_PER_CLASS`` = 20 observations a
    side, and the default corpus leaves only ~15 held-out samples per attack
    category. The guard is right, so the corpus is enlarged to satisfy it rather
    than the guard weakened to satisfy the corpus. Results here therefore carry a
    different dataset fingerprint from section 1 and are not comparable to it
    row-for-row.
    """
    try:
        spec = REGISTRY[detector]
    except KeyError:
        raise KeyError(
            f"unknown detector {detector!r}; known: {sorted(REGISTRY)}"
        ) from None

    features, fit_samples, test_samples, fingerprint, split_fingerprint = _prepare(
        seed, samples_per_class
    )

    seen = [s for s in fit_samples if s.category != withheld_category]
    novel = [s for s in test_samples if s.category == withheld_category]
    benign = [s for s in test_samples if not s.is_malicious]
    historical = [
        s
        for s in test_samples
        if s.is_malicious and s.category != withheld_category
    ]
    if not novel:
        raise ValueError(
            f"no held-out samples of {withheld_category!r}; separability cannot "
            "be measured"
        )

    scorer = spec.build(
        [features[s.id] for s in seen], [bool(s.is_malicious) for s in seen], seed
    )

    novel_scores = scorer([features[s.id] for s in novel])
    benign_scores = scorer([features[s.id] for s in benign])
    historical_scores = scorer([features[s.id] for s in historical])

    return {
        "detector": spec.name,
        "maturity": spec.maturity,
        "deployable": spec.deployable,
        "requiresLabels": spec.requires_labels,
        "withheldCategory": withheld_category,
        "seed": seed,
        "datasetFingerprint": fingerprint,
        "splitFingerprint": split_fingerprint,
        # Zero by construction, reported so the claim is checkable rather than
        # asserted - the failure mode Track 3 found in the V5 harness.
        "withheldInFitSet": sum(1 for s in seen if s.category == withheld_category),
        "novelSamples": len(novel),
        "benignSamples": len(benign),
        # The measurement. 0.5 is "cannot tell this category from benign at
        # all"; 1.0 is "ranks every novel attack above every benign event".
        "novelAuc": roc_auc(
            novel_scores + benign_scores,
            [True] * len(novel_scores) + [False] * len(benign_scores),
        ),
        # Reference: how well it ranks attack types it *did* see.
        "historicalAuc": roc_auc(
            historical_scores + benign_scores,
            [True] * len(historical_scores) + [False] * len(benign_scores),
        ),
    }
