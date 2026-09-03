"""The V5 adaptation scenarios.

Every configuration is measured against the same static V4 baseline: the
deployed Isolation Forest at its frozen threshold, over the same corpus, scored
in the same chronological order by the production feature extractor.

The controls matter more than the treatments. ``random_feedback`` runs the whole
loop on shuffled labels; if adaptation improves under it, the improvement did
not come from feedback and RQ1 is answered "no". ``no_feedback_retrain`` and
``threshold_only`` separate "adaptation helped" from "any new model helps" and
"any operating point change helps".
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any

from app.adaptation.experiments import simulation
from app.evaluation.datasets.adapters import synthetic_dataset
from app.evaluation.metrics.classification import ConfusionMatrix
from app.evaluation.splits import STRATIFIED_GROUP, build_split
from app.ml.features.extractor import FEATURE_NAMES, FeatureExtractor
from app.ml.models.isolation_forest import IsolationForestDetector

#: Matches the deployed configuration measured in Phase A.
DEFAULT_THRESHOLD = 0.65
MAX_THRESHOLD_STEP = 0.05
CONTAMINATION = 0.08
N_ESTIMATORS = 200


@dataclass
class Corpus:
    """A prepared corpus, split by the V4 splitter.

    The split is **stratified and group-aware**, not a chronological cut. A
    naive time cut on this corpus puts zero malicious samples in the held-out
    portion, which makes recall undefined and every comparison meaningless -
    measured while building this harness. V4 solved that problem already, so
    this reuses its splitter rather than inventing a second one.
    """

    fit_vectors: list[tuple[float, ...]]
    fit_labels: list[bool]
    test_vectors: list[tuple[float, ...]]
    test_labels: list[bool]
    feature_names: tuple[str, ...]
    fingerprint: str
    split_fingerprint: str
    name: str
    version: str

    @property
    def size(self) -> int:
        return len(self.fit_vectors) + len(self.test_vectors)


def prepare_corpus(*, seed: int = 1337, samples_per_class: int | None = None) -> Corpus:
    """Extract features once chronologically, then split with the V4 splitter.

    Features are extracted over the whole corpus in time order before splitting,
    because the behavioural features are stateful: extracting per split would
    give each split a different view of history than production has.
    """
    dataset = synthetic_dataset(seed=seed, samples_per_class=samples_per_class)
    ordered = sorted(dataset.samples, key=lambda sample: sample.timestamp)

    extractor = FeatureExtractor()
    features = {
        sample.id: extractor.extract(sample.candidate, observe=True).values
        for sample in ordered
    }

    plan = build_split(dataset, strategy=STRATIFIED_GROUP, seed=seed)
    # Train and validation both inform adaptation; test is read once, after.
    fit_samples = list(plan.train.samples) + list(plan.validation.samples)
    fit_samples.sort(key=lambda sample: sample.timestamp)
    test_samples = sorted(plan.test.samples, key=lambda sample: sample.timestamp)

    return Corpus(
        fit_vectors=[features[sample.id] for sample in fit_samples],
        fit_labels=[bool(sample.is_malicious) for sample in fit_samples],
        test_vectors=[features[sample.id] for sample in test_samples],
        test_labels=[bool(sample.is_malicious) for sample in test_samples],
        feature_names=tuple(FEATURE_NAMES),
        fingerprint=dataset.fingerprint(),
        split_fingerprint=plan.fingerprint(),
        name=dataset.name,
        version=dataset.version,
    )


def _matrix(scores: list[float], labels: list[bool], threshold: float) -> ConfusionMatrix:
    matrix = ConfusionMatrix()
    for score, is_malicious in zip(scores, labels, strict=True):
        flagged = score >= threshold
        if flagged and is_malicious:
            matrix.true_positives += 1
        elif flagged and not is_malicious:
            matrix.false_positives += 1
        elif not flagged and is_malicious:
            matrix.false_negatives += 1
        else:
            matrix.true_negatives += 1
    return matrix


def _metrics(matrix: ConfusionMatrix, threshold: float) -> dict[str, Any]:
    return {
        "threshold": threshold,
        "truePositives": matrix.true_positives,
        "falsePositives": matrix.false_positives,
        "trueNegatives": matrix.true_negatives,
        "falseNegatives": matrix.false_negatives,
        # Nullable throughout. An undefined metric is null, never zero.
        "precision": matrix.precision,
        "recall": matrix.recall,
        "f1": matrix.f1,
        "falsePositiveRate": matrix.false_positive_rate,
        "falseNegativeRate": (
            None
            if matrix.actual_positives == 0
            else matrix.false_negatives / matrix.actual_positives
        ),
        "alertVolume": matrix.predicted_positives,
    }


def _fit(vectors: list[tuple[float, ...]], names: tuple[str, ...], seed: int):
    detector = IsolationForestDetector(
        feature_names=names,
        contamination=CONTAMINATION,
        random_state=seed,
        n_estimators=N_ESTIMATORS,
    )
    detector.fit(vectors)
    return detector


@dataclass
class ScenarioResult:
    name: str
    condition: str
    seed: int
    metrics: dict[str, Any]
    timings: dict[str, float] = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)


def run_condition(
    corpus: Corpus,
    *,
    condition: str,
    seed: int,
    noise_rate: float = 0.05,
    coverage: float = 0.5,
    abstention_rate: float = 0.10,
    false_positive_bias: float = 0.2,
) -> ScenarioResult:
    """Run one condition end to end and measure it.

    The split is chronological: the model is fitted and adapted on the earlier
    portion and measured on the later one, so no condition is scored on data it
    was tuned against.
    """
    fit_vectors = corpus.fit_vectors
    fit_labels = corpus.fit_labels
    test_vectors = corpus.test_vectors
    test_labels = corpus.test_labels

    timings: dict[str, float] = {}
    notes: list[str] = []

    # --- Static baseline: the deployed configuration, untouched ------------
    started = time.perf_counter()
    baseline_detector = _fit(fit_vectors, corpus.feature_names, seed)
    timings["baselineTrainingSeconds"] = round(time.perf_counter() - started, 4)

    if condition == "static_v4":
        started = time.perf_counter()
        scores = [baseline_detector.anomaly_score(v) for v in test_vectors]
        timings["evaluationSeconds"] = round(time.perf_counter() - started, 4)
        timings["latencyMsPerEvent"] = round(
            timings["evaluationSeconds"] * 1000 / max(len(test_vectors), 1), 4
        )
        return ScenarioResult(
            name="baseline",
            condition=condition,
            seed=seed,
            metrics=_metrics(_matrix(scores, test_labels, DEFAULT_THRESHOLD), DEFAULT_THRESHOLD),
            timings=timings,
            notes=["Deployed model at the frozen threshold. No adaptation."],
        )

    # --- Feedback ----------------------------------------------------------
    started = time.perf_counter()
    shuffle = condition == "random_feedback"
    verdicts = simulation.simulate_feedback(
        fit_labels,
        seed=seed,
        noise_rate=0.0 if shuffle else noise_rate,
        coverage=coverage,
        abstention_rate=abstention_rate,
        false_positive_bias=0.0 if shuffle else false_positive_bias,
        shuffle_labels=shuffle,
    )
    timings["feedbackSeconds"] = round(time.perf_counter() - started, 4)

    # Only training-eligible verdicts count. `uncertain` is recorded and
    # ignored, exactly as the production vocabulary requires.
    believed = {
        verdict.index: verdict.label.binary_label
        for verdict in verdicts
        if verdict.label.is_training_eligible and verdict.label.binary_label is not None
    }
    erroneous = sum(1 for verdict in verdicts if verdict.is_erroneous)
    notes.append(
        f"{len(verdicts)} verdicts, {len(believed)} training-eligible, "
        f"{erroneous} actually wrong "
        f"({erroneous / len(verdicts):.1%} realised noise)" if verdicts else "no verdicts"
    )

    # --- Arm 2: curate the fit set ----------------------------------------
    detector = baseline_detector
    if condition in {"curation_only", "both_arms", "random_feedback", "no_feedback_retrain"}:
        started = time.perf_counter()
        if condition == "no_feedback_retrain":
            # Control: a new model, same data, different seed. Isolates "any
            # new model helps" from "adaptation helps".
            curated = fit_vectors
        else:
            curated = simulation.curate_fit_set(fit_vectors, believed)
        detector = _fit(curated, corpus.feature_names, seed + 1)
        timings["candidateTrainingSeconds"] = round(time.perf_counter() - started, 4)
        notes.append(f"fit set {len(fit_vectors)} -> {len(curated)} after curation")

    # --- Arm 1: move the operating point ----------------------------------
    threshold = DEFAULT_THRESHOLD
    if condition in {"threshold_only", "both_arms", "random_feedback"}:
        started = time.perf_counter()
        labelled_indices = sorted(believed)
        if labelled_indices:
            labelled_scores = [detector.anomaly_score(fit_vectors[i]) for i in labelled_indices]
            labelled_truth = [believed[i] for i in labelled_indices]
            threshold = simulation.choose_threshold(
                labelled_scores,
                labelled_truth,
                current=DEFAULT_THRESHOLD,
                max_step=MAX_THRESHOLD_STEP,
            )
        else:
            notes.append("no training-eligible feedback; threshold left unchanged")
        timings["thresholdSelectionSeconds"] = round(time.perf_counter() - started, 4)

    started = time.perf_counter()
    scores = [detector.anomaly_score(v) for v in test_vectors]
    timings["evaluationSeconds"] = round(time.perf_counter() - started, 4)
    timings["latencyMsPerEvent"] = round(
        timings["evaluationSeconds"] * 1000 / max(len(test_vectors), 1), 4
    )

    return ScenarioResult(
        name="adaptive",
        condition=condition,
        seed=seed,
        metrics=_metrics(_matrix(scores, test_labels, threshold), threshold),
        timings=timings,
        notes=notes,
    )


def run_new_behaviour(
    *,
    seed: int,
    withheld_category: str,
    noise_rate: float = 0.05,
    coverage: float = 0.5,
    samples_per_class: int | None = None,
) -> dict[str, Any]:
    """Scenario 4 + §33: does adapting to new behaviour cost old behaviour?

    One attack category is withheld from the fit set entirely, so the model has
    never seen it. Adaptation then happens on feedback that includes it. The
    result is scored **twice**: on the new category, and on the historical
    categories the model already handled.

    Reporting only the first number is the error §33 exists to prevent - a model
    that learns the new thing while quietly losing the old one looks like
    progress right up until an old attack walks through.
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

    # The model never sees the withheld category during fitting.
    seen = [s for s in fit_samples if s.category != withheld_category]
    if not seen:
        raise ValueError(f"withholding {withheld_category!r} emptied the fit set")

    fit_vectors = [features[s.id] for s in seen]
    fit_labels = [bool(s.is_malicious) for s in seen]

    new_test = [s for s in test_samples if s.category == withheld_category]
    historical_test = [
        s for s in test_samples if s.category != withheld_category
    ]
    if not new_test:
        raise ValueError(
            f"no held-out samples of {withheld_category!r}; the scenario cannot "
            "measure performance on unseen behaviour"
        )

    def measure(detector, samples, threshold):
        vectors = [features[s.id] for s in samples]
        labels = [bool(s.is_malicious) for s in samples]
        scores = [detector.anomaly_score(v) for v in vectors]
        return _metrics(_matrix(scores, labels, threshold), threshold)

    static = _fit(fit_vectors, tuple(FEATURE_NAMES), seed)

    verdicts = simulation.simulate_feedback(
        fit_labels, seed=seed, noise_rate=noise_rate, coverage=coverage
    )
    believed = {
        v.index: v.label.binary_label
        for v in verdicts
        if v.label.is_training_eligible and v.label.binary_label is not None
    }
    curated = simulation.curate_fit_set(fit_vectors, believed)
    adapted = _fit(curated, tuple(FEATURE_NAMES), seed + 1)

    labelled = sorted(believed)
    threshold = DEFAULT_THRESHOLD
    if labelled:
        threshold = simulation.choose_threshold(
            [adapted.anomaly_score(fit_vectors[i]) for i in labelled],
            [believed[i] for i in labelled],
            current=DEFAULT_THRESHOLD,
            max_step=MAX_THRESHOLD_STEP,
        )

    return {
        "withheldCategory": withheld_category,
        "seed": seed,
        "fitSamples": len(fit_vectors),
        "newBehaviourSamples": len(new_test),
        "historicalSamples": len(historical_test),
        "static": {
            "newBehaviour": measure(static, new_test, DEFAULT_THRESHOLD),
            "historical": measure(static, historical_test, DEFAULT_THRESHOLD),
        },
        "adapted": {
            "newBehaviour": measure(adapted, new_test, threshold),
            "historical": measure(adapted, historical_test, threshold),
        },
        "interpretation": (
            "A gain on the withheld category paid for by a loss on the "
            "historical categories is catastrophic forgetting, not adaptation."
        ),
    }
