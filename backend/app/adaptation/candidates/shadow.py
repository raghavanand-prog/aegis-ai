"""Shadow evaluation: what would the candidate have done?

Both models score the same events. Only the production model's verdict is real;
the candidate's is recorded for comparison and reaches nothing - not the event,
not the risk score, not the analyst's queue, not ``ml_inferences``.

That last one matters more than it looks. An ``MLInference`` row is what an
analyst reads when they ask why an event was flagged. Writing a candidate's
opinion there would put an unapproved model's judgement into the record of what
the platform concluded, which is the same failure as deploying it - just harder
to notice.

Shadow mode answers "how often would this have disagreed, and in which
direction", which is the question that decides whether a candidate is worth
proposing at all.
"""

from __future__ import annotations

from typing import Any

from sqlalchemy.orm import Session

from app.adaptation.candidates.evaluation import _load
from app.core.config import settings
from app.evaluation.datasets.adapters import synthetic_dataset
from app.ml.features.extractor import FeatureExtractor
from app.models.ml import MLModel


def compare(
    db: Session,
    *,
    candidate: MLModel,
    baseline: MLModel,
    seed: int = 1337,
    samples_per_class: int | None = None,
    threshold: float | None = None,
) -> dict[str, Any]:
    """Score both models over one corpus and report where they diverge.

    Writes nothing. ``db`` is taken for symmetry with the rest of the package
    and to make the absence of any write obvious at the call site.
    """
    threshold = threshold if threshold is not None else settings.ml_anomaly_threshold

    dataset = synthetic_dataset(seed=seed, samples_per_class=samples_per_class)
    ordered = sorted(dataset.samples, key=lambda sample: sample.timestamp)

    # One extractor, one chronological pass - the behavioural features are
    # stateful, so scoring each model over its own pass would give them
    # different views of history and make the disagreement uninterpretable.
    extractor = FeatureExtractor()
    vectors = [extractor.extract(sample.candidate, observe=True).values for sample in ordered]
    labels = [bool(sample.is_malicious) for sample in ordered]

    candidate_detector = _load(candidate)
    baseline_detector = _load(baseline)

    agreements = 0
    disagreements = 0
    candidate_only = 0
    baseline_only = 0
    candidate_only_correct = 0
    baseline_only_correct = 0

    for vector, is_malicious in zip(vectors, labels, strict=True):
        candidate_flag = candidate_detector.anomaly_score(vector) >= threshold
        baseline_flag = baseline_detector.anomaly_score(vector) >= threshold

        if candidate_flag == baseline_flag:
            agreements += 1
            continue

        disagreements += 1
        if candidate_flag:
            candidate_only += 1
            candidate_only_correct += int(is_malicious)
        else:
            baseline_only += 1
            baseline_only_correct += int(is_malicious)

    return {
        "candidate": candidate.identity,
        "baseline": baseline.identity,
        "dataset": {
            "name": dataset.name,
            "version": dataset.version,
            "fingerprint": dataset.fingerprint(),
        },
        "threshold": threshold,
        "samples": len(ordered),
        "agreements": agreements,
        "disagreements": disagreements,
        #: Events the candidate would flag and the incumbent would not, with how
        #: many of those were genuinely malicious. The split is the point: extra
        #: flags that are correct are a gain, extra flags that are wrong are the
        #: analyst's afternoon.
        "candidateOnlyFlags": candidate_only,
        "candidateOnlyCorrect": candidate_only_correct,
        #: Events the incumbent flags that the candidate would miss. Every
        #: correct one here is an attack the change would have lost.
        "baselineOnlyFlags": baseline_only,
        "baselineOnlyCorrect": baseline_only_correct,
        "interpretation": (
            "The candidate's verdicts were recorded for comparison only. No "
            "production decision, event, risk score or inference record was "
            "affected, and the candidate remains unable to serve."
        ),
    }
