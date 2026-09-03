"""Assessing drift, and keeping the three kinds of it apart.

The distinction this module exists to protect:

**Data drift** — the input distribution moved. Measurable without labels.
**Prediction drift** — the model's output distribution moved. Also label-free.
**Concept drift** — the relationship between features and truth changed.
    **Not measurable without labels.** Inputs alone cannot establish it.

Conflating the first with the third is the most common mistake in adaptive ML
monitoring, and it is expensive here: "data drift detected" would become
"the model is wrong", which would become a retrain, on evidence that never
supported the conclusion. So concept drift has its own entry point and that
entry point refuses to run without ground truth.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

import numpy as np

from app.adaptation.drift import metrics
from app.adaptation.drift.metrics import DriftStatus


class DriftKind(str, Enum):
    DATA = "data"
    PREDICTION = "prediction"
    CONCEPT = "concept"


@dataclass(frozen=True)
class FeatureDriftResult:
    """Drift for one feature, with everything needed to argue with it."""

    feature: str
    kind: DriftKind
    psi: float
    wasserstein_distance: float
    status: DriftStatus
    reference_samples: int
    current_samples: int
    reference_mean: float
    current_mean: float

    def as_dict(self) -> dict:
        return {
            "feature": self.feature,
            "kind": self.kind.value,
            "psi": self.psi,
            "wasserstein": self.wasserstein_distance,
            "status": self.status.value,
            "referenceSamples": self.reference_samples,
            "currentSamples": self.current_samples,
            "referenceMean": self.reference_mean,
            "currentMean": self.current_mean,
            # Said on every result, because a dashboard that omits it invites
            # exactly the inference this module exists to prevent.
            "interpretation": (
                "The distribution of this input changed. That is not evidence "
                "that the model became wrong."
            ),
        }


def assess_feature_drift(
    *,
    feature: str,
    reference,
    current,
    kind: DriftKind = DriftKind.DATA,
    bins: int = 10,
    min_samples: int = metrics.DEFAULT_MIN_SAMPLES,
    moderate: float = metrics.DEFAULT_MODERATE_THRESHOLD,
    significant: float = metrics.DEFAULT_SIGNIFICANT_THRESHOLD,
) -> FeatureDriftResult:
    """Compare one numeric feature between a baseline and a current window."""
    if kind is DriftKind.CONCEPT:
        raise ValueError(
            "Concept drift cannot be assessed from a feature distribution. "
            "Use assess_concept_drift, which requires labels."
        )

    psi = metrics.population_stability_index(
        reference, current, bins=bins, min_samples=min_samples
    )
    distance = metrics.wasserstein(reference, current)
    reference_array = np.asarray(list(reference), dtype=float)
    current_array = np.asarray(list(current), dtype=float)

    return FeatureDriftResult(
        feature=feature,
        kind=kind,
        psi=psi,
        wasserstein_distance=distance,
        status=metrics.classify(psi, moderate=moderate, significant=significant),
        reference_samples=int(len(reference_array)),
        current_samples=int(len(current_array)),
        reference_mean=float(np.mean(reference_array)) if len(reference_array) else 0.0,
        current_mean=float(np.mean(current_array)) if len(current_array) else 0.0,
    )


@dataclass(frozen=True)
class ConceptDriftResult:
    """Whether the feature-to-truth relationship appears to have changed."""

    reference_positive_rate: float
    current_positive_rate: float
    positive_rate_change: float
    reference_score_auc: float | None
    current_score_auc: float | None
    auc_change: float | None
    status: DriftStatus
    caveat: str


def assess_concept_drift(
    *,
    reference_labels,
    current_labels,
    reference_scores,
    current_scores,
    moderate: float = 0.05,
    significant: float = 0.15,
) -> ConceptDriftResult:
    """Compare detector separability between two labelled windows.

    Concept drift is claimed only from labelled data, and even then carefully:
    a fall in AUC between two windows is consistent with concept drift, with a
    harder sample of traffic, and with label noise. The result carries that
    caveat rather than resolving it.
    """
    reference_labels = list(reference_labels)
    current_labels = list(current_labels)
    if not reference_labels or not current_labels:
        raise ValueError(
            "Concept drift requires labels in both windows. Without ground truth "
            "there is nothing to say about the relationship between features and "
            "truth - measure data or prediction drift instead."
        )

    reference_rate = float(np.mean(reference_labels))
    current_rate = float(np.mean(current_labels))

    reference_auc = _safe_auc(reference_labels, reference_scores)
    current_auc = _safe_auc(current_labels, current_scores)
    auc_change = (
        None if reference_auc is None or current_auc is None else reference_auc - current_auc
    )

    # Status follows the drop in separability where one is measurable, and the
    # change in base rate otherwise. A base-rate change alone is weak evidence:
    # it says the traffic mix moved, not that the boundary did.
    driver = abs(auc_change) if auc_change is not None else abs(current_rate - reference_rate)
    return ConceptDriftResult(
        reference_positive_rate=reference_rate,
        current_positive_rate=current_rate,
        positive_rate_change=current_rate - reference_rate,
        reference_score_auc=reference_auc,
        current_score_auc=current_auc,
        auc_change=auc_change,
        status=metrics.classify(driver, moderate=moderate, significant=significant),
        caveat=(
            "A fall in separability between two windows is consistent with "
            "concept drift, with a harder sample of traffic, and with label "
            "noise. This result does not distinguish between them."
        ),
    )


def _safe_auc(labels, scores) -> float | None:
    """ROC-AUC, or None where it is undefined (one class present)."""
    labels = list(labels)
    scores = list(scores)
    if not scores or len(labels) != len(scores) or len(set(labels)) < 2:
        return None
    from sklearn.metrics import roc_auc_score

    return float(roc_auc_score(labels, scores))
