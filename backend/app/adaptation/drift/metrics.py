"""Distribution distance measures, and what counts as drift.

Three measures, chosen for the data types AEGISX actually has rather than for
completeness:

``population_stability_index``
    The SOC-conventional measure for a continuous feature. Bounded bins, cheap,
    and its thresholds are widely understood. Used as the primary status driver.

``wasserstein``
    Reported alongside PSI because it is in the units of the feature. "The
    distribution moved by 4.2 connections" is actionable in a way that "PSI 0.31"
    is not, and the two disagree in informative ways when a distribution changes
    shape without moving.

``categorical_drift``
    Chi-square for categorical features, reporting **Cramér's V alongside the
    p-value**. This matters: over a window of half a million events any
    difference is statistically significant, so a p-value alone would report
    drift permanently on a busy sensor. Status follows effect size.

None of these establishes that a model has become wrong. They establish that the
input distribution changed, which is a different claim - see ``detector``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

import numpy as np
from scipy import stats

#: Conventional PSI bands. These are an industry convention, not a measured
#: property of AEGISX telemetry, and every entry point takes them as arguments
#: so a deployment can tighten them against its own observed variance.
DEFAULT_MODERATE_THRESHOLD = 0.10
DEFAULT_SIGNIFICANT_THRESHOLD = 0.25

#: Below this many samples a distance is noise. Reporting one would generate
#: false alarms on quiet sensors, which is how drift monitoring gets ignored.
DEFAULT_MIN_SAMPLES = 100

#: Guards log(0) where a bin is populated in one window and empty in the other.
#: Small enough not to move a real result, large enough to keep PSI finite.
_EPSILON = 1e-6


class DriftStatus(str, Enum):
    STABLE = "stable"
    MODERATE = "moderate"
    SIGNIFICANT = "significant"


def classify(
    value: float,
    *,
    moderate: float = DEFAULT_MODERATE_THRESHOLD,
    significant: float = DEFAULT_SIGNIFICANT_THRESHOLD,
) -> DriftStatus:
    """Map an effect size onto a status band."""
    if value >= significant:
        return DriftStatus.SIGNIFICANT
    if value >= moderate:
        return DriftStatus.MODERATE
    return DriftStatus.STABLE


def _as_array(values) -> np.ndarray:
    array = np.asarray(list(values), dtype=float)
    return array[np.isfinite(array)]


def population_stability_index(
    reference,
    current,
    *,
    bins: int = 10,
    min_samples: int = 0,
) -> float:
    """PSI between two samples of one continuous feature.

    Bin edges come from the **reference** window's quantiles, because the
    reference is the distribution the model was fitted on. Re-binning on the
    current window would move the yardstick with the thing being measured.
    """
    reference_array = _as_array(reference)
    current_array = _as_array(current)

    if len(reference_array) < min_samples or len(current_array) < min_samples:
        raise ValueError(
            f"Refusing to report drift on fewer than {min_samples} samples "
            f"(reference={len(reference_array)}, current={len(current_array)}). "
            "A distance over a handful of points is noise, and a monitor that "
            "cries wolf on quiet sensors stops being read."
        )
    if len(reference_array) == 0 or len(current_array) == 0:
        raise ValueError("Cannot compute PSI over an empty sample")

    quantiles = np.linspace(0, 100, bins + 1)
    edges = np.unique(np.percentile(reference_array, quantiles))
    if len(edges) < 2:
        # A constant reference feature. Any spread in the current window is
        # drift, but PSI over one bin is undefined, so fall back to a two-bin
        # split around the constant.
        constant = float(reference_array[0])
        edges = np.array([constant - _EPSILON, constant + _EPSILON])

    # Keep the interior edges. Where the reference is constant there are only
    # two edges and ``edges[1:-1]`` would be empty, collapsing everything into a
    # single bin - which reports PSI 0 for two distributions that share no
    # values at all. Drift is least visible exactly where it is most obvious.
    interior = edges[1:-1] if len(edges) > 2 else edges
    edges = np.concatenate(([-np.inf], interior, [np.inf]))

    reference_counts, _ = np.histogram(reference_array, bins=edges)
    current_counts, _ = np.histogram(current_array, bins=edges)

    reference_share = reference_counts / max(reference_counts.sum(), 1)
    current_share = current_counts / max(current_counts.sum(), 1)

    reference_share = np.clip(reference_share, _EPSILON, None)
    current_share = np.clip(current_share, _EPSILON, None)

    return float(np.sum((current_share - reference_share) * np.log(current_share / reference_share)))


def wasserstein(reference, current) -> float:
    """Earth-mover distance, in the units of the feature."""
    reference_array = _as_array(reference)
    current_array = _as_array(current)
    if len(reference_array) == 0 or len(current_array) == 0:
        raise ValueError("Cannot compute a distance over an empty sample")
    return float(stats.wasserstein_distance(reference_array, current_array))


@dataclass(frozen=True)
class CategoricalDriftResult:
    """Chi-square with an effect size, and the categories that explain it."""

    statistic: float
    p_value: float
    #: Cramér's V. Bounded [0, 1] and independent of sample size, which is what
    #: makes it usable as a status driver where the p-value is not.
    effect_size: float
    status: DriftStatus
    new_categories: tuple[str, ...] = field(default_factory=tuple)
    missing_categories: tuple[str, ...] = field(default_factory=tuple)


def categorical_drift(
    reference_counts: dict[str, int],
    current_counts: dict[str, int],
    *,
    moderate: float = DEFAULT_MODERATE_THRESHOLD,
    significant: float = DEFAULT_SIGNIFICANT_THRESHOLD,
) -> CategoricalDriftResult:
    """Compare two categorical distributions.

    Returns the chi-square statistic and its p-value *and* Cramér's V, and
    drives status from V. A p-value answers "could this difference be chance",
    which over a large window is always no; an analyst needs "is this difference
    big", which is what the effect size answers.
    """
    categories = sorted(set(reference_counts) | set(current_counts))
    if not categories:
        raise ValueError("Cannot compare two empty categorical distributions")

    reference_row = np.array([reference_counts.get(name, 0) for name in categories], dtype=float)
    current_row = np.array([current_counts.get(name, 0) for name in categories], dtype=float)

    new_categories = tuple(
        name for name in categories if reference_counts.get(name, 0) == 0 and current_counts.get(name, 0) > 0
    )
    missing_categories = tuple(
        name for name in categories if reference_counts.get(name, 0) > 0 and current_counts.get(name, 0) == 0
    )

    table = np.vstack([reference_row, current_row])
    # Drop all-zero columns: they carry no information and make chi2 undefined.
    table = table[:, table.sum(axis=0) > 0]

    total = table.sum()
    if table.shape[1] < 2 or total == 0:
        # One category everywhere: identical by construction.
        return CategoricalDriftResult(
            statistic=0.0,
            p_value=1.0,
            effect_size=0.0,
            status=DriftStatus.STABLE,
            new_categories=new_categories,
            missing_categories=missing_categories,
        )

    statistic, p_value, _, _ = stats.chi2_contingency(table, correction=False)
    # Cramér's V for a 2 x k table: sqrt(chi2 / n), since min(rows, cols) - 1 = 1.
    effect_size = float(np.sqrt(statistic / total))

    return CategoricalDriftResult(
        statistic=float(statistic),
        p_value=float(p_value),
        effect_size=effect_size,
        status=classify(effect_size, moderate=moderate, significant=significant),
        new_categories=new_categories,
        missing_categories=missing_categories,
    )
