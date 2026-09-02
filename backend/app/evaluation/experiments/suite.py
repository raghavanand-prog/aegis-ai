"""The baseline and ablation suites.

Answering "does the hybrid architecture provide measurable value over its
components" requires the components to be measured under identical conditions:
same dataset, same split, same features, same threshold protocol. This module
builds that matrix.

What the ablation can and cannot conclude
-----------------------------------------

Removing a component and observing a metric drop shows *association* under this
dataset and this split. It does not establish that the component would help on
other telemetry, and it says nothing about interaction effects beyond the
combinations actually run. The report states the configurations evaluated and
declines to generalise past them.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from app.evaluation.datasets.base import EvaluationDataset
from app.evaluation.experiments.detectors import (
    AnomalyDetector,
    DetectorSpec,
    RiskBandHybridDetector,
    RulesDetector,
    SupervisedDetector,
    UnionHybridDetector,
)
from app.evaluation.experiments.runner import ExperimentResult, run_experiment
from app.evaluation.splits import SplitPlan
from app.ml.features.extractor import FEATURE_NAMES

#: Anomaly scores concentrate near the middle of 0..1, so the grid is dense
#: where the decision actually changes. It spans the V3 production default
#: (0.65) so the deployed setting is always a candidate.
ANOMALY_GRID: tuple[float, ...] = tuple(round(0.40 + 0.01 * step, 2) for step in range(56))

#: A probability grid can be uniform; it means the same thing everywhere.
PROBABILITY_GRID: tuple[float, ...] = tuple(round(0.05 * step, 2) for step in range(1, 20))

#: AEGISX risk bands are Low 25 / Medium 50 / High 70 / Critical 85. The grid is
#: every 5 points so the bands themselves are always candidates.
RISK_GRID: tuple[float, ...] = tuple(float(value) for value in range(5, 100, 5))


@dataclass
class SuiteResult:
    """Every experiment in one suite, plus what could not be run and why."""

    results: list[ExperimentResult]
    skipped: list[dict[str, Any]]

    def by_name(self) -> dict[str, ExperimentResult]:
        return {result.detector["name"]: result for result in self.results}

    def to_dict(self) -> dict[str, Any]:
        return {
            "experiments": [result.to_dict() for result in self.results],
            "skipped": self.skipped,
        }


def build_baseline_specs(
    *,
    anomaly_threshold: float,
    contamination: float,
    seed: int,
    registered: tuple[Any, dict[str, Any]] | None = None,
) -> list[DetectorSpec]:
    """The four baselines the research question requires, plus the deployed model."""
    rules = RulesDetector()
    fitted_anomaly = AnomalyDetector(
        feature_names=FEATURE_NAMES,
        contamination=contamination,
        random_state=seed,
        provenance="fitted",
    )

    specs: list[DetectorSpec] = [
        DetectorSpec(
            detector=rules,
            fixed_threshold=0.5,
            notes=(
                "Deterministic rules have no threshold; the 'threshold' column is a "
                "placeholder and no sweep was performed.",
            ),
        ),
        DetectorSpec(
            detector=fitted_anomaly,
            threshold_grid=ANOMALY_GRID,
            fixed_threshold=anomaly_threshold,
        ),
        DetectorSpec(
            detector=SupervisedDetector(feature_names=FEATURE_NAMES, random_state=seed),
            threshold_grid=PROBABILITY_GRID,
            fixed_threshold=0.5,
            notes=(
                "Supervised upper reference over the SAME AEGISX feature schema. It "
                "consumes training labels, which the production detectors do not, so it "
                "is not an alternative to them - it bounds what the feature schema "
                "supports.",
            ),
        ),
        DetectorSpec(
            detector=UnionHybridDetector(
                rules=RulesDetector(),
                anomaly=AnomalyDetector(
                    feature_names=FEATURE_NAMES,
                    contamination=contamination,
                    random_state=seed,
                    provenance="fitted",
                ),
            ),
            fixed_threshold=anomaly_threshold,
            notes=(
                "V3 hybrid definition: a rule fired OR the anomaly score crossed the "
                "threshold. The anomaly threshold is fixed at the production value "
                "rather than swept, because sweeping it here would optimise the hybrid "
                "against a target the components were not optimised against.",
            ),
        ),
        DetectorSpec(
            detector=RiskBandHybridDetector(
                rules=RulesDetector(),
                anomaly=AnomalyDetector(
                    feature_names=FEATURE_NAMES,
                    contamination=contamination,
                    random_state=seed,
                    provenance="fitted",
                ),
                anomaly_threshold=anomaly_threshold,
            ),
            threshold_grid=RISK_GRID,
            fixed_threshold=50.0,
            notes=(
                "AEGISX's production weighted risk scoring, thresholded on the risk "
                "score itself. This is the only configuration that measures the deployed "
                "decision path end to end.",
            ),
        ),
    ]

    if registered is not None:
        detector, info = registered
        specs.append(
            DetectorSpec(
                detector=AnomalyDetector(
                    feature_names=FEATURE_NAMES,
                    detector=detector,
                    provenance="registered",
                    model_info=info,
                    name="isolation_forest_registered",
                ),
                threshold_grid=ANOMALY_GRID,
                fixed_threshold=anomaly_threshold,
                notes=(
                    "The artifact the running system would load, digest-verified and "
                    "NOT refitted. On a corpus from a different telemetry class this is "
                    "expected to score poorly; that gap is the measurement.",
                ),
            )
        )

    return specs


def run_suite(
    *,
    dataset: EvaluationDataset,
    plan: SplitPlan,
    features: dict[str, tuple[float, ...]],
    specs: list[DetectorSpec],
    objective: str = "f1",
    seed: int = 1337,
) -> SuiteResult:
    """Run every spec, recording rather than swallowing the ones that cannot run."""
    results: list[ExperimentResult] = []
    skipped: list[dict[str, Any]] = []

    for spec in specs:
        name = getattr(spec.detector, "name", "unknown")
        try:
            results.append(
                run_experiment(
                    dataset=dataset,
                    plan=plan,
                    spec=spec,
                    features=features,
                    objective=objective,
                    seed=seed,
                )
            )
        except (ValueError, RuntimeError) as exc:
            # A detector that cannot be fitted is a reportable fact, not a
            # crash and not something to quietly drop from the comparison.
            skipped.append({"detector": name, "reason": str(exc)})

    return SuiteResult(results=results, skipped=skipped)


# ------------------------------------------------------------------ ablation


def build_ablation_specs(
    *, anomaly_threshold: float, contamination: float, seed: int
) -> list[DetectorSpec]:
    """Component-contribution matrix over the detectors this dataset supports.

    Correlation and threat intelligence are absent here on purpose: both need
    persisted events and entity history that a flow corpus does not provide.
    They are evaluated separately, on the corpus that can support them, rather
    than being included as a row of zeroes that would read like a measurement.
    """

    def anomaly() -> AnomalyDetector:
        return AnomalyDetector(
            feature_names=FEATURE_NAMES,
            contamination=contamination,
            random_state=seed,
            provenance="fitted",
        )

    return [
        DetectorSpec(
            detector=RulesDetector(),
            fixed_threshold=0.5,
            notes=("Ablation: rules only.",),
        ),
        DetectorSpec(
            detector=AnomalyDetector(
                feature_names=FEATURE_NAMES,
                contamination=contamination,
                random_state=seed,
                provenance="fitted",
                name="ablation_ml_only",
            ),
            fixed_threshold=anomaly_threshold,
            notes=(
                "Ablation: ML only, at the production threshold. Not swept, so the "
                "comparison against the hybrid is like for like.",
            ),
        ),
        DetectorSpec(
            detector=UnionHybridDetector(
                rules=RulesDetector(), anomaly=anomaly(), name="ablation_rules_plus_ml"
            ),
            fixed_threshold=anomaly_threshold,
            notes=("Ablation: rules + ML, union.",),
        ),
        DetectorSpec(
            detector=RiskBandHybridDetector(
                rules=RulesDetector(),
                anomaly=anomaly(),
                anomaly_threshold=anomaly_threshold,
                name="ablation_rules_plus_ml_risk",
            ),
            fixed_threshold=50.0,
            notes=(
                "Ablation: rules + ML combined through production risk scoring, at the "
                "Medium band. Fixed rather than swept for the same reason.",
            ),
        ),
    ]


def ablation_table(suite: SuiteResult) -> list[dict[str, Any]]:
    """Flatten an ablation suite into a comparison table."""
    rows: list[dict[str, Any]] = []
    for result in suite.results:
        matrix = result.test.confusion
        rows.append(
            {
                "configuration": result.detector["name"],
                "components": result.detector.get("kind"),
                "scoreKind": result.detector["scoreKind"],
                "threshold": result.threshold,
                "truePositives": matrix.true_positives,
                "trueNegatives": matrix.true_negatives,
                "falsePositives": matrix.false_positives,
                "falseNegatives": matrix.false_negatives,
                "precision": matrix.precision,
                "recall": matrix.recall,
                "f1": matrix.f1,
                "falsePositiveRate": matrix.false_positive_rate,
                "falseNegativeRate": matrix.false_negative_rate,
                "mcc": result.test.to_dict()["mcc"],
                "alerts": result.test.alerts,
                "alertsPerThousandEvents": result.test.to_dict()["alertVolume"][
                    "alertsPerThousandEvents"
                ],
            }
        )
    return rows
