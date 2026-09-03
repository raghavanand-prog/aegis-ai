"""CLI: V6 Track 3 hypothesis 5 - is the detector class the limit?

    python -m app.adaptation.experiments.run_detector_comparison --seeds 10

Track 3 measured that nine of thirteen withheld attack categories are
unreachable at any threshold under the production Isolation Forest. Hypothesis 5
says the detector class is what limits adaptation. The competing explanation,
hypothesis 2, says the feature space simply does not carry the information.

The experiment holds the corpus, split, seed and withheld category fixed and
varies only the detector. Separability is ROC-AUC - threshold-free, so the
``MAX_THRESHOLD_STEP`` clamp that saturated Track 3 cannot confound it, and
rank-based, so the detectors' scores never need a common scale.

The supervised entry is the decisive one and is **not a deployment candidate**.
It bounds what the feature space can support given every available label. If it
separates a category the unsupervised detectors cannot, the information is
present and the detector class is the limit. If it fails too, the features are
the limit and hypothesis 5 is wrong.

**Nothing in this experiment is deployed, proposed, or registered.**
"""

from __future__ import annotations

import argparse
import json
import platform
import statistics
import sys
from datetime import datetime, timezone
from typing import Any

from app.adaptation.experiments import candidate_detectors as detectors
from app.adaptation.experiments import seeds
from app.adaptation.experiments.run_novel_behaviour_eval import DEFAULT_CATEGORIES
from app.evaluation.reports.store import write_report
from app.evaluation.watchdog import add_argument as add_timeout_argument
from app.evaluation.watchdog import start as start_watchdog

REPORT_PREFIX = "v6-detector-comparison"
SCHEMA_VERSION = "1.0"


def _mean(values: list[float | None]) -> float | None:
    present = [value for value in values if value is not None]
    return round(statistics.fmean(present), 6) if present else None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="run_detector_comparison",
        description="V6 Track 3 hypothesis 5: detector class versus feature space.",
    )
    parser.add_argument("--seeds", type=int, default=10)
    parser.add_argument("--categories", nargs="+", default=list(DEFAULT_CATEGORIES))
    parser.add_argument("--output-dir", default=None)
    parser.add_argument("--format", choices=("text", "json"), default="text")
    add_timeout_argument(parser)
    args = parser.parse_args(argv)

    watchdog = start_watchdog(args.max_seconds, label="v6 detector comparison")
    seed_plan = seeds.build_seeds(args.seeds)
    fingerprint: str | None = None
    split_fingerprint: str | None = None

    try:
        results: list[dict[str, Any]] = []
        for category in args.categories:
            entry: dict[str, Any] = {}
            unmeasurable: str | None = None

            for name, spec in detectors.REGISTRY.items():
                runs = []
                for seed in seed_plan:
                    try:
                        runs.append(
                            detectors.measure_separability(
                                seed=seed, withheld_category=category, detector=name
                            )
                        )
                    except ValueError as error:
                        unmeasurable = str(error)
                        break
                if unmeasurable:
                    break

                fingerprint = fingerprint or runs[0]["datasetFingerprint"]
                split_fingerprint = split_fingerprint or runs[0]["splitFingerprint"]
                entry[name] = {
                    "maturity": spec.maturity,
                    "deployable": spec.deployable,
                    "requiresLabels": spec.requires_labels,
                    "novelAuc": _mean([run["novelAuc"] for run in runs]),
                    "historicalAuc": _mean([run["historicalAuc"] for run in runs]),
                    "perSeed": [
                        {
                            "seed": run["seed"],
                            "novelAuc": run["novelAuc"],
                            "historicalAuc": run["historicalAuc"],
                        }
                        for run in runs
                    ],
                    "notes": spec.notes,
                }

            if unmeasurable:
                results.append(
                    {
                        "withheldCategory": category,
                        "measurable": False,
                        "unavailableReason": unmeasurable,
                    }
                )
                print(f"  {category:<24} not measurable: {unmeasurable}", flush=True)
                continue

            results.append(
                {"withheldCategory": category, "measurable": True, "detectors": entry}
            )
            summary = "  ".join(
                f"{name.split('_')[0]}={entry[name]['novelAuc']}" for name in entry
            )
            print(f"  {category:<24} {summary}", flush=True)

        report = {
            "schemaVersion": SCHEMA_VERSION,
            "generatedAt": datetime.now(timezone.utc).isoformat(),
            "command": " ".join(sys.argv),
            "question": (
                "Is the detector class the limit on novel-behaviour detection, "
                "or is it the feature space?"
            ),
            "metric": (
                "ROC-AUC of the withheld category against benign held-out "
                "traffic. Threshold-free, so the MAX_THRESHOLD_STEP clamp cannot "
                "confound it. 0.5 is indistinguishable from benign."
            ),
            "dataset": {
                "name": "aegisx-detection-eval",
                "fingerprint": fingerprint,
                "splitFingerprint": split_fingerprint,
                "samplesPerClass": detectors.SAMPLES_PER_CLASS,
                "note": (
                    "Enlarged from the Track 1 corpus so every category clears "
                    "V4's MIN_PER_CLASS = 20 guard for ROC-AUC. A different "
                    "fingerprint from section 1; not comparable row-for-row."
                ),
            },
            "protocol": {"seeds": seed_plan},
            "environment": {
                "python": platform.python_version(),
                "platform": platform.platform(),
            },
            "results": results,
            "caveats": [
                "These detectors are not deployed, not proposed and not "
                "registered. They are experimental comparisons only, and the "
                "production detector is unchanged.",
                "supervised_ceiling is a DIAGNOSTIC, not a deployment candidate. "
                "It consumes labels the production pipeline does not have, and "
                "V5's refusal to substitute a supervised detector still stands.",
                "The corpus is synthetic. Nothing here is evidence about real "
                "attack traffic.",
                "Results are per category and are not averaged across "
                "categories, which differ in whether any detector separates them.",
            ],
        }

        path, _ = write_report(report, args.output_dir, prefix=REPORT_PREFIX)
    finally:
        if watchdog is not None:
            watchdog.cancel()

    if args.format == "json":
        print(json.dumps(report, indent=2))
    else:
        print(f"\n  Report written to {path}")
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
