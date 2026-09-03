"""CLI: the detection baseline in the configuration production uses.

    python -m app.adaptation.experiments.run_production_baseline_eval --seeds 10

Fits the runtime telemetry corpus as ``train_anomaly_model`` does, scores the
same labelled test split and frozen threshold Track 1 used, and reports the
result beside the static baseline it replaces.
"""

from __future__ import annotations

import argparse
import json
import platform
import statistics
import sys
from datetime import datetime, timezone
from typing import Any

from app.adaptation.experiments import production_baseline, scenarios, seeds
from app.evaluation.reports.store import write_report
from app.evaluation.watchdog import add_argument as add_timeout_argument
from app.evaluation.watchdog import start as start_watchdog

REPORT_PREFIX = "v6-production-baseline"
SCHEMA_VERSION = "1.0"


def _agg(values: list[float | None]) -> dict[str, Any]:
    present = [value for value in values if value is not None]
    if not present:
        return {"mean": None, "stdev": None, "runs": 0}
    return {
        "mean": round(statistics.fmean(present), 6),
        "stdev": round(statistics.pstdev(present), 6),
        "min": round(min(present), 6),
        "max": round(max(present), 6),
        "runs": len(present),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="run_production_baseline_eval")
    parser.add_argument("--seeds", type=int, default=10)
    parser.add_argument("--noise", type=float, default=0.05)
    parser.add_argument("--coverage", type=float, default=0.5)
    parser.add_argument("--output-dir", default=None)
    parser.add_argument("--format", choices=("text", "json"), default="text")
    add_timeout_argument(parser)
    args = parser.parse_args(argv)

    watchdog = start_watchdog(args.max_seconds, label="v6 production baseline")
    seed_plan = seeds.build_seeds(args.seeds)

    try:
        runs = [
            production_baseline.measure(
                seed=seed, noise_rate=args.noise, coverage=args.coverage
            )
            for seed in seed_plan
        ]
        first = runs[0]

        def metric(block: str, key: str) -> dict[str, Any]:
            return _agg([run[block][key] for run in runs])

        report = {
            "schemaVersion": SCHEMA_VERSION,
            "generatedAt": datetime.now(timezone.utc).isoformat(),
            "command": " ".join(sys.argv),
            "question": (
                "What is the detection baseline when the detector is fitted the "
                "way production fits it, rather than re-fitted on the 40%-"
                "malicious labelled corpus?"
            ),
            "fit": {
                "corpus": first["fitCorpus"],
                "samples": first["fitSamples"],
                "note": (
                    "The corpus train_anomaly_model actually fits: unlabelled "
                    "runtime telemetry, roughly 12% suspicious scenarios."
                ),
            },
            "scoring": {
                "corpus": first["scoredOn"],
                "datasetFingerprint": first["datasetFingerprint"],
                "splitFingerprint": first["splitFingerprint"],
                "threshold": scenarios.DEFAULT_THRESHOLD,
                "fitScoringOverlap": first["fitScoringOverlap"],
                "note": (
                    "Same corpus, split and frozen threshold as Track 1, so the "
                    "number is directly comparable to the static baseline it "
                    "replaces. Only the fitting data differs."
                ),
            },
            "protocol": {"seeds": seed_plan},
            "environment": {
                "python": platform.python_version(),
                "platform": platform.platform(),
            },
            "rocAuc": _agg([run["rocAuc"] for run in runs]),
            "frozenThreshold": {
                key: metric("frozenThreshold", key)
                for key in ("precision", "recall", "f1", "falsePositiveRate", "alertVolume")
            },
            "adaptedThreshold": {
                key: metric("adaptedThreshold", key)
                for key in (
                    "precision",
                    "recall",
                    "f1",
                    "falsePositiveRate",
                    "alertVolume",
                    "threshold",
                )
            },
            "arms": first["arms"],
            "perSeed": [
                {
                    "seed": run["seed"],
                    "rocAuc": run["rocAuc"],
                    "frozenF1": run["frozenThreshold"]["f1"],
                    "adaptedF1": run["adaptedThreshold"]["f1"],
                }
                for run in runs
            ],
            "caveats": [
                "Both corpora are synthetic. This re-establishes an experimental "
                "baseline; it is not evidence about real traffic.",
                "The production configuration operates at a very different point "
                "- high recall, ~34% false-positive rate - from V5's adapted "
                "model, which was high-precision and low-recall. F1 favours the "
                "former; an operator might not.",
                "Arm 2 (curation) is not applicable in this configuration: "
                "production's fit set is unlabelled telemetry, not observed "
                "events, so analyst labels have nothing there to purify.",
                "Nothing here is deployed or registered.",
            ],
        }
        path, _ = write_report(report, args.output_dir, prefix=REPORT_PREFIX)
    finally:
        if watchdog is not None:
            watchdog.cancel()

    if args.format == "json":
        print(json.dumps(report, indent=2))
    else:
        print(
            f"  ROC-AUC {report['rocAuc']['mean']}  "
            f"F1@0.65 {report['frozenThreshold']['f1']['mean']}  "
            f"FPR {report['frozenThreshold']['falsePositiveRate']['mean']}\n"
            f"\n  Report written to {path}"
        )
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
