"""CLI: the redesigned Arm 2, measured against the production baseline.

    python -m app.adaptation.experiments.run_arm2_eval --seeds 10

Reports the safety bounds alongside the metrics, because an arm that adds
analyst-supplied rows to training data is only as good as what it refuses.
"""

from __future__ import annotations

import argparse
import json
import platform
import sys
from datetime import datetime, timezone
from typing import Any

from app.adaptation.experiments import arm2, scenarios, seeds
from app.evaluation.metrics.ranking import bootstrap_interval, cohens_d
from app.evaluation.reports.store import write_report
from app.evaluation.watchdog import add_argument as add_timeout_argument
from app.evaluation.watchdog import start as start_watchdog

REPORT_PREFIX = "v6-arm2"
SCHEMA_VERSION = "1.0"
METRICS = ("precision", "recall", "f1", "falsePositiveRate", "alertVolume", "rocAuc")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="run_arm2_eval")
    parser.add_argument("--seeds", type=int, default=10)
    parser.add_argument("--noise", type=float, default=0.05)
    parser.add_argument("--coverage", type=float, default=0.5)
    parser.add_argument(
        "--max-feedback-fraction",
        type=float,
        default=arm2.DEFAULT_MAX_FEEDBACK_FRACTION,
    )
    parser.add_argument("--output-dir", default=None)
    parser.add_argument("--format", choices=("text", "json"), default="text")
    add_timeout_argument(parser)
    args = parser.parse_args(argv)

    watchdog = start_watchdog(args.max_seconds, label="v6 arm 2")
    seed_plan = seeds.build_seeds(args.seeds)

    try:
        runs = [
            arm2.measure(
                seed=seed,
                noise_rate=args.noise,
                coverage=args.coverage,
                max_feedback_fraction=args.max_feedback_fraction,
            )
            for seed in seed_plan
        ]
        first = runs[0]

        comparison: dict[str, Any] = {}
        for metric in METRICS:
            base = [run["baseline"][metric] for run in runs]
            aug = [run["augmented"][metric] for run in runs]
            comparison[metric] = {
                "baseline": bootstrap_interval([v for v in base if v is not None]),
                "augmented": bootstrap_interval([v for v in aug if v is not None]),
                "cohensD": cohens_d(aug, base),
            }

        report = {
            "schemaVersion": SCHEMA_VERSION,
            "generatedAt": datetime.now(timezone.utc).isoformat(),
            "command": " ".join(sys.argv),
            "question": (
                "Does adding analyst-verified benign observed events to the "
                "production training corpus reduce false positives?"
            ),
            "design": {
                "note": (
                    "V5's Arm 2 removed analyst-identified malicious rows from a "
                    "corpus of observed events, which production's fit set is "
                    "not. This adds analyst-verified benign observed events to "
                    "the telemetry corpus instead."
                ),
                "admission": (
                    "Positive-listed: a row enters only if its label is "
                    "training-eligible and projects to benign. confirmed_malicious, "
                    "true_positive, suspicious and uncertain are all refused."
                ),
                "maxFeedbackFraction": args.max_feedback_fraction,
                "capBinds": first["feedbackFraction"] >= args.max_feedback_fraction - 1e-9,
            },
            "composition": {
                "telemetryRows": first["telemetryRows"],
                "feedbackRows": first["feedbackRows"],
                "feedbackFraction": first["feedbackFraction"],
                "mislabelledRowsAdmitted": first["poisonedRows"],
                "admittedOutsideFitSplit": first["admittedOutsideFitSplit"],
                "admittedVectorsAlsoSeenInScoringSet": first[
                    "admittedVectorsAlsoSeenInScoringSet"
                ],
            },
            "scoring": {
                "datasetFingerprint": first["datasetFingerprint"],
                "splitFingerprint": first["splitFingerprint"],
                "threshold": scenarios.DEFAULT_THRESHOLD,
            },
            "protocol": {"seeds": seed_plan, "noiseRate": args.noise},
            "environment": {
                "python": platform.python_version(),
                "platform": platform.platform(),
            },
            "comparison": comparison,
            "perSeed": [
                {
                    "seed": run["seed"],
                    "baselineF1": run["baseline"]["f1"],
                    "augmentedF1": run["augmented"]["f1"],
                    "baselineFpr": run["baseline"]["falsePositiveRate"],
                    "augmentedFpr": run["augmented"]["falsePositiveRate"],
                }
                for run in runs
            ],
            "caveats": [
                "F1 is close to unchanged. This arm trades recall for precision; "
                "reporting it as an F1 result would misdescribe what it does.",
                "Feedback is simulated. There is no analyst population.",
                "Both corpora are synthetic.",
                "Nothing is deployed. Reaching production still requires an "
                "approved proposal and activate_model.",
            ],
        }
        path, _ = write_report(report, args.output_dir, prefix=REPORT_PREFIX)
    finally:
        if watchdog is not None:
            watchdog.cancel()

    if args.format == "json":
        print(json.dumps(report, indent=2))
    else:
        fpr = comparison["falsePositiveRate"]
        print(
            f"  FPR {fpr['baseline']['mean']} -> {fpr['augmented']['mean']} "
            f"(d={fpr['cohensD']})\n\n  Report written to {path}"
        )
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
