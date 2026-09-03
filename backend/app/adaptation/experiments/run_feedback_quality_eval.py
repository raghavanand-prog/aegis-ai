"""CLI: Track 2 - feedback quality against the redesigned Arm 2.

    python -m app.adaptation.experiments.run_feedback_quality_eval --seeds 10

Reports recall beside the false-positive rate for every condition, because the
poisoning vector this arm exposes is visible in recall and invisible in FPR, F1
and ROC-AUC - all three of which it *improves*.
"""

from __future__ import annotations

import argparse
import json
import platform
import sys
from datetime import datetime, timezone
from typing import Any

from app.adaptation.experiments import feedback_quality, scenarios, seeds
from app.evaluation.metrics.ranking import bootstrap_interval, cohens_d
from app.evaluation.reports.store import write_report
from app.evaluation.watchdog import add_argument as add_timeout_argument
from app.evaluation.watchdog import start as start_watchdog

REPORT_PREFIX = "v6-feedback-quality"
SCHEMA_VERSION = "1.0"
METRICS = ("precision", "recall", "f1", "falsePositiveRate", "alertVolume", "rocAuc")


def _mean(values: list[float | None]) -> float | None:
    present = [value for value in values if value is not None]
    return round(sum(present) / len(present), 6) if present else None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="run_feedback_quality_eval")
    parser.add_argument("--seeds", type=int, default=10)
    parser.add_argument(
        "--conditions", nargs="+", default=list(feedback_quality.CONDITIONS)
    )
    parser.add_argument("--output-dir", default=None)
    parser.add_argument("--format", choices=("text", "json"), default="text")
    add_timeout_argument(parser)
    args = parser.parse_args(argv)

    watchdog = start_watchdog(args.max_seconds, label="v6 feedback quality")
    seed_plan = seeds.build_seeds(args.seeds)

    try:
        results: list[dict[str, Any]] = []
        for condition in args.conditions:
            spec = feedback_quality.CONDITIONS[condition]
            runs = [
                feedback_quality.measure(condition=condition, seed=seed)
                for seed in seed_plan
            ]
            comparison = {}
            for metric in METRICS:
                base = [run["baseline"][metric] for run in runs]
                aug = [run["augmented"][metric] for run in runs]
                comparison[metric] = {
                    "baseline": bootstrap_interval([v for v in base if v is not None]),
                    "augmented": bootstrap_interval([v for v in aug if v is not None]),
                    "delta": (
                        round(_mean(aug) - _mean(base), 6)
                        if _mean(aug) is not None and _mean(base) is not None
                        else None
                    ),
                    "cohensD": cohens_d(aug, base),
                }
            results.append(
                {
                    "condition": condition,
                    "description": spec.description,
                    "feedbackRows": _mean([run["feedbackRows"] for run in runs]),
                    "poisonedRows": _mean([run["poisonedRows"] for run in runs]),
                    "realisedErrorRate": _mean(
                        [run["realisedErrorRate"] for run in runs]
                    ),
                    "comparison": comparison,
                    "perSeed": [
                        {
                            "seed": run["seed"],
                            "fpr": run["augmented"]["falsePositiveRate"],
                            "recall": run["augmented"]["recall"],
                            "feedbackRows": run["feedbackRows"],
                        }
                        for run in runs
                    ],
                }
            )
            fpr = comparison["falsePositiveRate"]
            rec = comparison["recall"]
            print(
                f"  {condition:<18} rows={results[-1]['feedbackRows']:<7} "
                f"dFPR={fpr['delta']:<+9} dRecall={rec['delta']:<+9}",
                flush=True,
            )

        report = {
            "schemaVersion": SCHEMA_VERSION,
            "generatedAt": datetime.now(timezone.utc).isoformat(),
            "command": " ".join(sys.argv),
            "question": (
                "How does analyst feedback quality affect the redesigned Arm 2?"
            ),
            "protocol": {
                "seeds": seed_plan,
                "threshold": scenarios.DEFAULT_THRESHOLD,
                "baseline": "production configuration, telemetry corpus only",
            },
            "environment": {
                "python": platform.python_version(),
                "platform": platform.platform(),
            },
            "results": results,
            "caveats": [
                "Read recall, not FPR, to detect the benign-bias failure mode. "
                "Benign bias improves FPR, F1 and ROC-AUC while costing recall; "
                "monitoring any of those three would miss it.",
                "Sparse and delayed feedback make the model worse, not merely "
                "less good. Feedback volume is a precondition, not a dial.",
                "Poisoning here is diffuse - randomly chosen malicious events. A "
                "targeted adversary labelling one attack category benign is not "
                "modelled and would be a more informative test.",
                "Feedback is simulated; both corpora are synthetic.",
                "Nothing is deployed.",
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
