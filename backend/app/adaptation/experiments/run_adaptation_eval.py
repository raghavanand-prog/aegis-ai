"""CLI: the V5 adaptation evaluation.

    python -m app.adaptation.experiments.run_adaptation_eval --seeds 3

Runs the pre-registered matrix from ``docs/V5_EXPERIMENTAL_DESIGN.md`` and
writes a schema-versioned JSON report beside V4's, using the same store.

Reports every condition including the controls, and reports them whether or not
they favour adaptation. The random-label control exists precisely to be able to
say "the improvement did not come from feedback", and a runner that quietly
omitted it would make that impossible.
"""

from __future__ import annotations

import argparse
import json
import platform
import statistics
import sys
from datetime import datetime, timezone
from typing import Any

from app.adaptation.experiments import scenarios
from app.evaluation.reports.store import write_report
from app.evaluation.watchdog import add_argument as add_timeout_argument
from app.evaluation.watchdog import start as start_watchdog

REPORT_PREFIX = "v5-adaptation"
SCHEMA_VERSION = "1.0"

#: Conditions. The first is the comparison of record; the last three are the
#: controls that decide what may be claimed.
CONDITIONS = (
    "static_v4",
    "threshold_only",
    "curation_only",
    "both_arms",
    "random_feedback",
    "no_feedback_retrain",
)

#: Requested label-noise rates. 0% is an unrealistic ceiling, 5% a plausible
#: SOC, 15% a bad week.
NOISE_RATES = (0.0, 0.05, 0.15)

#: Conditions whose behaviour does not depend on feedback quality, so running
#: them at every noise rate would repeat identical work.
NOISE_INVARIANT = {"static_v4", "no_feedback_retrain"}


def _aggregate(values: list[float | None]) -> dict[str, Any]:
    """Mean and spread, or an explicit null where the metric was undefined."""
    present = [value for value in values if value is not None]
    if not present:
        return {"mean": None, "min": None, "max": None, "stdev": None, "runs": len(values)}
    return {
        "mean": round(statistics.fmean(present), 6),
        "min": round(min(present), 6),
        "max": round(max(present), 6),
        "stdev": round(statistics.pstdev(present), 6) if len(present) > 1 else 0.0,
        "runs": len(present),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="run_adaptation_eval",
        description="V5 static-vs-adaptive evaluation.",
    )
    parser.add_argument("--seeds", type=int, default=3, help="how many seeds per condition")
    parser.add_argument("--coverage", type=float, default=0.5)
    parser.add_argument("--abstention", type=float, default=0.10)
    parser.add_argument("--fp-bias", type=float, default=0.2)
    parser.add_argument("--output-dir", default=None)
    parser.add_argument("--format", choices=("text", "json"), default="text")
    add_timeout_argument(parser)
    args = parser.parse_args(argv)

    watchdog = start_watchdog(args.max_seconds, label="v5 adaptation evaluation")
    seeds = [1337, 4242, 99, 2024, 7][: args.seeds]

    try:
        corpus = scenarios.prepare_corpus()
        results: list[dict[str, Any]] = []

        for condition in CONDITIONS:
            rates = (0.05,) if condition in NOISE_INVARIANT else NOISE_RATES
            for noise in rates:
                runs = []
                for seed in seeds:
                    result = scenarios.run_condition(
                        corpus,
                        condition=condition,
                        seed=seed,
                        noise_rate=noise,
                        coverage=args.coverage,
                        abstention_rate=args.abstention,
                        false_positive_bias=args.fp_bias,
                    )
                    runs.append(result)
                    print(
                        f"  {condition:<22} noise={noise:<5} seed={seed:<5} "
                        f"F1={result.metrics['f1']} FPR={result.metrics['falsePositiveRate']}",
                        flush=True,
                    )

                results.append(
                    {
                        "condition": condition,
                        "requestedNoiseRate": noise,
                        "seeds": seeds,
                        "metrics": {
                            metric: _aggregate([run.metrics[metric] for run in runs])
                            for metric in (
                                "precision",
                                "recall",
                                "f1",
                                "falsePositiveRate",
                                "falseNegativeRate",
                                "alertVolume",
                                "threshold",
                            )
                        },
                        "timings": {
                            key: _aggregate([run.timings.get(key) for run in runs])
                            for key in (
                                "baselineTrainingSeconds",
                                "candidateTrainingSeconds",
                                "thresholdSelectionSeconds",
                                "evaluationSeconds",
                                "latencyMsPerEvent",
                            )
                        },
                        "notes": runs[0].notes,
                    }
                )

        report = {
            "schemaVersion": SCHEMA_VERSION,
            "generatedAt": datetime.now(timezone.utc).isoformat(),
            "command": " ".join(sys.argv),
            "design": "docs/V5_EXPERIMENTAL_DESIGN.md",
            "dataset": {
                "name": corpus.name,
                "version": corpus.version,
                "fingerprint": corpus.fingerprint,
                "splitFingerprint": corpus.split_fingerprint,
                "fitSamples": len(corpus.fit_vectors),
                "testSamples": len(corpus.test_vectors),
                "testMalicious": sum(corpus.test_labels),
            },
            "protocol": {
                "split": "stratified_group (V4 splitter), test read once per condition",
                "coverage": args.coverage,
                "abstentionRate": args.abstention,
                "falsePositiveBias": args.fp_bias,
                "maxThresholdStep": scenarios.MAX_THRESHOLD_STEP,
                "baselineThreshold": scenarios.DEFAULT_THRESHOLD,
            },
            "environment": {
                "python": platform.python_version(),
                "platform": platform.platform(),
            },
            "results": results,
            "caveats": [
                "Feedback is simulated. There is no analyst population, and the "
                "simulator is a model of an analyst rather than an analyst.",
                "The corpus is synthetic. Nothing here is evidence about "
                "real-world attack traffic.",
                "Latency is single-process on one laptop: a relative measure, "
                "not a throughput claim.",
                "Human approval time is not measured and is not estimated.",
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
