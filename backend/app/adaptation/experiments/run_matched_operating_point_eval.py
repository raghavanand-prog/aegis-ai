"""CLI: V5's comparison re-run without the frozen-threshold confound.

    python -m app.adaptation.experiments.run_matched_operating_point_eval --seeds 20

Reports each condition at the frozen 0.65 (as V5 did) beside three matched
measures a calibration shift cannot flatter, and sweeps the alert budget so the
operational comparison is legible.
"""

from __future__ import annotations

import argparse
import json
import platform
import statistics
import sys
from datetime import datetime, timezone
from typing import Any

from app.adaptation.experiments import matched_operating_point as mop
from app.adaptation.experiments import scenarios, seeds
from app.adaptation.experiments.matched_operating_point import _recall_at_budget
from app.evaluation.reports.store import write_report
from app.evaluation.watchdog import add_argument as add_timeout_argument
from app.evaluation.watchdog import start as start_watchdog

REPORT_PREFIX = "v6-matched-operating-point"
SCHEMA_VERSION = "1.0"
DEFAULT_BUDGETS = (3, 20, 39, 78)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="run_matched_operating_point_eval")
    parser.add_argument("--seeds", type=int, default=20)
    parser.add_argument("--budgets", type=int, nargs="+", default=list(DEFAULT_BUDGETS))
    parser.add_argument("--output-dir", default=None)
    parser.add_argument("--format", choices=("text", "json"), default="text")
    add_timeout_argument(parser)
    args = parser.parse_args(argv)

    watchdog = start_watchdog(args.max_seconds, label="v6 matched operating point")
    seed_plan = seeds.build_seeds(args.seeds)

    try:
        # Fit once per (seed, condition); every budget is then computed from the
        # same scores rather than refitting per budget.
        cache: dict[str, list[tuple[list[float], list[bool]]]] = {
            condition: [] for condition in mop.DEFAULT_CONDITIONS
        }
        per_seed_runs: list[dict[str, Any]] = []
        for seed in seed_plan:
            corpus = scenarios.prepare_corpus(seed=seed)
            results = {}
            for condition in mop.DEFAULT_CONDITIONS:
                result = scenarios.run_condition(corpus, condition=condition, seed=seed)
                cache[condition].append((result.scores, result.labels))
                results[condition] = result
            per_seed_runs.append(
                mop.run(seed=seed, conditions=mop.DEFAULT_CONDITIONS)
            )
            print(f"  seed {seed} done", flush=True)

        aggregated = mop.aggregate(per_seed_runs)

        budgets: dict[int, dict[str, float]] = {}
        for budget in args.budgets:
            budgets[budget] = {
                condition: round(
                    statistics.fmean(
                        [
                            _recall_at_budget(scores, labels, budget)[0]
                            for scores, labels in cache[condition]
                        ]
                    ),
                    6,
                )
                for condition in mop.DEFAULT_CONDITIONS
            }

        report = {
            "schemaVersion": SCHEMA_VERSION,
            "generatedAt": datetime.now(timezone.utc).isoformat(),
            "command": " ".join(sys.argv),
            "question": (
                "How much of V5's adaptation effect survives comparison at a "
                "matched operating point rather than a frozen 0.65?"
            ),
            "protocol": {
                "seeds": seed_plan,
                "frozenThreshold": scenarios.DEFAULT_THRESHOLD,
                "budgets": args.budgets,
                "datasetFingerprint": per_seed_runs[0]["datasetFingerprint"],
                "splitFingerprint": per_seed_runs[0]["splitFingerprint"],
                "testSamples": per_seed_runs[0]["testSamples"],
                "testMalicious": per_seed_runs[0]["testMalicious"],
            },
            "environment": {
                "python": platform.python_version(),
                "platform": platform.platform(),
            },
            "conditions": aggregated,
            "recallByBudget": {str(k): v for k, v in budgets.items()},
            "caveats": [
                "threshold_only is identical to static_v4 on every "
                "threshold-free measure BY CONSTRUCTION: Arm 1 moves the "
                "operating point and does not change the model, so it cannot "
                "change a ranking. Its entire apparent gain at 0.65 is "
                "threshold placement.",
                "curation_only and both_arms are likewise identical on "
                "threshold-free measures, for the same reason. All capability "
                "difference comes from Arm 2.",
                "best-achievable F1 is an optimistic ceiling chosen with "
                "knowledge of the labels. It is used because it is comparable, "
                "not because any operator attains it.",
                "A budget of 3 is the static baseline's own alert volume and is "
                "too small to discriminate - every condition is pinned near "
                "0.018. Reported for completeness, not as a comparison.",
                "The random-label control is retained. It is what decides "
                "whether a surviving effect is attributable to feedback content.",
                "Feedback is simulated; the corpus is synthetic.",
            ],
        }
        path, _ = write_report(report, args.output_dir, prefix=REPORT_PREFIX)
    finally:
        if watchdog is not None:
            watchdog.cancel()

    if args.format == "json":
        print(json.dumps(report, indent=2))
    else:
        static = aggregated["static_v4"]
        both = aggregated["both_arms"]
        print(
            f"\n  F1@0.65 {static['f1AtFrozen']} -> {both['f1AtFrozen']}"
            f"   ROC-AUC {static['rocAuc']} -> {both['rocAuc']}"
            f"\n  Report written to {path}"
        )
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
