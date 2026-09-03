"""CLI: targeted poisoning of the redesigned Arm 2.

    python -m app.adaptation.experiments.run_targeted_poisoning_eval --seeds 8

Reports per-category recall beside the aggregate, and reports the aggregate's
seed-to-seed spread, because the finding is that the attack moves the aggregate
by less than its own noise.
"""

from __future__ import annotations

import argparse
import json
import platform
import statistics
import sys
from datetime import datetime, timezone
from typing import Any

from app.adaptation.experiments import (
    feedback_caps,
    scenarios,
    seeds,
    targeted_poisoning,
)
from app.evaluation.metrics.ranking import bootstrap_interval, cohens_d
from app.evaluation.reports.store import write_report
from app.evaluation.watchdog import add_argument as add_timeout_argument
from app.evaluation.watchdog import start as start_watchdog

REPORT_PREFIX = "v6-targeted-poisoning"
SCHEMA_VERSION = "1.0"
DEFAULT_TARGETS = (
    "MALWARE",
    "PORT_SCAN",
    "RANSOMWARE",
    "SUSPICIOUS_DNS",
    "BRUTE_FORCE",
)


def _clean(values: list[float | None]) -> list[float]:
    return [value for value in values if value is not None]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="run_targeted_poisoning_eval")
    parser.add_argument("--seeds", type=int, default=8)
    parser.add_argument("--targets", nargs="+", default=list(DEFAULT_TARGETS))
    parser.add_argument("--reach", type=float, nargs="+", default=[1.0])
    parser.add_argument(
        "--cap-policy", choices=list(feedback_caps.POLICIES),
        default=feedback_caps.POLICY_GLOBAL,
    )
    parser.add_argument("--per-group-ceiling", type=int, default=25)
    parser.add_argument(
        "--baseline-seeds", type=int, nargs="+", default=[2024, 7, 819369],
        help="honest seeds the per-group baseline is learned from; must exclude "
             "the seeds under attack, or the baseline learns the attack as normal",
    )
    parser.add_argument("--output-dir", default=None)
    parser.add_argument("--format", choices=("text", "json"), default="text")
    add_timeout_argument(parser)
    args = parser.parse_args(argv)

    watchdog = start_watchdog(args.max_seconds, label="v6 targeted poisoning")
    seed_plan = seeds.build_seeds(args.seeds)

    try:
        baseline_rates = (
            targeted_poisoning.honest_baseline_rates(seeds=tuple(args.baseline_seeds))
            if args.cap_policy == feedback_caps.POLICY_BASELINE_RELATIVE
            else None
        )

        results: list[dict[str, Any]] = []
        for target in args.targets:
            for reach in args.reach:
                runs = [
                    targeted_poisoning.measure(
                        seed=seed,
                        target_category=target,
                        adversary_reach=reach,
                        cap_policy=args.cap_policy,
                        per_group_ceiling=args.per_group_ceiling,
                        baseline_rates=baseline_rates,
                    )
                    for seed in seed_plan
                ]
                agg_base = _clean([r["aggregate"]["baseline"]["recall"] for r in runs])
                agg_pois = _clean([r["aggregate"]["poisoned"]["recall"] for r in runs])
                tgt_base = _clean([r["targetRecall"]["baseline"] for r in runs])
                tgt_pois = _clean([r["targetRecall"]["poisoned"] for r in runs])

                target_delta = (
                    statistics.fmean(tgt_pois) - statistics.fmean(tgt_base)
                    if tgt_base and tgt_pois
                    else None
                )
                aggregate_delta = (
                    statistics.fmean(agg_pois) - statistics.fmean(agg_base)
                    if agg_base and agg_pois
                    else None
                )
                results.append(
                    {
                        "targetCategory": target,
                        "adversaryReach": reach,
                        "poisonedRows": statistics.fmean(
                            [r["poisonedRows"] for r in runs]
                        ),
                        "targetRecall": {
                            "baseline": bootstrap_interval(tgt_base),
                            "poisoned": bootstrap_interval(tgt_pois),
                            "delta": round(target_delta, 6) if target_delta else None,
                            "cohensD": cohens_d(tgt_pois, tgt_base),
                        },
                        "aggregateRecall": {
                            "baseline": bootstrap_interval(agg_base),
                            "poisoned": bootstrap_interval(agg_pois),
                            "delta": round(aggregate_delta, 6)
                            if aggregate_delta
                            else None,
                            "cohensD": cohens_d(agg_pois, agg_base),
                            # The number that decides whether a gate can see it.
                            "seedStdev": round(statistics.pstdev(agg_base), 6)
                            if len(agg_base) > 1
                            else None,
                        },
                        "attenuation": (
                            round(abs(target_delta / aggregate_delta), 2)
                            if target_delta and aggregate_delta
                            else None
                        ),
                        "aggregateFprDelta": round(
                            statistics.fmean(
                                _clean(
                                    [
                                        r["aggregate"]["poisoned"]["falsePositiveRate"]
                                        for r in runs
                                    ]
                                )
                            )
                            - statistics.fmean(
                                _clean(
                                    [
                                        r["aggregate"]["baseline"]["falsePositiveRate"]
                                        for r in runs
                                    ]
                                )
                            ),
                            6,
                        ),
                    }
                )
                row = results[-1]
                print(
                    f"  {target:<22} reach={reach:<5} rows={row['poisonedRows']:<6.1f} "
                    f"target Δ={row['targetRecall']['delta']} "
                    f"aggregate Δ={row['aggregateRecall']['delta']} "
                    f"(seed sd {row['aggregateRecall']['seedStdev']})",
                    flush=True,
                )

        report = {
            "schemaVersion": SCHEMA_VERSION,
            "generatedAt": datetime.now(timezone.utc).isoformat(),
            "command": " ".join(sys.argv),
            "question": (
                "Does the recall floor recommended in §7.3 detect a targeted "
                "poisoning attack on one attack category?"
            ),
            "threatModel": (
                "A compromised, coerced or careless analyst with ordinary "
                "feedback permissions - no privileged access, no code execution. "
                "Every existing control is respected: only benign-projecting "
                "labels are admitted, the feedback cap holds, and deployment "
                "still requires approval. The question is sufficiency."
            ),
            "protocol": {
                "seeds": seed_plan,
                "threshold": scenarios.DEFAULT_THRESHOLD,
                "maxFeedbackFraction": targeted_poisoning.arm2.DEFAULT_MAX_FEEDBACK_FRACTION,
                "capPolicy": args.cap_policy,
                "groupField": targeted_poisoning.GROUP_FIELD,
                "baselineSeeds": args.baseline_seeds if baseline_rates else None,
                "baselineRates": baseline_rates,
            },
            "environment": {
                "python": platform.python_version(),
                "platform": platform.platform(),
            },
            "results": results,
            "caveats": [
                "Per-category recall is measured over a few dozen held-out "
                "samples, so its own intervals are wide. The attenuation figure "
                "is the robust part of this result, not the per-category point "
                "estimate.",
                "A category the detector already misses cannot be poisoned - "
                "there is no recall to remove.",
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
