"""CLI: the V6 Track 3 controlled novel-behaviour experiment.

    python -m app.adaptation.experiments.run_novel_behaviour_eval --seeds 10

V5 section 3 reported recall 0.000 -> 0.0085 on withheld attack categories and
concluded that adaptation does not help against novel behaviour. Two problems
with that as stated, both found by V6 Track 3:

1. The V5 harness draws feedback from the fit set the category was removed
   from, so the loop is never told the category exists. The result cannot
   separate "curation cannot teach an unseen pattern" from "nobody mentioned
   the pattern".
2. V5 averaged across categories. They differ in kind: some withheld categories
   score above the benign mass and are separable by a model that has never seen
   them, others score *below* the benign median and are unreachable at any
   threshold. A mean across those describes neither.

So this runner varies exactly one thing - whether the analyst labelled any
instance of the withheld category - and reports **per category**, never
aggregated across them.

There was also no committed runner for the V5 scenario at all; its numbers came
from an uncommitted ad-hoc invocation. This module is the reproducible command
that was missing.
"""

from __future__ import annotations

import argparse
import json
import platform
import statistics
import sys
from datetime import datetime, timezone
from typing import Any

from app.adaptation.experiments import scenarios, seeds
from app.evaluation.reports.store import write_report
from app.evaluation.watchdog import add_argument as add_timeout_argument
from app.evaluation.watchdog import start as start_watchdog

REPORT_PREFIX = "v6-novel-behaviour"
SCHEMA_VERSION = "1.0"

#: Every attack category in the synthetic corpus. The default is all of them
#: because selecting a favourable subset is exactly the error V5's aggregate
#: made harder to see.
DEFAULT_CATEGORIES = (
    "ANOMALOUS_SIGNIN",
    "BRUTE_FORCE",
    "CREDENTIAL_ACCESS",
    "DATA_EXFILTRATION",
    "LATERAL_MOVEMENT",
    "LOLBIN_EXECUTION",
    "MALWARE",
    "PORT_SCAN",
    "PRIVILEGE_ESCALATION",
    "RANSOMWARE",
    "SUSPICIOUS_DNS",
    "SUSPICIOUS_DOWNLOAD",
    "SUSPICIOUS_POWERSHELL",
)

ARMS = {"feedbackWithheld": False, "feedbackSupplied": True}


def _mean(values: list[float | None]) -> float | None:
    present = [value for value in values if value is not None]
    return round(statistics.fmean(present), 6) if present else None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="run_novel_behaviour_eval",
        description="V6 Track 3 controlled novel-behaviour experiment.",
    )
    parser.add_argument("--seeds", type=int, default=10)
    parser.add_argument("--categories", nargs="+", default=list(DEFAULT_CATEGORIES))
    parser.add_argument("--noise", type=float, default=0.05)
    parser.add_argument("--coverage", type=float, default=0.5)
    parser.add_argument("--window-fraction", type=float, default=0.5)
    parser.add_argument("--output-dir", default=None)
    parser.add_argument("--format", choices=("text", "json"), default="text")
    add_timeout_argument(parser)
    args = parser.parse_args(argv)

    watchdog = start_watchdog(args.max_seconds, label="v6 novel behaviour")
    seed_plan = seeds.build_seeds(args.seeds)

    try:
        results: list[dict[str, Any]] = []
        for category in args.categories:
            per_seed: list[dict[str, Any]] = []
            arms: dict[str, dict[str, Any]] = {}
            skipped: str | None = None

            for arm, supplied in ARMS.items():
                runs = []
                for seed in seed_plan:
                    try:
                        runs.append(
                            scenarios.run_novel_behaviour_controlled(
                                seed=seed,
                                withheld_category=category,
                                feedback_includes_withheld=supplied,
                                adaptation_window_fraction=args.window_fraction,
                                noise_rate=args.noise,
                                coverage=args.coverage,
                            )
                        )
                    except ValueError as error:
                        # A category with too few held-out samples cannot be
                        # measured. Recorded as unmeasurable, never as zero.
                        skipped = str(error)
                        break
                if skipped:
                    break

                arms[arm] = {
                    "verdictsAboutWithheld": _mean(
                        [run["verdictsAboutWithheld"] for run in runs]
                    ),
                    "threshold": _mean([run["threshold"] for run in runs]),
                    "novelRecall": _mean(
                        [run["adapted"]["newBehaviour"]["recall"] for run in runs]
                    ),
                    "historicalRecall": _mean(
                        [run["adapted"]["historical"]["recall"] for run in runs]
                    ),
                    "historicalF1": _mean(
                        [run["adapted"]["historical"]["f1"] for run in runs]
                    ),
                    "staticNovelRecall": _mean(
                        [run["static"]["newBehaviour"]["recall"] for run in runs]
                    ),
                    "novelScoresAboveFloor": _mean(
                        [run["novelScores"]["aboveFloor"] for run in runs]
                    ),
                    "novelScoreMax": _mean([run["novelScores"]["max"] for run in runs]),
                    "novelScoreMedian": _mean(
                        [run["novelScores"]["median"] for run in runs]
                    ),
                    "scoredSamples": _mean([run["novelScores"]["count"] for run in runs]),
                }
                per_seed.extend(
                    {
                        "arm": arm,
                        "seed": run["seed"],
                        "threshold": run["threshold"],
                        "verdictsAboutWithheld": run["verdictsAboutWithheld"],
                        "novelRecall": run["adapted"]["newBehaviour"]["recall"],
                        "staticNovelRecall": run["static"]["newBehaviour"]["recall"],
                        "historicalRecall": run["adapted"]["historical"]["recall"],
                        "novelScoresAboveFloor": run["novelScores"]["aboveFloor"],
                        "novelScoreMax": run["novelScores"]["max"],
                    }
                    for run in runs
                )

            if skipped:
                results.append(
                    {
                        "withheldCategory": category,
                        "measurable": False,
                        "unavailableReason": skipped,
                    }
                )
                print(f"  {category:<24} not measurable: {skipped}", flush=True)
                continue

            floor = scenarios.DEFAULT_THRESHOLD - scenarios.MAX_THRESHOLD_STEP
            reachable = (arms["feedbackSupplied"]["novelScoresAboveFloor"] or 0) > 0
            results.append(
                {
                    "withheldCategory": category,
                    "measurable": True,
                    "reachableThresholdFloor": floor,
                    # The diagnosis. If the novel events never score above the
                    # most permissive reachable operating point, no feedback can
                    # help through the only channel that could use it.
                    "separableByReachableThreshold": reachable,
                    "arms": arms,
                    "perSeed": per_seed,
                }
            )
            print(
                f"  {category:<24} separable={str(reachable):<5} "
                f"withheld recall={arms['feedbackWithheld']['novelRecall']} "
                f"supplied recall={arms['feedbackSupplied']['novelRecall']} "
                f"(verdicts {arms['feedbackSupplied']['verdictsAboutWithheld']})",
                flush=True,
            )

        report = {
            "schemaVersion": SCHEMA_VERSION,
            "generatedAt": datetime.now(timezone.utc).isoformat(),
            "command": " ".join(sys.argv),
            "design": "docs/V6_RESEARCH_REPORT.md",
            "question": (
                "Does the V5 novel-behaviour result survive supplying the "
                "adaptation loop with feedback about the withheld category?"
            ),
            "protocol": {
                "seeds": seed_plan,
                "noiseRate": args.noise,
                "coverage": args.coverage,
                "adaptationWindowFraction": args.window_fraction,
                "baselineThreshold": scenarios.DEFAULT_THRESHOLD,
                "maxThresholdStep": scenarios.MAX_THRESHOLD_STEP,
                "leakageControl": (
                    "Held-out samples of the withheld category are partitioned "
                    "into an adaptation window the analyst may label and a "
                    "scoring set neither arm labels. Both arms score on the "
                    "identical scoring set."
                ),
            },
            "environment": {
                "python": platform.python_version(),
                "platform": platform.platform(),
            },
            "results": results,
            "caveats": [
                "Feedback is simulated. There is no analyst population.",
                "The corpus is synthetic.",
                "Curation cannot act on novel behaviour at all - it only removes "
                "rows from a fit set the category was excluded from - so "
                "threshold selection is the only channel under test.",
                "Results are reported per category and are not averaged across "
                "categories, which differ in whether the model separates them "
                "at all.",
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
