"""CLI: the patient baseline-poisoning adversary (V6 §9.3, tested in §11).

    python -m app.adaptation.experiments.run_patient_poisoning_eval --seeds 8

Runs an honest campaign and an adversarial one of the same length, and reports
the ceiling each earns. The honest arm is not decoration: if it ratchets too,
the effect is an artefact of the simulation rather than an attack.

Also sweeps ``tolerance``, because that is the parameter that decides whether
the ratchet turns at all.
"""

from __future__ import annotations

import argparse
import json
import platform
import statistics
import sys
from datetime import datetime, timezone
from typing import Any

from app.adaptation.experiments import patient_poisoning, seeds
from app.adaptation.feedback import caps
from app.evaluation.metrics.ranking import bootstrap_interval, cohens_d
from app.evaluation.reports.store import write_report
from app.evaluation.watchdog import add_argument as add_timeout_argument
from app.evaluation.watchdog import start as start_watchdog

REPORT_PREFIX = "v6-patient-poisoning"
SCHEMA_VERSION = "1.0"


def _mean(values: list[float]) -> float | None:
    return round(statistics.fmean(values), 6) if values else None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="run_patient_poisoning_eval")
    parser.add_argument("--seeds", type=int, default=8)
    parser.add_argument("--target", default="MALWARE")
    parser.add_argument("--cycles", type=int, default=10)
    parser.add_argument("--tolerances", type=float, nargs="+", default=[1.25, 1.5, 2.0, 3.0])
    parser.add_argument("--damage-cycles", type=int, nargs="+", default=[1, 3, 6, 10])
    parser.add_argument("--output-dir", default=None)
    parser.add_argument("--format", choices=("text", "json"), default="text")
    add_timeout_argument(parser)
    args = parser.parse_args(argv)

    watchdog = start_watchdog(args.max_seconds, label="v6 patient poisoning")
    seed_plan = seeds.build_seeds(args.seeds)

    try:
        # --- the ratchet, against its control -----------------------------
        arms: dict[str, Any] = {}
        for name, reach in (("honest", 0.0), ("adversary", 1.0)):
            runs = [
                patient_poisoning.run_campaign(
                    seed=seed,
                    target_category=args.target,
                    cycles=args.cycles,
                    adversary_reach=reach,
                )
                for seed in seed_plan
            ]
            arms[name] = {
                "allowanceByCycle": [
                    _mean([run["cycles"][i]["targetAllowance"] for run in runs])
                    for i in range(args.cycles)
                ],
                "poisonByCycle": [
                    _mean([float(run["cycles"][i]["poisonLanded"]) for run in runs])
                    for i in range(args.cycles)
                ],
                "maliciousAdmittedByCycle": [
                    _mean([float(run["cycles"][i]["maliciousAdmitted"]) for run in runs])
                    for i in range(args.cycles)
                ],
                "honestBaselineRate": _mean([run["honestBaselineRate"] for run in runs]),
            }
            print(
                f"  {name:<10} allowance {arms[name]['allowanceByCycle'][0]} -> "
                f"{arms[name]['allowanceByCycle'][-1]}  "
                f"poison {arms[name]['poisonByCycle'][-1]}",
                flush=True,
            )

        # --- tolerance: containment against honest throughput --------------
        tolerance_rows = []
        for tolerance in args.tolerances:
            attacked = [
                patient_poisoning.run_campaign(
                    seed=seed,
                    target_category=args.target,
                    cycles=args.cycles,
                    adversary_reach=1.0,
                    tolerance=tolerance,
                )
                for seed in seed_plan
            ]
            honest = [
                patient_poisoning.run_campaign(
                    seed=seed,
                    target_category=args.target,
                    cycles=args.cycles,
                    adversary_reach=0.0,
                    tolerance=tolerance,
                )
                for seed in seed_plan
            ]
            tolerance_rows.append(
                {
                    "tolerance": tolerance,
                    "attackPoisonFinal": _mean(
                        [float(c["cycles"][-1]["poisonLanded"]) for c in attacked]
                    ),
                    "honestAdmittedFinal": _mean(
                        [float(c["cycles"][-1]["totalAdmitted"]) for c in honest]
                    ),
                    "honestTargetAdmittedFinal": _mean(
                        [float(c["cycles"][-1]["targetAdmitted"]) for c in honest]
                    ),
                }
            )
            row = tolerance_rows[-1]
            print(
                f"  tolerance {tolerance:<6} attack poison {row['attackPoisonFinal']:<8} "
                f"honest admitted {row['honestAdmittedFinal']}",
                flush=True,
            )

        # --- does it cost detection? --------------------------------------
        damage_rows = []
        for cycles in args.damage_cycles:
            runs = [
                patient_poisoning.measure_damage(
                    seed=seed,
                    target_category=args.target,
                    cycles=cycles,
                    adversary_reach=1.0,
                )
                for seed in seed_plan
            ]
            honest = [
                r["targetRecall"]["honest"]
                for r in runs
                if r["targetRecall"]["honest"] is not None
            ]
            poisoned = [
                r["targetRecall"]["poisoned"]
                for r in runs
                if r["targetRecall"]["poisoned"] is not None
            ]
            damage_rows.append(
                {
                    "cycles": cycles,
                    "finalPoisonLanded": _mean(
                        [float(r["finalPoisonLanded"]) for r in runs]
                    ),
                    "targetRecallHonest": bootstrap_interval(honest),
                    "targetRecallPoisoned": bootstrap_interval(poisoned),
                    "cohensD": cohens_d(poisoned, honest),
                }
            )

        report = {
            "schemaVersion": SCHEMA_VERSION,
            "generatedAt": datetime.now(timezone.utc).isoformat(),
            "command": " ".join(sys.argv),
            "question": (
                "Can an adversary defeat the baseline_relative cap by raising "
                "the baseline over several feedback cycles instead of "
                "attacking one batch?"
            ),
            "threatModel": (
                "An analyst with ordinary feedback permissions and patience. "
                "Every control is respected and every individual batch is "
                "within policy; the campaign starts from honest history because "
                "production refuses a cold start."
            ),
            "protocol": {
                "seeds": seed_plan,
                "cycles": args.cycles,
                "target": args.target,
                "defaultTolerance": caps.DEFAULT_TOLERANCE,
                "honestHistory": patient_poisoning.DEFAULT_HONEST_HISTORY,
            },
            "environment": {
                "python": platform.python_version(),
                "platform": platform.platform(),
            },
            "arms": arms,
            "tolerance": tolerance_rows,
            "damage": damage_rows,
            "caveats": [
                "The ratchet on the allowance is the robust result. The recall "
                "damage is directionally present but its per-category intervals "
                "overlap heavily, exactly as V6 §8.5 established for this "
                "metric at these sample sizes; no dose-response curve is "
                "claimed from it.",
                "The honest arm is the control. It does not ratchet, which is "
                "what makes the adversarial ratchet attributable.",
                "Poison is counted as malicious rows admitted *in the targeted "
                "group*. Honest label noise admits malicious rows too - "
                "measured around 14 per cycle - and a metric counting all of "
                "them cannot see this attack.",
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
