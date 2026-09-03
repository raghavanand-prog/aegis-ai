"""CLI: does fit-set contamination explain the V4/V5 detection baseline?

    python -m app.adaptation.experiments.run_contamination_eval --seeds 10

Holds corpus, split, seed, detector, fit-set size and test set fixed, and varies
only the malicious fraction of the fitting data. Also reports the contamination
that V5's curation arm actually reaches, because that is the quantity linking
this sweep to the Track 1 results.
"""

from __future__ import annotations

import argparse
import json
import platform
import statistics
import sys
from datetime import datetime, timezone
from typing import Any

from app.adaptation.experiments import contamination, scenarios, seeds, simulation
from app.evaluation.reports.store import write_report
from app.evaluation.watchdog import add_argument as add_timeout_argument
from app.evaluation.watchdog import start as start_watchdog

REPORT_PREFIX = "v6-contamination"
SCHEMA_VERSION = "1.0"
CURATION_NOISE_RATES = (0.0, 0.05, 0.15)


def _mean(values: list[float | None]) -> float | None:
    present = [value for value in values if value is not None]
    return round(statistics.fmean(present), 6) if present else None


def _curation_residual(seed_plan: list[int]) -> list[dict[str, Any]]:
    """The contamination V5's curation arm leaves behind, per noise rate.

    Curation drops rows an analyst called malicious, so it *is* a contamination
    reduction - and label noise decides how much of the contamination survives.
    """
    corpus = scenarios.prepare_corpus(seed=1337)
    before = sum(corpus.fit_labels) / len(corpus.fit_labels)
    rows = []
    for noise in CURATION_NOISE_RATES:
        residuals, sizes = [], []
        for seed in seed_plan:
            verdicts = simulation.simulate_feedback(
                corpus.fit_labels,
                seed=seed,
                noise_rate=noise,
                coverage=0.5,
                abstention_rate=0.10,
                false_positive_bias=0.2,
            )
            believed = {
                v.index: v.label.binary_label
                for v in verdicts
                if v.label.is_training_eligible and v.label.binary_label is not None
            }
            kept = [
                index
                for index in range(len(corpus.fit_vectors))
                if not believed.get(index, False)
            ]
            residuals.append(
                sum(1 for index in kept if corpus.fit_labels[index]) / len(kept)
            )
            sizes.append(len(kept))
        rows.append(
            {
                "noiseRate": noise,
                "maliciousFractionBefore": round(before, 6),
                "maliciousFractionAfter": _mean(residuals),
                "fitSizeAfter": _mean(sizes),
            }
        )
    return rows


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="run_contamination_eval")
    parser.add_argument("--seeds", type=int, default=10)
    parser.add_argument("--fit-size", type=int, default=contamination.DEFAULT_FIT_SIZE)
    parser.add_argument("--output-dir", default=None)
    parser.add_argument("--format", choices=("text", "json"), default="text")
    add_timeout_argument(parser)
    args = parser.parse_args(argv)

    watchdog = start_watchdog(args.max_seconds, label="v6 contamination sweep")
    seed_plan = seeds.build_seeds(args.seeds)

    try:
        results: list[dict[str, Any]] = []
        fingerprint = split_fingerprint = None
        for level in contamination.LEVELS:
            runs = [
                contamination.measure(
                    seed=seed, malicious_fraction=level, size=args.fit_size
                )
                for seed in seed_plan
            ]
            fingerprint = fingerprint or runs[0]["datasetFingerprint"]
            split_fingerprint = split_fingerprint or runs[0]["splitFingerprint"]
            results.append(
                {
                    "requestedMaliciousFraction": level,
                    "actualMaliciousFraction": runs[0]["maliciousFraction"],
                    "fitSize": args.fit_size,
                    "seeds": seed_plan,
                    "rocAuc": _mean([run["rocAuc"] for run in runs]),
                    "metrics": {
                        key: _mean([run["metrics"][key] for run in runs])
                        for key in (
                            "precision",
                            "recall",
                            "f1",
                            "falsePositiveRate",
                            "alertVolume",
                        )
                    },
                    "perSeed": [
                        {
                            "seed": run["seed"],
                            "rocAuc": run["rocAuc"],
                            "f1": run["metrics"]["f1"],
                        }
                        for run in runs
                    ],
                }
            )
            print(
                f"  malicious={level:<6} rocAuc={results[-1]['rocAuc']:<10} "
                f"F1@0.65={results[-1]['metrics']['f1']}",
                flush=True,
            )

        report = {
            "schemaVersion": SCHEMA_VERSION,
            "generatedAt": datetime.now(timezone.utc).isoformat(),
            "command": " ".join(sys.argv),
            "question": (
                "Is the V4/V5 static detection baseline an artefact of fitting an "
                "unsupervised detector on a 40%-malicious corpus?"
            ),
            "dataset": {
                "name": "aegisx-detection-eval",
                "fingerprint": fingerprint,
                "splitFingerprint": split_fingerprint,
                "note": (
                    "Track 1's corpus. The fit split is resampled to a constant "
                    "size at every level so sample count cannot be confounded "
                    "with contamination; the test set is never resampled. The "
                    "40% row is therefore not identical to V5's static baseline, "
                    "which used the full 1,560-row fit split."
                ),
            },
            "protocol": {
                "seeds": seed_plan,
                "fitSize": args.fit_size,
                "threshold": scenarios.DEFAULT_THRESHOLD,
                "productionTrainingContamination": (
                    "~12% suspicious scenarios in the runtime telemetry generator "
                    "that train_anomaly_model actually fits, measured from its "
                    "scenario mix"
                ),
            },
            "curationResidual": _curation_residual(seed_plan),
            "environment": {
                "python": platform.python_version(),
                "platform": platform.platform(),
            },
            "results": results,
            "caveats": [
                "The corpus is synthetic, and its own provenance calls it out of "
                "distribution for the anomaly model.",
                "contamination as a *parameter* is not what is varied here. It "
                "never reaches anomaly_score, which squashes the raw score about "
                "the median of the training scores. What varies is the fitting "
                "data itself.",
                "Nothing here is deployed. The production model is trained by "
                "train_anomaly_model on a different corpus and is unchanged.",
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
