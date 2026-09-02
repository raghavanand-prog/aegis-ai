"""Detection evaluation CLI.

    python -m app.evaluation.run_detection_eval
    python -m app.evaluation.run_detection_eval --samples-per-class 200 --seed 7
    python -m app.evaluation.run_detection_eval --format json --quiet
    python -m app.evaluation.run_detection_eval --fail-under-f1 0.80   # CI gate

Runs the current deterministic detection engine against the labelled evaluation
dataset and writes a machine-readable report plus a human-readable summary.
Nothing about the result is hard coded: change a rule, rerun, and the numbers
move.
"""

from __future__ import annotations

import argparse
import json
import sys

from app.evaluation.datasets.labeled_dataset import (
    DEFAULT_SAMPLES_PER_CLASS,
    DEFAULT_SEED,
    build_dataset,
)
from app.evaluation.reports.store import write_report
from app.evaluation.runners.detection_runner import run_detection_evaluation
from app.evaluation.watchdog import add_argument as add_timeout_argument
from app.evaluation.watchdog import start as start_watchdog


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m app.evaluation.run_detection_eval",
        description="Evaluate the AEGISX deterministic detection engine against labelled data.",
    )
    parser.add_argument(
        "--seed", type=int, default=DEFAULT_SEED, help="dataset seed (default: %(default)s)"
    )
    parser.add_argument(
        "--samples-per-class",
        type=int,
        default=DEFAULT_SAMPLES_PER_CLASS,
        help="malicious samples generated per attack class (default: %(default)s)",
    )
    parser.add_argument(
        "--format",
        choices=("text", "json", "both"),
        default="both",
        help="what to print (default: %(default)s)",
    )
    parser.add_argument(
        "--output-dir",
        default=None,
        help="where to write reports (default: app/evaluation/reports)",
    )
    parser.add_argument("--no-write", action="store_true", help="do not write report files")
    parser.add_argument("--quiet", action="store_true", help="suppress stdout output")
    parser.add_argument(
        "--fail-under-f1",
        type=float,
        default=None,
        metavar="F1",
        help="exit non-zero when the overall F1 score falls below this value (for CI)",
    )
    parser.add_argument(
        "--fail-over-fpr",
        type=float,
        default=None,
        metavar="FPR",
        help="exit non-zero when the false positive rate rises above this value (for CI)",
    )
    add_timeout_argument(parser)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    # A wall-clock ceiling so a hung run fails with a diagnosis instead of
    # burning a CI job. See app/evaluation/watchdog.py.
    watchdog = start_watchdog(args.max_seconds, label="detection evaluation")

    dataset = build_dataset(seed=args.seed, samples_per_class=args.samples_per_class)
    report = run_detection_evaluation(dataset)
    payload = report.to_dict()

    if not args.no_write:
        detailed, latest = write_report(payload, args.output_dir)
        if not args.quiet:
            print(f"report written: {detailed}")
            print(f"latest report: {latest}")

    if not args.quiet:
        if args.format in ("text", "both"):
            print(report.to_text())
        if args.format in ("json", "both"):
            print(json.dumps(payload, indent=2))

    exit_code = 0
    overall = payload["overall"]

    if args.fail_under_f1 is not None:
        f1 = overall["f1"]
        if f1 is None or f1 < args.fail_under_f1:
            print(
                f"FAIL: F1 {f1} is below the required {args.fail_under_f1}",
                file=sys.stderr,
            )
            exit_code = 1

    if args.fail_over_fpr is not None:
        fpr = overall["falsePositiveRate"]
        if fpr is None or fpr > args.fail_over_fpr:
            print(
                f"FAIL: false positive rate {fpr} exceeds the allowed {args.fail_over_fpr}",
                file=sys.stderr,
            )
            exit_code = 1

    if watchdog is not None:
        watchdog.cancel()
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
