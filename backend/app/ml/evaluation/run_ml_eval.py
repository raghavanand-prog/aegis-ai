"""Run the hybrid detection evaluation.

    python -m app.ml.evaluation.run_ml_eval

Rebuilds the labelled dataset from its seed, loads the registered model exactly
as the running system loads it, and measures rules, ML and both over the same
samples. Reports are written next to the V2 detection reports so the two can be
read side by side.

Exit codes follow the V2 CLI: non-zero when a floor is breached, so this can
guard a build.
"""

from __future__ import annotations

import argparse
import json
import sys

from app.core.config import settings
from app.core.database import session_scope
from app.core.logging_config import configure_logging
from app.evaluation.datasets.labeled_dataset import (
    DEFAULT_SAMPLES_PER_CLASS,
    DEFAULT_SEED,
    build_dataset,
)
from app.evaluation.reports.store import write_report
from app.evaluation.watchdog import add_argument as add_timeout_argument
from app.evaluation.watchdog import start as start_watchdog
from app.ml.evaluation.hybrid_runner import load_registered_model, run_hybrid_evaluation

REPORT_PREFIX = "hybrid-eval"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m app.ml.evaluation.run_ml_eval",
        description=(
            "Measure deterministic rules, the anomaly model, and both together "
            "against the labelled evaluation dataset."
        ),
    )
    parser.add_argument("--seed", type=int, default=DEFAULT_SEED)
    parser.add_argument(
        "--samples-per-class", type=int, default=DEFAULT_SAMPLES_PER_CLASS
    )
    parser.add_argument(
        "--threshold",
        type=float,
        default=None,
        help="Anomaly threshold to evaluate at (defaults to ML_ANOMALY_THRESHOLD).",
    )
    parser.add_argument(
        "--sweep",
        action="store_true",
        help=(
            "Also report rule/ML/hybrid metrics across a range of thresholds, so the "
            "operating point is chosen from measurement rather than by feel."
        ),
    )
    parser.add_argument("--output-dir", default=None)
    parser.add_argument("--format", choices=("text", "json"), default="text")
    parser.add_argument(
        "--require-model",
        action="store_true",
        help="Exit non-zero when no model is registered (use in CI once one exists).",
    )
    add_timeout_argument(parser)
    args = parser.parse_args(argv)

    configure_logging()
    # Armed before anything that can block. The failure this guards against was
    # a deadlock in the session factory, which happens on the first database
    # touch below.
    watchdog = start_watchdog(args.max_seconds, label="hybrid evaluation")

    threshold = args.threshold if args.threshold is not None else settings.ml_anomaly_threshold

    dataset = build_dataset(seed=args.seed, samples_per_class=args.samples_per_class)
    dataset.normalize_all()

    with session_scope() as db:
        detector, model_info, reason = load_registered_model(db)

    if detector is None and args.require_model:
        print(f"error: {reason}", file=sys.stderr)
        return 2

    report = run_hybrid_evaluation(
        dataset,
        detector,
        model_info,
        threshold=threshold,
        unavailable_reason=reason,
    )

    payload = report.to_dict()

    if args.sweep and detector is not None:
        payload["thresholdSweep"] = _sweep(dataset, detector, model_info)

    write_report(payload, args.output_dir)

    if args.format == "json":
        print(json.dumps(payload, indent=2))
    else:
        print(report.to_text())
        if "thresholdSweep" in payload:
            print()
            print(_render_sweep(payload["thresholdSweep"]))

    if watchdog is not None:
        watchdog.cancel()
    return 0


def _sweep(dataset, detector, model_info) -> list[dict]:
    """Metrics across a range of thresholds.

    Published because the threshold is the single knob that moves every ML
    number, and an operating point chosen without seeing this table is chosen
    arbitrarily.
    """
    rows = []
    for step in range(50, 100, 5):
        threshold = step / 100
        report = run_hybrid_evaluation(
            dataset, detector, model_info, threshold=threshold
        )
        ml = next(c for c in report.configurations if c.name == "ml")
        hybrid = next(c for c in report.configurations if c.name == "hybrid")
        rows.append(
            {
                "threshold": threshold,
                "mlPrecision": ml.overall.precision,
                "mlRecall": ml.overall.recall,
                "mlFalsePositiveRate": ml.overall.false_positive_rate,
                "mlAlerts": ml.alerts,
                "hybridPrecision": hybrid.overall.precision,
                "hybridRecall": hybrid.overall.recall,
                "hybridF1": hybrid.overall.f1,
                "hybridFalsePositiveRate": hybrid.overall.false_positive_rate,
                "uniqueMlDetections": len(ml.unique_detections),
            }
        )
    return rows


def _render_sweep(rows: list[dict]) -> str:
    def pct(value) -> str:
        return "n/a" if value is None else f"{value * 100:.1f}%"

    lines = ["-- Threshold sweep " + "-" * 57]
    lines.append(
        f"{'thresh':>7}{'ML prec':>10}{'ML rec':>9}{'ML FPR':>9}"
        f"{'hybrid F1':>11}{'hybrid FPR':>12}{'ML-only TP':>12}"
    )
    for row in rows:
        lines.append(
            f"{row['threshold']:>7}{pct(row['mlPrecision']):>10}"
            f"{pct(row['mlRecall']):>9}{pct(row['mlFalsePositiveRate']):>9}"
            f"{pct(row['hybridF1']):>11}{pct(row['hybridFalsePositiveRate']):>12}"
            f"{row['uniqueMlDetections']:>12}"
        )
    lines.append(
        "  'ML-only TP' counts malicious samples the model caught that no rule did. "
        "It is the only column that justifies running a second detector."
    )
    return "\n".join(lines)


if __name__ == "__main__":  # pragma: no cover - CLI entrypoint
    sys.exit(main())
