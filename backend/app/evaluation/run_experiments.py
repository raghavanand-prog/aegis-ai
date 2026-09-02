"""V4 experiment runner.

    python -m app.evaluation.run_experiments --dataset unsw-nb15 --split stratified_group

Runs the baseline suite (rules / anomaly / supervised / hybrid) and the
ablation matrix over one dataset and one split, then writes a schema-versioned
JSON report and a readable summary.

Nothing here selects a threshold from test results, and nothing here reports a
number that was not measured. Where a configuration cannot be evaluated, the
report says which and why.
"""

from __future__ import annotations

import argparse
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from app.core.config import get_settings
from app.evaluation.datasets.base import EvaluationDataset
from app.evaluation.experiments.runner import extract_features, leakage_audit
from app.evaluation.experiments.suite import (
    SuiteResult,
    ablation_table,
    build_ablation_specs,
    build_baseline_specs,
    run_suite,
)
from app.evaluation.reports.store import write_report
from app.evaluation.splits import STRATIFIED_GROUP, TEMPORAL, build_split
from app.evaluation.watchdog import add_argument as add_timeout_argument
from app.evaluation.watchdog import start as start_watchdog

logger = logging.getLogger("aegisx.evaluation.experiments")

REPORT_SCHEMA_VERSION = "1.0"
REPORT_PREFIX = "v4-experiments"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m app.evaluation.run_experiments",
        description="Run the V4 baseline and ablation suites over a labelled dataset.",
    )
    parser.add_argument(
        "--dataset",
        default="unsw-nb15",
        choices=["unsw-nb15", "aegisx-synthetic"],
        help="which corpus to evaluate on (default: unsw-nb15)",
    )
    parser.add_argument(
        "--split",
        default=STRATIFIED_GROUP,
        choices=[STRATIFIED_GROUP, TEMPORAL],
        help="split strategy (default: stratified_group)",
    )
    parser.add_argument(
        "--max-samples",
        type=int,
        default=200_000,
        help="approximate ceiling on samples loaded (default: 200000; 0 means all)",
    )
    parser.add_argument("--seed", type=int, default=1337, help="split and model seed")
    parser.add_argument(
        "--seeds",
        type=int,
        default=1,
        help="repeat the baseline suite with this many consecutive seeds for variance",
    )
    parser.add_argument(
        "--objective",
        default="f1",
        choices=["f1", "precision", "recall"],
        help="what the validation threshold search maximises (default: f1)",
    )
    parser.add_argument(
        "--no-ablation", action="store_true", help="skip the ablation matrix"
    )
    parser.add_argument(
        "--include-registered",
        action="store_true",
        help="also evaluate the registered production model artifact (needs a database)",
    )
    parser.add_argument("--output-dir", default=None, help="where to write the report")
    add_timeout_argument(parser)
    return parser


def load_dataset(name: str, *, max_samples: int | None) -> EvaluationDataset:
    if name == "unsw-nb15":
        from app.evaluation.datasets.unsw_nb15 import load

        return load(max_samples=max_samples)

    from app.evaluation.datasets.adapters import synthetic_dataset

    return synthetic_dataset()


def load_registered() -> tuple[Any, dict[str, Any]] | None:
    """Load the deployed artifact, or return ``None`` with the reason logged."""
    from app.core.database import get_session_factory
    from app.ml.evaluation.hybrid_runner import load_registered_model

    session = get_session_factory()()
    try:
        detector, info, reason = load_registered_model(session)
    finally:
        session.close()
    if detector is None:
        logger.warning("Registered model unavailable: %s", reason)
        return None
    return detector, info or {}


def _table(rows: list[dict[str, Any]]) -> str:
    """Fixed-width comparison table. `-` means the metric is undefined here."""
    columns = [
        ("configuration", 30),
        ("threshold", 10),
        ("TP", 8),
        ("TN", 9),
        ("FP", 8),
        ("FN", 7),
        ("precision", 10),
        ("recall", 8),
        ("f1", 8),
        ("FPR", 8),
        ("MCC", 8),
    ]
    keys = {
        "TP": "truePositives",
        "TN": "trueNegatives",
        "FP": "falsePositives",
        "FN": "falseNegatives",
        "FPR": "falsePositiveRate",
        "MCC": "mcc",
    }
    lines = ["  " + "".join(name.ljust(width) for name, width in columns)]
    lines.append("  " + "-" * sum(width for _, width in columns))
    for row in rows:
        cells = []
        for name, width in columns:
            value = row.get(keys.get(name, name))
            if value is None:
                text = "-"
            elif isinstance(value, float) and name not in ("threshold",):
                text = f"{value * 100:.1f}%" if name != "MCC" else f"{value:.3f}"
            else:
                text = str(value)
            cells.append(text.ljust(width))
        lines.append("  " + "".join(cells))
    return "\n".join(lines)


def summarise(payload: dict[str, Any]) -> str:
    dataset = payload["dataset"]
    split = payload["split"]
    lines = [
        "",
        "=" * 78,
        "  AEGISX V4 EXPERIMENT REPORT",
        "=" * 78,
        "",
        f"  Dataset        {dataset['name']} v{dataset['version']} "
        f"[{dataset['fingerprint']}]",
        f"  Samples        {dataset['totalSamples']} "
        f"({dataset['maliciousSamples']} malicious, {dataset['benignSamples']} benign; "
        f"{(dataset['maliciousRate'] or 0) * 100:.2f}% positive)",
        f"  Groups         {dataset['distinctGroups']} distinct duplicate groups",
        f"  Split          {split['strategy']} [{split['fingerprint']}] seed={split['seed']}",
        "  "
        + "  ".join(
            f"{name}={info['samples']}({info['malicious']}m)"
            for name, info in split["splits"].items()
        ),
        "",
    ]

    for warning in split.get("warnings", []):
        lines.append(f"  ! {warning}")
    if split.get("warnings"):
        lines.append("")

    lines.append("  BASELINES (test split, threshold frozen on validation)")
    lines.append("")
    lines.append(_table(payload["baselineTable"]))
    lines.append("")

    for entry in payload["baselines"]["skipped"]:
        lines.append(f"  SKIPPED {entry['detector']}: {entry['reason']}")
    if payload["baselines"]["skipped"]:
        lines.append("")

    if payload.get("ablationTable"):
        lines.append("  ABLATION (component contribution)")
        lines.append("")
        lines.append(_table(payload["ablationTable"]))
        lines.append("")

    if payload.get("seedVariance"):
        lines.append("  SEED VARIANCE (test F1 across repeated seeds)")
        lines.append("")
        for name, interval in sorted(payload["seedVariance"].items()):
            if interval.get("lower") is None:
                lines.append(f"    {name:32} {interval.get('unavailableReason', 'n/a')}")
            else:
                lines.append(
                    f"    {name:32} mean {interval['mean']:.4f}  "
                    f"95% CI [{interval['lower']:.4f}, {interval['upper']:.4f}]  "
                    f"sd {interval['stdDev']:.4f}  n={interval['samples']}"
                )
        lines.append("")

    audit = payload.get("leakageAudit")
    if audit:
        lines.append("  LEAKAGE AUDIT (test samples sharing a training feature vector)")
        lines.append("")
        for name, entry in audit["splits"].items():
            share = entry["share"]
            lines.append(
                f"    {name:12} {entry['sharingATrainingFeatureVector']}/{entry['samples']}"
                f"  ({share * 100:.2f}%)" if share is not None else f"    {name:12} n/a"
            )
        if audit["concerning"]:
            lines.append("")
            lines.append(
                "    ! Above 5%: a meaningful share of the test split could be answered "
                "from memory. Treat the metrics above as an upper bound."
            )
        lines.append("")

    lines.append("  NOTES")
    for note in payload["notes"]:
        lines.append(f"    - {note}")
    lines.append("")
    lines.append("=" * 78)
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:  # noqa: C901 - one flat CLI
    parser = build_parser()
    args = parser.parse_args(argv)
    watchdog = start_watchdog(args.max_seconds, label="v4 experiments")

    try:
        settings = get_settings()
        max_samples = None if args.max_samples == 0 else args.max_samples

        try:
            dataset = load_dataset(args.dataset, max_samples=max_samples)
        except RuntimeError as exc:
            print(f"\nDataset unavailable.\n\n  {exc}\n", file=sys.stderr)
            return 2

        if not dataset.samples:
            print("\nThe dataset loaded zero samples; nothing to evaluate.\n", file=sys.stderr)
            return 2

        print(f"\nExtracting features for {len(dataset)} samples...")
        features = extract_features(dataset)

        registered = None
        if args.include_registered:
            registered = load_registered()

        seed_results: dict[str, list[float]] = {}
        baselines: SuiteResult | None = None
        plan = None

        for offset in range(max(1, args.seeds)):
            seed = args.seed + offset
            plan = build_split(dataset, strategy=args.split, seed=seed)
            specs = build_baseline_specs(
                anomaly_threshold=settings.ml_anomaly_threshold,
                contamination=settings.ml_contamination,
                seed=seed,
                registered=registered,
            )
            suite = run_suite(
                dataset=dataset,
                plan=plan,
                features=features,
                specs=specs,
                objective=args.objective,
                seed=seed,
            )
            if baselines is None:
                baselines = suite
            for result in suite.results:
                f1 = result.test.confusion.f1
                if f1 is not None:
                    seed_results.setdefault(result.detector["name"], []).append(f1)

        assert baselines is not None and plan is not None

        ablation: SuiteResult | None = None
        if not args.no_ablation:
            ablation = run_suite(
                dataset=dataset,
                plan=plan,
                features=features,
                specs=build_ablation_specs(
                    anomaly_threshold=settings.ml_anomaly_threshold,
                    contamination=settings.ml_contamination,
                    seed=args.seed,
                ),
                objective=args.objective,
                seed=args.seed,
            )

        variance: dict[str, Any] = {}
        if args.seeds > 1:
            from app.evaluation.metrics.ranking import bootstrap_interval

            variance = {
                name: bootstrap_interval(values, seed=args.seed)
                for name, values in seed_results.items()
            }

        notes = [
            "Thresholds were selected on the validation split and frozen before the "
            "test split was evaluated. The test split was read exactly once per "
            "configuration.",
            "Features come from the production extractor, replayed in chronological "
            "order, so behavioural context is causal and matches ingestion.",
            "Duplicate groups never cross a split boundary.",
            "An anomaly score is a ranking, not a probability; ranking metrics are "
            "omitted for detectors whose output has no ordering.",
        ]
        notes.extend(dataset.provenance.notes)
        notes.extend(dataset.label_schema.notes)

        payload: dict[str, Any] = {
            "schemaVersion": REPORT_SCHEMA_VERSION,
            "generatedAt": datetime.now(timezone.utc).isoformat(),
            "command": " ".join(sys.argv),
            "dataset": dataset.describe(),
            "split": plan.to_dict(),
            "objective": args.objective,
            "seed": args.seed,
            "seedsRun": args.seeds,
            "baselines": baselines.to_dict(),
            "baselineTable": ablation_table(baselines),
            "ablation": ablation.to_dict() if ablation else None,
            "ablationTable": ablation_table(ablation) if ablation else None,
            "seedVariance": variance,
            "leakageAudit": leakage_audit(plan, features),
            "notes": notes,
        }

        text = summarise(payload)
        print(text)

        directory = Path(args.output_dir) if args.output_dir else None
        detailed, latest = write_report(
            payload,
            directory or settings.evaluation_reports_dir or None,
            prefix=f"{REPORT_PREFIX}-{args.dataset}-{args.split}",
        )
        print(f"  Report written to {detailed}")
        print(f"  Latest pointer   {latest}\n")
        return 0
    finally:
        if watchdog is not None:
            watchdog.cancel()


if __name__ == "__main__":  # pragma: no cover - CLI entry point
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    raise SystemExit(main())
