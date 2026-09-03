"""CLI: train one candidate model.

Deliberately a CLI and not an endpoint. Training is minutes of CPU, and V4
established that putting that behind HTTP hands any authenticated user a
resource-exhaustion primitive. It is also a decision with a named owner, which
``--created-by`` records.

    python -m app.adaptation.candidates.train_candidate --seed 4242

The result is a model in ``candidate`` status: registered, reproducible, and
unable to serve until it has been evaluated, passed its gates and been approved.
"""

from __future__ import annotations

import argparse
import json
import sys

from app.adaptation.candidates import training
from app.core.database import session_scope
from app.evaluation.watchdog import add_argument as add_timeout_argument
from app.evaluation.watchdog import start as start_watchdog


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="train_candidate",
        description="Train a candidate model. Does not activate it.",
    )
    parser.add_argument("--seed", type=int, default=4242)
    parser.add_argument("--samples", type=int, default=6000)
    parser.add_argument("--span-days", type=int, default=14)
    parser.add_argument("--contamination", type=float, default=None)
    parser.add_argument("--n-estimators", type=int, default=200)
    parser.add_argument(
        "--feedback-dataset-id",
        type=int,
        default=None,
        help="feedback dataset this candidate was built from, where one was",
    )
    parser.add_argument(
        "--created-by",
        default="cli",
        help="who is responsible for this candidate; recorded in the registry",
    )
    parser.add_argument("--notes", default=None)
    parser.add_argument("--format", choices=("text", "json"), default="text")
    add_timeout_argument(parser)
    args = parser.parse_args(argv)

    watchdog = start_watchdog(args.max_seconds, label="candidate training")
    try:
        with session_scope() as db:
            model = training.train_candidate(
                db,
                seed=args.seed,
                samples=args.samples,
                span_days=args.span_days,
                contamination=args.contamination,
                n_estimators=args.n_estimators,
                created_by=args.created_by,
                notes=args.notes,
                feedback_dataset_id=args.feedback_dataset_id,
            )
            report = training.describe(model)
    finally:
        if watchdog is not None:
            watchdog.cancel()

    if args.format == "json":
        print(json.dumps(report, indent=2))
    else:
        print()
        print(f"  Candidate       {report['identity']}  ({report['status']})")
        print(f"  Feature schema  v{report['featureSchemaVersion']}")
        print(f"  Corpus          {report['datasetFingerprint']}")
        print(f"  Artifact        sha256:{report['artifactSha256'][:16]}")
        print(f"  Trained by      {report['createdBy']}")
        print()
        print("  This model is NOT serving and cannot be activated until it has")
        print("  been evaluated, passed its safety gates and been approved.")
        print()
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
