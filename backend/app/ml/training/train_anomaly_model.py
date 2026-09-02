"""Train and register the anomaly detection model.

    python -m app.ml.training.train_anomaly_model

Training is an explicit, operator-run step. It deliberately does **not** happen
on application startup: a backend that silently retrains on every restart has
no reproducible detection behaviour, and "the model changed when the pod
restarted" is not a sentence anyone wants to say during an investigation.

The flow, in order:

    corpus -> validation -> features -> fit -> held-out scoring -> artifact
    -> sha256 -> registry row -> (optionally) activate

Nothing is registered unless the artifact was written and re-read successfully,
so a half-trained model cannot become the active one.
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from datetime import datetime, timezone
from typing import Any

from app.core.config import settings
from app.core.database import session_scope
from app.core.init_db import bootstrap
from app.core.logging_config import configure_logging
from app.evaluation.watchdog import add_argument as add_timeout_argument
from app.evaluation.watchdog import start as start_watchdog
from app.ml.models.isolation_forest import MODEL_NAME, MODEL_TYPE, IsolationForestDetector
from app.ml.registry import registry
from app.ml.training.corpus import (
    DEFAULT_SAMPLES,
    DEFAULT_SEED,
    DEFAULT_SPAN_DAYS,
    TRAINING_DATASET_VERSION,
    build_corpus,
)
from app.models.enums import AuditAction
from app.services import audit_service

logger = logging.getLogger("aegisx.ml.training")

#: Fraction of the corpus held back from fitting, used only to describe the
#: score distribution the model produces on data it has never seen.
HOLDOUT_FRACTION = 0.2


def train(
    *,
    seed: int = DEFAULT_SEED,
    samples: int = DEFAULT_SAMPLES,
    span_days: int = DEFAULT_SPAN_DAYS,
    contamination: float | None = None,
    random_state: int | None = None,
    n_estimators: int = 200,
    activate: bool = True,
    created_by: str = "cli",
    notes: str | None = None,
) -> dict[str, Any]:
    """Run one training pass end to end and return a report."""
    contamination = contamination if contamination is not None else settings.ml_contamination
    random_state = random_state if random_state is not None else settings.ml_random_state

    logger.info("Building training corpus (seed=%s, samples=%s)", seed, samples)
    corpus = build_corpus(seed=seed, samples=samples, span_days=span_days)

    if corpus.size < 200:
        raise SystemExit(
            f"Corpus produced only {corpus.size} usable samples; refusing to train."
        )

    split = int(corpus.size * (1 - HOLDOUT_FRACTION))
    fit_vectors = corpus.vectors[:split]
    holdout = corpus.vectors[split:]

    detector = IsolationForestDetector(
        feature_names=corpus.feature_names,
        contamination=contamination,
        random_state=random_state,
        n_estimators=n_estimators,
    )
    logger.info("Fitting on %d samples (%d held out)", len(fit_vectors), len(holdout))
    report = detector.fit(fit_vectors)

    # Describe the score distribution on unseen data. This is characterisation,
    # not accuracy: the corpus is unlabelled, so there is no precision or recall
    # to report here and none is invented. Labelled measurement lives in
    # `app.ml.evaluation` and runs against the labelled evaluation dataset.
    holdout_scores = [detector.anomaly_score(vector) for vector in holdout]
    holdout_scores.sort()
    threshold = settings.ml_anomaly_threshold
    flagged = sum(1 for score in holdout_scores if score >= threshold)

    # Flagged rate at candidate thresholds, measured on data the fit never saw.
    # This is what an operating point should be chosen from: "how much ordinary
    # traffic would this threshold flag" is the question, and guessing at it is
    # how an anomaly detector becomes an alert cannon.
    calibration = [
        {
            "threshold": round(candidate / 100, 2),
            "flaggedRate": round(
                sum(1 for score in holdout_scores if score >= candidate / 100)
                / len(holdout_scores),
                4,
            )
            if holdout_scores
            else None,
        }
        for candidate in range(55, 81, 5)
    ]

    metrics: dict[str, Any] = {
        **report.to_dict(),
        "holdoutSamples": len(holdout),
        "calibration": calibration,
        "recommendedThreshold": _recommended_threshold(holdout_scores),
        "holdoutFlaggedRate": round(flagged / len(holdout), 4) if holdout else None,
        "holdoutScoreP50": _percentile(holdout_scores, 50),
        "holdoutScoreP95": _percentile(holdout_scores, 95),
        "holdoutScoreMax": round(holdout_scores[-1], 4) if holdout_scores else None,
        "thresholdAtTraining": threshold,
        "measured": (
            "Unsupervised fit on unlabelled synthetic telemetry. These are score "
            "distribution statistics, not detection accuracy - run "
            "`python -m app.ml.evaluation.run_ml_eval` for labelled measurement."
        ),
    }

    with session_scope() as db:
        version = registry.next_version(db, MODEL_NAME)
        path = registry.artifact_path(MODEL_NAME, version)

        digest = detector.save(path)
        # Read it straight back: an artifact that cannot be loaded must never
        # reach the registry, let alone become active.
        IsolationForestDetector.load(path, expected_sha256=digest)

        model = registry.register(
            db,
            name=MODEL_NAME,
            version=version,
            model_type=MODEL_TYPE,
            feature_schema_version=corpus.schema_version,
            dataset_version=TRAINING_DATASET_VERSION,
            dataset_fingerprint=corpus.fingerprint(),
            training_samples=len(fit_vectors),
            parameters={
                "contamination": contamination,
                "randomState": random_state,
                "nEstimators": n_estimators,
                "seed": seed,
                "samples": samples,
                "spanDays": span_days,
                "holdoutFraction": HOLDOUT_FRACTION,
            },
            metrics=metrics,
            feature_names=list(corpus.feature_names),
            artifact_path_str=str(path),
            artifact_sha256=digest,
            created_by=created_by,
            notes=notes,
            activate=activate,
        )

        audit_service.record(
            db,
            action=AuditAction.ML_MODEL_TRAINED,
            target_type="ml_model",
            target_id=model.identity,
            details={
                "samples": len(fit_vectors),
                "datasetFingerprint": corpus.fingerprint(),
                "activated": activate,
                "createdBy": created_by,
            },
        )
        result = {
            "generatedAt": datetime.now(timezone.utc).isoformat(),
            "model": registry.to_dict(model),
            "dataset": corpus.to_dict(),
        }

    return result


def _recommended_threshold(sorted_scores: list[float]) -> float | None:
    """The score above which ~1% of held-out ordinary traffic sits.

    A deliberately conservative default: an anomaly badge an analyst sees on one
    event in a hundred carries information, and one they see on one in seven
    does not. Reported as a recommendation - the running threshold is
    ML_ANOMALY_THRESHOLD, and changing it never requires retraining.
    """
    if not sorted_scores:
        return None
    index = min(int(len(sorted_scores) * 0.99), len(sorted_scores) - 1)
    return round(sorted_scores[index], 3)


def _percentile(sorted_values: list[float], percentile: int) -> float | None:
    if not sorted_values:
        return None
    index = min(int(len(sorted_values) * percentile / 100), len(sorted_values) - 1)
    return round(sorted_values[index], 4)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m app.ml.training.train_anomaly_model",
        description="Train, persist and register the AEGISX anomaly detection model.",
    )
    parser.add_argument("--seed", type=int, default=DEFAULT_SEED)
    parser.add_argument("--samples", type=int, default=DEFAULT_SAMPLES)
    parser.add_argument("--span-days", type=int, default=DEFAULT_SPAN_DAYS)
    parser.add_argument("--contamination", type=float, default=None)
    parser.add_argument("--random-state", type=int, default=None)
    parser.add_argument("--n-estimators", type=int, default=200)
    parser.add_argument(
        "--no-activate",
        action="store_true",
        help="Register the model without making it the serving version.",
    )
    parser.add_argument("--notes", default=None)
    parser.add_argument("--format", choices=("text", "json"), default="text")
    add_timeout_argument(parser)
    args = parser.parse_args(argv)

    configure_logging()
    watchdog = start_watchdog(args.max_seconds, label="model training")
    bootstrap()

    result = train(
        seed=args.seed,
        samples=args.samples,
        span_days=args.span_days,
        contamination=args.contamination,
        random_state=args.random_state,
        n_estimators=args.n_estimators,
        activate=not args.no_activate,
        notes=args.notes,
    )

    if watchdog is not None:
        watchdog.cancel()

    if args.format == "json":
        print(json.dumps(result, indent=2))
        return 0

    model = result["model"]
    dataset = result["dataset"]
    metrics = model["metrics"]
    print()
    print(f"  Model            {model['identity']}  ({model['status']})")
    print(f"  Type             {model['modelType']}")
    print(f"  Feature schema   v{model['featureSchemaVersion']} ({model['featureCount']} features)")
    print(f"  Dataset          {dataset['name']} v{dataset['version']} "
          f"[{dataset['fingerprint']}] - synthetic, unlabelled")
    print(f"  Trained on       {model['trainingSamples']} samples "
          f"over {dataset['spanDays']} simulated days")
    print(f"  Artifact         {model['artifactName']}  sha256:{model['artifactSha256'][:16]}")
    print()
    print("  Score distribution on held-out data (NOT accuracy):")
    print(f"    held out           {metrics['holdoutSamples']}")
    print(f"    p50 anomaly score  {metrics['holdoutScoreP50']}")
    print(f"    p95 anomaly score  {metrics['holdoutScoreP95']}")
    print(f"    flagged at {metrics['thresholdAtTraining']}   "
          f"{metrics['holdoutFlaggedRate']}")
    print(f"    recommended threshold  {metrics['recommendedThreshold']} "
          f"(flags ~1% of ordinary traffic)")
    print()
    print("  Flagged rate by threshold (held-out, unseen during fitting):")
    for row in metrics["calibration"]:
        rate = row["flaggedRate"]
        bar = "#" * int((rate or 0) * 60)
        print(f"    {row['threshold']:.2f}  {(rate or 0) * 100:6.2f}%  {bar}")
    print()
    print("  Detection accuracy is measured separately, against the labelled dataset:")
    print("    python -m app.ml.evaluation.run_ml_eval")
    print()
    return 0


if __name__ == "__main__":  # pragma: no cover - CLI entrypoint
    sys.exit(main())
