"""Persist and read back evaluation results.

The archival artifact stays the JSON report on disk. This service maintains the
queryable index over it, so "compare these two experiments" is a query rather
than a directory walk.

Idempotence matters here. An experiment id is a hash of its configuration, so
re-running the same setup must update the existing experiment row and append a
new run - never create a second, indistinguishable experiment. Two runs of the
same configuration with the same seed are still two runs: they are how a
reproducibility claim is checked, and collapsing them would erase the evidence.
"""

from __future__ import annotations

import logging
from typing import Any

from sqlalchemy.orm import Session

from app.evaluation.experiments.runner import ExperimentResult
from app.models.evaluation import EvaluationDatasetRecord, Experiment, ExperimentRun
from app.repositories.evaluation_repository import (
    evaluation_datasets,
    experiment_runs,
    experiments,
)

logger = logging.getLogger("aegisx.evaluation.persistence")


def _upsert_dataset(db: Session, card: dict[str, Any]) -> EvaluationDatasetRecord:
    provenance = card.get("provenance") or {}
    record = evaluation_datasets.get_by_identity(
        db,
        name=card["name"],
        version=card["version"],
        fingerprint=card["fingerprint"],
    )
    if record is not None:
        # Identity matched on the fingerprint, so the contents are the same
        # data. Refresh the card in case the descriptive metadata improved.
        record.card = card
        return record

    record = EvaluationDatasetRecord(
        name=card["name"],
        version=card["version"],
        fingerprint=card["fingerprint"],
        source=provenance.get("source"),
        license=provenance.get("license"),
        citation=provenance.get("citation"),
        description=provenance.get("description"),
        total_samples=card["totalSamples"],
        malicious_samples=card["maliciousSamples"],
        benign_samples=card["benignSamples"],
        distinct_groups=card.get("distinctGroups"),
        card=card,
    )
    return evaluation_datasets.add(db, record)


def _model_provenance(detector: dict[str, Any]) -> dict[str, Any]:
    """Pull model identity out of a detector description, hybrid or plain."""
    model = detector.get("model") or {}
    if not model:
        for component in detector.get("components") or []:
            model = component.get("model") or {}
            if model:
                break
    return model or {}


def _ruleset_fingerprint(detector: dict[str, Any]) -> str | None:
    if detector.get("rulesetFingerprint"):
        return detector["rulesetFingerprint"]
    for component in detector.get("components") or []:
        if component.get("rulesetFingerprint"):
            return component["rulesetFingerprint"]
    return None


def store_result(
    db: Session,
    result: ExperimentResult,
    *,
    seed: int,
    report_path: str | None = None,
) -> ExperimentRun:
    """Persist one experiment result, creating or updating its experiment row."""
    payload = result.to_dict()
    detector = payload["detector"]
    dataset_card = payload["dataset"]
    split = payload["split"]
    test = payload["test"]
    confusion = test["confusion"]
    ranking = test["ranking"]
    latency = test["latency"]
    alerts = test["alertVolume"]

    dataset = _upsert_dataset(db, dataset_card)
    db.flush()

    model = _model_provenance(detector)
    experiment = experiments.get_by_experiment_id(db, result.experiment_id)
    if experiment is None:
        experiment = Experiment(
            experiment_id=result.experiment_id,
            dataset_id=dataset.id,
            detector_name=detector["name"],
            detector_kind=detector.get("kind", "unknown"),
            score_kind=detector["scoreKind"],
            split_strategy=split["strategy"],
            split_fingerprint=split["fingerprint"],
            split_seed=split["seed"],
            feature_schema_version=payload["environment"]["featureSchemaVersion"],
            ruleset_fingerprint=_ruleset_fingerprint(detector),
            model_name=model.get("name"),
            model_version=str(model["version"]) if model.get("version") else None,
            model_artifact_sha256=model.get("artifactSha256"),
            objective=payload["thresholdSelection"].get("objective"),
            detector_config=detector,
        )
        experiments.add(db, experiment)
        db.flush()
    else:
        experiment.detector_config = detector

    run = ExperimentRun(
        experiment_id=experiment.id,
        seed=seed,
        threshold=payload["threshold"],
        threshold_selection=payload["thresholdSelection"],
        true_positives=confusion["truePositives"],
        true_negatives=confusion["trueNegatives"],
        false_positives=confusion["falsePositives"],
        false_negatives=confusion["falseNegatives"],
        precision=confusion.get("precision"),
        recall=confusion.get("recall"),
        f1=confusion.get("f1"),
        specificity=confusion.get("specificity"),
        accuracy=confusion.get("accuracy"),
        false_positive_rate=confusion.get("falsePositiveRate"),
        false_negative_rate=confusion.get("falseNegativeRate"),
        mcc=test.get("mcc"),
        balanced_accuracy=test.get("balancedAccuracy"),
        roc_auc=ranking.get("rocAuc"),
        pr_auc=ranking.get("prAuc"),
        alerts=alerts.get("alerts"),
        alerts_per_thousand=alerts.get("alertsPerThousandEvents"),
        latency_mean_ms=latency.get("meanMs"),
        latency_p95_ms=latency.get("p95Ms"),
        confusion_normalized=test["confusionNormalized"],
        per_class=test["perClass"],
        threshold_sweep=payload["thresholdSweep"],
        validation_metrics=payload.get("validation"),
        environment=payload["environment"],
        notes=payload.get("notes", []),
        report_path=report_path,
    )
    experiment_runs.add(db, run)
    db.flush()
    logger.info(
        "Stored %s run for %s (seed %s)", detector["name"], result.experiment_id, seed
    )
    return run


def store_report(
    db: Session,
    results: list[tuple[ExperimentResult, int]],
    *,
    report_path: str | None = None,
    leakage: dict[str, Any] | None = None,
) -> list[ExperimentRun]:
    """Persist a whole suite, attaching the shared leakage audit to each run."""
    stored: list[ExperimentRun] = []
    for result, seed in results:
        run = store_result(db, result, seed=seed, report_path=report_path)
        if leakage is not None:
            run.leakage_audit = leakage
        stored.append(run)
    db.flush()
    return stored


# ------------------------------------------------------------- serialization


def dataset_to_dict(record: EvaluationDatasetRecord) -> dict[str, Any]:
    return {
        "id": record.id,
        "name": record.name,
        "version": record.version,
        "fingerprint": record.fingerprint,
        "source": record.source,
        "license": record.license,
        "citation": record.citation,
        "description": record.description,
        "totalSamples": record.total_samples,
        "maliciousSamples": record.malicious_samples,
        "benignSamples": record.benign_samples,
        "distinctGroups": record.distinct_groups,
        "card": record.card,
        "createdAt": record.created_at,
    }


def run_to_dict(run: ExperimentRun, *, include_documents: bool = False) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "id": run.id,
        "seed": run.seed,
        "executedAt": run.executed_at,
        "threshold": run.threshold,
        "thresholdSelection": run.threshold_selection,
        "confusion": {
            "truePositives": run.true_positives,
            "trueNegatives": run.true_negatives,
            "falsePositives": run.false_positives,
            "falseNegatives": run.false_negatives,
        },
        "metrics": {
            "precision": run.precision,
            "recall": run.recall,
            "f1": run.f1,
            "specificity": run.specificity,
            "accuracy": run.accuracy,
            "falsePositiveRate": run.false_positive_rate,
            "falseNegativeRate": run.false_negative_rate,
            "mcc": run.mcc,
            "balancedAccuracy": run.balanced_accuracy,
            "rocAuc": run.roc_auc,
            "prAuc": run.pr_auc,
        },
        "alertVolume": {
            "alerts": run.alerts,
            "alertsPerThousandEvents": run.alerts_per_thousand,
        },
        "latency": {"meanMs": run.latency_mean_ms, "p95Ms": run.latency_p95_ms},
    }
    if include_documents:
        payload.update(
            {
                "confusionNormalized": run.confusion_normalized,
                "perClass": run.per_class,
                "thresholdSweep": run.threshold_sweep,
                "validation": run.validation_metrics,
                "leakageAudit": run.leakage_audit,
                "environment": run.environment,
                "notes": run.notes,
                "reportPath": run.report_path,
            }
        )
    return payload


def experiment_to_dict(
    experiment: Experiment, *, include_runs: bool = False, include_documents: bool = False
) -> dict[str, Any]:
    runs = list(experiment.runs)
    latest = runs[0] if runs else None
    payload: dict[str, Any] = {
        "experimentId": experiment.experiment_id,
        "detector": {
            "name": experiment.detector_name,
            "kind": experiment.detector_kind,
            # Carried on every response so a consumer cannot mistake an anomaly
            # ranking for a probability.
            "scoreKind": experiment.score_kind,
        },
        "dataset": {
            "name": experiment.dataset.name,
            "version": experiment.dataset.version,
            "fingerprint": experiment.dataset.fingerprint,
        },
        "split": {
            "strategy": experiment.split_strategy,
            "fingerprint": experiment.split_fingerprint,
            "seed": experiment.split_seed,
        },
        "provenance": {
            "featureSchemaVersion": experiment.feature_schema_version,
            "rulesetFingerprint": experiment.ruleset_fingerprint,
            "modelName": experiment.model_name,
            "modelVersion": experiment.model_version,
            "modelArtifactSha256": experiment.model_artifact_sha256,
        },
        "objective": experiment.objective,
        "runCount": len(runs),
        "createdAt": experiment.created_at,
        "latestRun": run_to_dict(latest, include_documents=include_documents)
        if latest
        else None,
    }
    if include_runs:
        payload["runs"] = [
            run_to_dict(run, include_documents=include_documents) for run in runs
        ]
    if include_documents:
        payload["detectorConfig"] = experiment.detector_config
    return payload
