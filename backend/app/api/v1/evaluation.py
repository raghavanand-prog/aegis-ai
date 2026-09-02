"""Research evaluation: measured results, read only.

Separate from the production detection endpoints on purpose. Everything here
describes how well AEGISX performed on a labelled corpus under a recorded
configuration; nothing here participates in detecting anything.

**There is no endpoint that runs an experiment.** Running one means minutes of
CPU over an entire corpus, and exposing that over HTTP would hand any
authenticated user a resource-exhaustion primitive for free. Experiments are
started from the CLI by an operator, and their results are ingested here. If
that ever changes, it needs RBAC, a queue, a timeout, a result cap and audit
logging - not just a route.

Every payload carries the provenance of the number it reports: dataset name,
version and fingerprint, split strategy and fingerprint, feature schema
version, ruleset fingerprint, model version and artifact digest, and the score
kind. A percentage without those is not a result, and this API never emits one.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.api.deps import require
from app.core.database import get_db
from app.core.rbac import Permission
from app.models.user import User
from app.repositories.evaluation_repository import (
    evaluation_datasets,
    experiment_runs,
    experiments,
)
from app.services import evaluation_service

router = APIRouter(prefix="/evaluation", tags=["evaluation"])

NO_RESULTS_DETAIL = (
    "No evaluation experiments have been recorded yet. Run "
    "`python -m app.evaluation.run_experiments --dataset unsw-nb15` in the backend "
    "and ingest the report with `--persist` to populate this."
)


@router.get(
    "/status",
    summary="Whether any evaluation results exist, and what they cover",
    description=(
        "Always answers, including when nothing has been evaluated - in which case it "
        "says why the research views are empty rather than rendering a blank panel."
    ),
)
def evaluation_status(
    db: Session = Depends(get_db),
    _user: User = Depends(require(Permission.EVALUATION_READ)),
) -> dict[str, Any]:
    datasets = evaluation_datasets.list_all(db, limit=100)
    recorded, total = experiments.list_paginated(db, limit=1)

    from app.evaluation.datasets.unsw_nb15 import loader as unsw

    return {
        "available": total > 0,
        "reason": None if total > 0 else NO_RESULTS_DETAIL,
        "experimentCount": total,
        "datasetCount": len(datasets),
        "datasets": [
            {
                "name": record.name,
                "version": record.version,
                "fingerprint": record.fingerprint,
                "totalSamples": record.total_samples,
            }
            for record in datasets
        ],
        "detectors": experiments.detector_names(db),
        "corpora": {
            "unsw-nb15": {
                "onDisk": unsw.available(),
                "reason": unsw.unavailable_reason(),
                "fetchCommand": unsw.FETCH_COMMAND,
            }
        },
    }


@router.get(
    "/datasets",
    summary="Dataset versions results were measured on",
    description=(
        "One entry per (name, version, fingerprint). Two entries sharing a name and "
        "version but not a fingerprint are different data, and results across them "
        "must not be pooled."
    ),
)
def list_datasets(
    limit: int = Query(50, ge=1, le=200),
    db: Session = Depends(get_db),
    _user: User = Depends(require(Permission.EVALUATION_READ)),
) -> dict[str, Any]:
    records = evaluation_datasets.list_all(db, limit=limit)
    return {
        "items": [evaluation_service.dataset_to_dict(record) for record in records],
        "total": len(records),
    }


@router.get(
    "/datasets/{dataset_id}",
    summary="Full dataset card",
    description=(
        "Provenance, licence, citation, label schema with its complete original -> "
        "normalized mapping, class balance, sampling strategy and documented "
        "limitations."
    ),
)
def get_dataset(
    dataset_id: int,
    db: Session = Depends(get_db),
    _user: User = Depends(require(Permission.EVALUATION_READ)),
) -> dict[str, Any]:
    record = evaluation_datasets.get(db, dataset_id)
    if record is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Dataset not found.")
    return evaluation_service.dataset_to_dict(record)


@router.get(
    "/experiments",
    summary="Recorded experiments",
    description=(
        "Each row is one configuration - dataset, split, detector, threshold policy - "
        "with its most recent run. `scoreKind` says what the detector's number means; "
        "an anomaly ranking and a probability are not interchangeable."
    ),
)
def list_experiments(
    dataset: str | None = Query(None, description="filter by dataset name"),
    detector: str | None = Query(None, description="filter by detector name"),
    split: str | None = Query(None, description="filter by split strategy"),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
    _user: User = Depends(require(Permission.EVALUATION_READ)),
) -> dict[str, Any]:
    items, total = experiments.list_paginated(
        db,
        dataset_name=dataset,
        detector_name=detector,
        split_strategy=split,
        limit=limit,
        offset=offset,
    )
    return {
        "items": [evaluation_service.experiment_to_dict(item) for item in items],
        "total": total,
        "limit": limit,
        "offset": offset,
    }


@router.get(
    "/experiments/{experiment_id}",
    summary="One experiment in full",
    description=(
        "Every run, the threshold sweep, the normalized confusion matrix, per-class "
        "detection rates, the leakage audit and the environment the numbers were "
        "produced in."
    ),
)
def get_experiment(
    experiment_id: str,
    db: Session = Depends(get_db),
    _user: User = Depends(require(Permission.EVALUATION_READ)),
) -> dict[str, Any]:
    experiment = experiments.get_by_experiment_id(db, experiment_id)
    if experiment is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Experiment not found.")
    return evaluation_service.experiment_to_dict(
        experiment, include_runs=True, include_documents=True
    )


@router.get(
    "/experiments/{experiment_id}/threshold-sweep",
    summary="Threshold sweep for one experiment",
    description=(
        "Precision, recall, F1, FPR, FNR and alert volume at each candidate threshold, "
        "measured on the **validation** split. The frozen threshold was chosen from "
        "this curve before the test split was evaluated."
    ),
)
def get_threshold_sweep(
    experiment_id: str,
    db: Session = Depends(get_db),
    _user: User = Depends(require(Permission.EVALUATION_READ)),
) -> dict[str, Any]:
    experiment = experiments.get_by_experiment_id(db, experiment_id)
    if experiment is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Experiment not found.")
    run = experiment_runs.latest_for(db, experiment.id)
    if run is None:
        raise HTTPException(
            status.HTTP_404_NOT_FOUND, detail="This experiment has no recorded runs."
        )
    return {
        "experimentId": experiment.experiment_id,
        "detector": experiment.detector_name,
        "scoreKind": experiment.score_kind,
        "measuredOn": "validation split",
        "chosenThreshold": run.threshold,
        "selection": run.threshold_selection,
        "points": run.threshold_sweep,
        "note": (
            "Empty for a detector with no threshold to choose - deterministic rules "
            "either match or they do not."
        )
        if not run.threshold_sweep
        else None,
    }


@router.get(
    "/experiments/{experiment_id}/confusion-matrix",
    summary="Confusion matrix, raw counts and row-normalized",
    description=(
        "Row normalization answers 'of the actual attacks, what fraction was caught'. "
        "Counts are machine-readable; nothing here depends on reading a chart."
    ),
)
def get_confusion_matrix(
    experiment_id: str,
    db: Session = Depends(get_db),
    _user: User = Depends(require(Permission.EVALUATION_READ)),
) -> dict[str, Any]:
    experiment = experiments.get_by_experiment_id(db, experiment_id)
    if experiment is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Experiment not found.")
    run = experiment_runs.latest_for(db, experiment.id)
    if run is None:
        raise HTTPException(
            status.HTTP_404_NOT_FOUND, detail="This experiment has no recorded runs."
        )
    return {
        "experimentId": experiment.experiment_id,
        "detector": experiment.detector_name,
        "threshold": run.threshold,
        "counts": {
            "truePositives": run.true_positives,
            "trueNegatives": run.true_negatives,
            "falsePositives": run.false_positives,
            "falseNegatives": run.false_negatives,
        },
        "normalized": run.confusion_normalized,
        "perClass": run.per_class,
    }


@router.get(
    "/compare",
    summary="Compare experiments measured on the same data",
    description=(
        "Refuses to compare experiments whose dataset fingerprints differ. Two results "
        "from different data are not a comparison, and returning one anyway is how a "
        "misleading headline gets made."
    ),
)
def compare_experiments(
    ids: list[str] = Query(..., description="experiment ids to compare"),
    db: Session = Depends(get_db),
    _user: User = Depends(require(Permission.EVALUATION_READ)),
) -> dict[str, Any]:
    if len(ids) < 2:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST, detail="Provide at least two experiment ids."
        )

    found = []
    missing = []
    for experiment_id in ids:
        experiment = experiments.get_by_experiment_id(db, experiment_id)
        if experiment is None:
            missing.append(experiment_id)
        else:
            found.append(experiment)

    if missing:
        raise HTTPException(
            status.HTTP_404_NOT_FOUND, detail=f"Unknown experiment ids: {sorted(missing)}"
        )

    fingerprints = {experiment.dataset.fingerprint for experiment in found}
    splits = {experiment.split_fingerprint for experiment in found}
    comparable = len(fingerprints) == 1

    warnings: list[str] = []
    if not comparable:
        warnings.append(
            "These experiments were measured on different dataset fingerprints "
            f"({sorted(fingerprints)}). Their metrics are not comparable and are "
            "returned for inspection only."
        )
    elif len(splits) > 1:
        warnings.append(
            "Same dataset, different splits. The comparison is valid but the "
            "difference includes split variance, not only detector quality."
        )

    return {
        "comparable": comparable,
        "warnings": warnings,
        "datasetFingerprints": sorted(fingerprints),
        "items": [
            evaluation_service.experiment_to_dict(experiment) for experiment in found
        ],
    }
