"""Detection engine transparency: rule catalogue and measured quality.

Everything here describes deterministic rules. There is no model, and the
endpoints say so in their own payloads so a consumer cannot mistake these for
ML metrics.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy.orm import Session

from app.api.deps import client_ip, require
from app.core.database import get_db
from app.core.rbac import Permission
from app.detection import RULES, catalogue
from app.evaluation.datasets.labeled_dataset import (
    DEFAULT_SAMPLES_PER_CLASS,
    DEFAULT_SEED,
    build_dataset,
)
from app.evaluation.reports.store import list_reports, load_latest, write_report
from app.evaluation.runners.detection_runner import ruleset_fingerprint, run_detection_evaluation
from app.models.enums import AuditAction
from app.models.user import User
from app.schemas.common import Message
from app.services import audit_service

router = APIRouter(prefix="/detection", tags=["detection"])

NO_REPORT_DETAIL = (
    "No detection evaluation has been run yet. Run "
    "`python -m app.evaluation.run_detection_eval` in the backend to produce one."
)


@router.get(
    "/rules",
    summary="Detection rule catalogue",
    description=(
        "Every rule the engine can fire, with its stable id, version, severity, risk "
        "contribution and MITRE technique. Rules are hand written and deterministic; the "
        "`legacyId` field maps back to the V1 identifier so older stored detections stay "
        "interpretable."
    ),
)
def detection_rules(
    _: User = Depends(require(Permission.DETECTION_READ)),
) -> dict[str, Any]:
    return {
        "engine": "deterministic-rules",
        "usesMachineLearning": False,
        "ruleCount": len(RULES),
        "rulesetFingerprint": ruleset_fingerprint(),
        "rules": catalogue(),
    }


@router.get(
    "/quality",
    summary="Latest detection engine evaluation",
    description=(
        "Returns the most recent evaluation of the deterministic rules against the "
        "labelled dataset: precision, recall, F1, false positive and false negative rates, "
        "per-class and per-rule breakdowns, and engine latency.\n\n"
        "Responds 404 when no evaluation has been run - the platform never invents "
        "measurements it does not have."
    ),
    responses={404: {"model": Message, "description": "No evaluation report available"}},
)
def detection_quality(
    _: User = Depends(require(Permission.DETECTION_READ)),
) -> dict[str, Any]:
    report = load_latest()
    if report is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=NO_REPORT_DETAIL)

    current = ruleset_fingerprint()
    report["stale"] = report.get("engine", {}).get("fingerprint") != current
    report["currentRulesetFingerprint"] = current
    report["availableReports"] = list_reports()
    return report


@router.post(
    "/quality/run",
    summary="Run the detection evaluation now",
    description=(
        "Rebuilds the labelled dataset from its seed, runs the current rules over it and "
        "stores a fresh report. Administrator only, and audited. The dataset is synthetic "
        "and labelled; no production data is involved."
    ),
    responses={403: {"model": Message, "description": "Administrator role required"}},
)
def run_detection_quality(
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(require(Permission.DETECTION_EVALUATE)),
    seed: int = Query(default=DEFAULT_SEED, ge=0),
    samples_per_class: int = Query(
        default=DEFAULT_SAMPLES_PER_CLASS, ge=1, le=500, alias="samplesPerClass"
    ),
) -> dict[str, Any]:
    dataset = build_dataset(seed=seed, samples_per_class=samples_per_class)
    report = run_detection_evaluation(dataset).to_dict()
    write_report(report)

    audit_service.record(
        db,
        action=AuditAction.DETECTION_EVALUATION_RUN,
        user=user,
        target_type="detection",
        target_id=report["engine"]["fingerprint"],
        ip_address=client_ip(request),
        details={
            "seed": seed,
            "samplesPerClass": samples_per_class,
            "eventsEvaluated": report["volume"]["eventsProcessed"],
            "f1": report["overall"]["f1"],
        },
    )
    db.commit()

    report["stale"] = False
    report["currentRulesetFingerprint"] = report["engine"]["fingerprint"]
    return report
