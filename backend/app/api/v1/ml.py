"""Machine learning endpoints.

Transparency first: these expose what the model is, what it was trained on,
what it said about a specific event and why - not just a score. Everything
here reports honestly when the model is unavailable rather than returning an
empty list that reads like "nothing was anomalous".

No inference happens in a route handler. Handlers call the engine and the
registry; the ML layer never imports FastAPI.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy.orm import Session

from app.api.deps import client_ip, require
from app.core.database import get_db
from app.core.rbac import Permission
from app.ml.features import FEATURE_NAMES
from app.ml.inference import engine as inference_engine
from app.ml.registry import RegistryError, registry
from app.ml.schemas import FEATURE_SCHEMA_VERSION
from app.models.enums import AuditAction, MLModelStatus
from app.models.user import User
from app.schemas.common import Message, as_utc
from app.scoring import describe_strategy
from app.services import audit_service, event_service

router = APIRouter(prefix="/ml", tags=["ml"])

NO_MODEL = (
    "No anomaly model has been trained yet. Run "
    "`python -m app.ml.training.train_anomaly_model` in the backend."
)


@router.get(
    "/status",
    summary="Anomaly detector status",
    description=(
        "Whether the anomaly model is loaded and scoring, and - when it is not - the "
        "specific reason. A blank ML panel in the UI always has an explanation behind "
        "it: no model trained, artifact missing, digest mismatch, or a feature schema "
        "the running build does not speak."
    ),
)
def ml_status(_: User = Depends(require(Permission.ML_READ))) -> dict[str, Any]:
    return inference_engine.engine.status()


@router.get(
    "/features",
    summary="Feature schema",
    description=(
        "The exact feature vector the extractor produces, in order. This tuple is the "
        "schema: a model fitted on a different ordering is refused at load time rather "
        "than silently scoring the wrong columns."
    ),
)
def ml_features(_: User = Depends(require(Permission.ML_READ))) -> dict[str, Any]:
    return {
        "featureSchemaVersion": FEATURE_SCHEMA_VERSION,
        "featureCount": len(FEATURE_NAMES),
        "features": list(FEATURE_NAMES),
        "notes": [
            (
                "No detection output is a feature. Rule matches, rule severity and the "
                "rule risk score are excluded so the ML signal stays independent of the "
                "rules it is meant to complement."
            ),
            (
                "Features are computed by one implementation shared by training, "
                "evaluation and live inference, which is what prevents training/serving "
                "skew."
            ),
        ],
    }


@router.get(
    "/scoring",
    summary="Risk scoring strategy",
    description=(
        "The weights behind every risk score, and the bands they map onto. Published "
        "so the number an analyst sees can be reproduced by hand."
    ),
)
def ml_scoring(_: User = Depends(require(Permission.ML_READ))) -> dict[str, Any]:
    return describe_strategy()


@router.get(
    "/models",
    summary="Registered models",
    description=(
        "Every trained model version with its training provenance, hyperparameters and "
        "artifact digest. Versions are immutable; activating one archives the previous, "
        "which is what makes a rollback possible."
    ),
)
def list_models(
    _: User = Depends(require(Permission.ML_READ)),
    db: Session = Depends(get_db),
    name: str | None = Query(default=None, max_length=64),
    limit: int = Query(default=50, ge=1, le=200),
) -> dict[str, Any]:
    models = registry.list_models(db, name=name, limit=limit)
    active = registry.get_active(db, name or "isolation_forest")
    previous = registry.get_previous(db, name or "isolation_forest")
    return {
        "models": [registry.to_dict(model) for model in models],
        "active": registry.to_dict(active) if active else None,
        "previous": registry.to_dict(previous) if previous else None,
        "total": len(models),
    }


@router.get(
    "/models/{model_id}",
    summary="One registered model",
    responses={404: {"model": Message, "description": "Unknown model"}},
)
def get_model(
    model_id: int,
    _: User = Depends(require(Permission.ML_READ)),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    model = registry.get(db, model_id)
    if model is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Model not found")
    return registry.to_dict(model)


@router.post(
    "/models/{model_id}/activate",
    summary="Activate a model version",
    description=(
        "Makes this version the one serving inference and archives the incumbent. "
        "Administrator only and audited: activating a model changes what the whole "
        "platform detects, which is not an ordinary analyst action."
    ),
    responses={
        403: {"model": Message, "description": "Administrator role required"},
        404: {"model": Message, "description": "Unknown model"},
        409: {"model": Message, "description": "Model cannot be activated"},
    },
)
def activate_model(
    model_id: int,
    request: Request,
    user: User = Depends(require(Permission.ML_MANAGE)),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    model = registry.get(db, model_id)
    if model is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Model not found")

    previous = registry.get_active(db, model.name)
    try:
        registry.activate_model(db, model)
    except RegistryError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc

    audit_service.record(
        db,
        action=AuditAction.ML_MODEL_ACTIVATED,
        user=user,
        target_type="ml_model",
        target_id=model.identity,
        ip_address=client_ip(request),
        details={
            "previous": previous.identity if previous else None,
            "featureSchemaVersion": model.feature_schema_version,
        },
    )
    db.commit()

    # Load it immediately so the next event is scored by the version an
    # administrator just chose, not by the one that happened to be in memory.
    loaded = inference_engine.engine.reload(db)
    return {
        "model": registry.to_dict(model),
        "loaded": loaded,
        "status": inference_engine.engine.status(),
    }


@router.post(
    "/models/{model_id}/deactivate",
    summary="Deactivate a model version",
    description=(
        "Stops serving this version. If no other version is active the platform "
        "degrades to rules-only detection, which is a supported state - not an outage."
    ),
    responses={404: {"model": Message, "description": "Unknown model"}},
)
def deactivate_model(
    model_id: int,
    request: Request,
    user: User = Depends(require(Permission.ML_MANAGE)),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    model = registry.get(db, model_id)
    if model is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Model not found")

    registry.deactivate_model(db, model)
    audit_service.record(
        db,
        action=AuditAction.ML_MODEL_DEACTIVATED,
        user=user,
        target_type="ml_model",
        target_id=model.identity,
        ip_address=client_ip(request),
    )
    db.commit()
    inference_engine.engine.reload(db)
    return {"model": registry.to_dict(model), "status": inference_engine.engine.status()}


@router.post(
    "/models/rollback",
    summary="Roll back to the previous model version",
    description=(
        "Reactivates the most recently archived version of a model. Nothing is deleted "
        "and no artifact is rewritten - the previous version simply becomes the serving "
        "one again."
    ),
    responses={404: {"model": Message, "description": "No previous version to roll back to"}},
)
def rollback_model(
    request: Request,
    user: User = Depends(require(Permission.ML_MANAGE)),
    db: Session = Depends(get_db),
    name: str = Query(default="isolation_forest", max_length=64),
) -> dict[str, Any]:
    previous = registry.get_previous(db, name)
    if previous is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No archived version of {name!r} is available to roll back to.",
        )

    current = registry.get_active(db, name)
    registry.activate_model(db, previous)
    audit_service.record(
        db,
        action=AuditAction.ML_MODEL_ROLLBACK,
        user=user,
        target_type="ml_model",
        target_id=previous.identity,
        ip_address=client_ip(request),
        details={"rolledBackFrom": current.identity if current else None},
    )
    db.commit()
    inference_engine.engine.reload(db)
    return {
        "model": registry.to_dict(previous),
        "rolledBackFrom": registry.to_dict(current) if current else None,
        "status": inference_engine.engine.status(),
    }


@router.get(
    "/events/{event_id}",
    summary="ML findings for one event",
    description=(
        "Every model verdict recorded against an event, newest first, with the features "
        "that sat furthest from the training norm.\n\n"
        "An empty `findings` list means the model did not score this event - because it "
        "was unavailable, or the event predates it. It does **not** mean the model found "
        "the event normal; `modelAvailable` and `reason` say which."
    ),
    responses={404: {"model": Message, "description": "Unknown event"}},
)
def event_findings(
    event_id: str,
    _: User = Depends(require(Permission.ML_READ)),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    event = event_service.get_event(db, event_id)
    if event is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Event not found")

    engine_status = inference_engine.engine.status()
    findings = sorted(
        event.ml_inferences or [], key=lambda row: row.inferred_at, reverse=True
    )
    return {
        "eventId": event.event_id,
        "modelAvailable": engine_status["available"],
        "reason": engine_status["reason"],
        "riskScore": event.risk_score,
        "riskLevel": event.risk_level,
        "riskSignals": event.risk_signals or [],
        "findings": [
            {
                "model": row.model_name,
                "modelVersion": row.model_version,
                "featureSchemaVersion": row.feature_schema_version,
                "anomalyScore": round(row.anomaly_score, 4),
                "scoreKind": "anomaly_score",
                "isAnomaly": row.is_anomaly,
                "threshold": row.threshold,
                "topContributors": row.top_contributors or [],
                "featuresUsed": sorted(row.features or {}),
                "latencyMs": round(row.latency_ms, 3),
                "inferredAt": as_utc(row.inferred_at).isoformat(),
            }
            for row in findings
        ],
    }


@router.get(
    "/incidents/{incident_id}",
    summary="ML findings across an incident",
    responses={404: {"model": Message, "description": "Unknown incident"}},
)
def incident_findings(
    incident_id: str,
    _: User = Depends(require(Permission.ML_READ)),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    from app.services import incident_service

    incident = incident_service.get_incident(db, incident_id)
    if incident is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Incident not found")

    findings = []
    for event in incident.events or []:
        for row in event.ml_inferences or []:
            findings.append(
                {
                    "eventId": event.event_id,
                    "eventTitle": event.title,
                    "model": row.model_name,
                    "modelVersion": row.model_version,
                    "anomalyScore": round(row.anomaly_score, 4),
                    "scoreKind": "anomaly_score",
                    "isAnomaly": row.is_anomaly,
                    "threshold": row.threshold,
                    "topContributors": row.top_contributors or [],
                    "inferredAt": as_utc(row.inferred_at).isoformat(),
                }
            )
    findings.sort(key=lambda item: item["anomalyScore"], reverse=True)

    engine_status = inference_engine.engine.status()
    return {
        "incidentId": incident.incident_id,
        "modelAvailable": engine_status["available"],
        "reason": engine_status["reason"],
        "eventsScored": len({f["eventId"] for f in findings}),
        "anomalyCount": sum(1 for f in findings if f["isAnomaly"]),
        "findings": findings,
    }


@router.get(
    "/registry/summary",
    summary="Registry summary",
    description="Counts by status, for the administration surface.",
)
def registry_summary(
    _: User = Depends(require(Permission.ML_READ)),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    models = registry.list_models(db, limit=500)
    return {
        "total": len(models),
        "byStatus": {
            state.value: sum(1 for model in models if model.status == state.value)
            for state in MLModelStatus
        },
        "trainingCommand": "python -m app.ml.training.train_anomaly_model",
        "hint": NO_MODEL if not models else None,
    }
