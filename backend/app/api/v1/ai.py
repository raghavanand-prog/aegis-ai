"""AI analyst endpoints.

Three verbs over the same machinery - analyse, explain, recommend - differing
only in what the prompt asks the model to concentrate on.

Access is split deliberately: reading an analysis someone already paid for is a
viewer action; *requesting* one spends money and, with a hosted provider, sends
incident detail to a third party, so it needs the analyst role.

Every response is labelled AI-generated and carries its grounding warnings. No
endpoint here changes an incident's severity, status or risk score.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Body, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from app.ai import service as ai_service
from app.ai.evidence import build as build_evidence
from app.api.deps import client_ip, require
from app.core.database import get_db
from app.core.rbac import Permission
from app.models.enums import AIAnalysisKind
from app.models.user import User
from app.schemas.common import Message
from app.schemas.ml import AIAnalysisRequest
from app.services import incident_service

router = APIRouter(prefix="/ai", tags=["ai"])

UNAVAILABLE = {
    503: {
        "model": Message,
        "description": "The AI analyst is disabled, unconfigured, over budget or failing",
    }
}
NOT_FOUND = {404: {"model": Message, "description": "Unknown incident"}}


def _incident_or_404(db: Session, incident_id: str):
    incident = incident_service.get_incident(db, incident_id)
    if incident is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Incident not found")
    return incident


def _run(
    db: Session,
    request: Request,
    incident_id: str,
    kind: AIAnalysisKind,
    payload: AIAnalysisRequest | None,
    user: User,
) -> dict[str, Any]:
    incident = _incident_or_404(db, incident_id)
    try:
        analysis = ai_service.analyze_incident(
            db,
            incident,
            kind=kind,
            question=payload.question if payload else None,
            user=user,
            # Who asked, from where. An AI request spends money and, with a
            # hosted provider, sends incident detail outside the estate.
            ip_address=client_ip(request),
        )
    except ai_service.AIUnavailable as exc:
        # The failure has already been audited by the service. 503 rather than
        # 500: this is an optional subsystem being unavailable, and the UI shows
        # it as a degraded state rather than an error.
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(exc)
        ) from exc

    db.commit()
    return ai_service.to_dict(analysis)


@router.get(
    "/status",
    summary="AI analyst availability",
    description=(
        "Whether the analyst can answer, which provider is configured, whether that "
        "provider sends data outside this deployment, and the remaining daily budget. "
        "The UI reads this to decide whether to offer the controls at all."
    ),
)
def ai_status(_: User = Depends(require(Permission.AI_READ))) -> dict[str, Any]:
    return ai_service.status()


@router.post(
    "/incidents/{incident_id}/analyze",
    summary="Full AI analysis of an incident",
    description=(
        "Builds an evidence package from the incident - events, rule findings, ML "
        "findings, indicators, threat intelligence, correlated sequences, MITRE context "
        "and the risk breakdown - and asks the configured provider to analyse it.\n\n"
        "The model sees only that package. Its answer is checked against it before "
        "storage: any technique or reference it cites that the evidence does not "
        "contain is recorded as a grounding warning and shown next to the text."
    ),
    responses={**NOT_FOUND, **UNAVAILABLE},
)
def analyze(
    incident_id: str,
    request: Request,
    payload: AIAnalysisRequest | None = Body(default=None),
    db: Session = Depends(get_db),
    user: User = Depends(require(Permission.AI_REQUEST)),
) -> dict[str, Any]:
    return _run(db, request, incident_id, AIAnalysisKind.ANALYZE, payload, user)


@router.post(
    "/incidents/{incident_id}/explain",
    summary="Explain an incident and its risk score",
    description=(
        "Same evidence, narrower task: walk the analyst through what was observed and "
        "why the risk score came out where it did, signal by signal."
    ),
    responses={**NOT_FOUND, **UNAVAILABLE},
)
def explain(
    incident_id: str,
    request: Request,
    payload: AIAnalysisRequest | None = Body(default=None),
    db: Session = Depends(get_db),
    user: User = Depends(require(Permission.AI_REQUEST)),
) -> dict[str, Any]:
    return _run(db, request, incident_id, AIAnalysisKind.EXPLAIN, payload, user)


@router.post(
    "/incidents/{incident_id}/recommend",
    summary="Recommend investigation and containment steps",
    description=(
        "Concentrates on next actions, grounded in the specific hosts, accounts and "
        "indicators in the evidence. Recommendations are suggestions for a human - "
        "AEGISX executes nothing automatically."
    ),
    responses={**NOT_FOUND, **UNAVAILABLE},
)
def recommend(
    incident_id: str,
    request: Request,
    payload: AIAnalysisRequest | None = Body(default=None),
    db: Session = Depends(get_db),
    user: User = Depends(require(Permission.AI_REQUEST)),
) -> dict[str, Any]:
    return _run(db, request, incident_id, AIAnalysisKind.RECOMMEND, payload, user)


@router.get(
    "/incidents/{incident_id}/analyses",
    summary="Stored AI analyses for an incident",
    description=(
        "Reading costs nothing and reveals nothing externally, so this is open to "
        "viewers. Each entry carries the provider, model, prompt version and evidence "
        "fingerprint it was produced from."
    ),
    responses=NOT_FOUND,
)
def list_analyses(
    incident_id: str,
    db: Session = Depends(get_db),
    _: User = Depends(require(Permission.AI_READ)),
) -> dict[str, Any]:
    incident = _incident_or_404(db, incident_id)
    analyses = ai_service.list_analyses(db, incident)
    return {
        "incidentId": incident.incident_id,
        "total": len(analyses),
        "analyses": [ai_service.to_dict(analysis) for analysis in analyses],
        "status": ai_service.status(),
    }


@router.get(
    "/incidents/{incident_id}/evidence",
    summary="The evidence package the AI analyst would receive",
    description=(
        "Exactly what would be sent to a provider for this incident, after sanitisation "
        "and capping. Published so an analyst can see what the model was and was not "
        "shown - an AI answer whose inputs are hidden is not reviewable.\n\n"
        "No provider is called and nothing is stored."
    ),
    responses=NOT_FOUND,
)
def evidence(
    incident_id: str,
    db: Session = Depends(get_db),
    _: User = Depends(require(Permission.AI_READ)),
) -> dict[str, Any]:
    incident = _incident_or_404(db, incident_id)
    package = build_evidence(db, incident)
    return {
        "incidentId": incident.incident_id,
        "fingerprint": package.fingerprint(),
        "summary": package.summary(),
        "sufficient": package.is_sufficient,
        "injectionAttemptsDetected": package.injection_flags,
        "package": package.to_dict(),
    }
