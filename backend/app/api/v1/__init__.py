"""API v1 router aggregation."""

from fastapi import APIRouter

from app.api.v1 import (
    adaptation,
    ai,
    analytics,
    audit,
    auth,
    decisions,
    detection,
    evaluation,
    events,
    evidence,
    health,
    incidents,
    iocs,
    ml,
    notifications,
    providers,
    response_actions,
    sequences,
    telemetry,
    threat_intel,
    ws,
)

api_router = APIRouter()
api_router.include_router(health.router)
api_router.include_router(auth.router)
api_router.include_router(events.router)
api_router.include_router(incidents.router)
# V9: investigation evidence, mounted under the incidents prefix because
# every question about evidence starts from an incident.
api_router.include_router(evidence.router)
# V9: what evidence each consequential decision was taken on, and whether
# it still holds.
api_router.include_router(decisions.router)
# V9 Phase E: requesting containment, and a second person deciding on it.
# Nothing here executes an action.
api_router.include_router(response_actions.router)
# V9 Phase F: which evidence sources are answering, and which are degraded.
api_router.include_router(providers.router)
api_router.include_router(iocs.router)
api_router.include_router(notifications.router)
api_router.include_router(analytics.router)
api_router.include_router(detection.router)

# V4: research evaluation. Read only, and deliberately separate from the
# production detection endpoints above.
api_router.include_router(evaluation.router)
api_router.include_router(adaptation.router)
# --- V3 -------------------------------------------------------------------
api_router.include_router(ml.router)
api_router.include_router(sequences.router)
api_router.include_router(threat_intel.router)
api_router.include_router(ai.router)
# --------------------------------------------------------------------------
api_router.include_router(audit.router)
api_router.include_router(telemetry.router)
api_router.include_router(ws.router)

__all__ = ["api_router"]
