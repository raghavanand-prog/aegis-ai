"""API v1 router aggregation."""

from fastapi import APIRouter

from app.api.v1 import (
    ai,
    analytics,
    audit,
    auth,
    detection,
    evaluation,
    events,
    health,
    incidents,
    iocs,
    ml,
    notifications,
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
api_router.include_router(iocs.router)
api_router.include_router(notifications.router)
api_router.include_router(analytics.router)
api_router.include_router(detection.router)

# V4: research evaluation. Read only, and deliberately separate from the
# production detection endpoints above.
api_router.include_router(evaluation.router)
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
