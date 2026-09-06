"""Health and readiness endpoints.

Three states are reported, and they mean different things:

* ``healthy``     - the component is doing its job
* ``degraded``    - reachable but not fully working (telemetry stalled, say)
* ``unavailable`` - not usable at all

``/health`` and ``/health/ready`` are public and deliberately thin: an
unauthenticated caller learns whether the service is up, not how it is built.
The per-component endpoints require a session because they expose internals.
"""

from __future__ import annotations

import time
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, Response, status
from sqlalchemy.orm import Session

from app.api.deps import require
from app.core.config import settings
from app.core.database import get_db
from app.core.rbac import Permission
from app.models.user import User
from app.services import health_service

router = APIRouter(tags=["health"])

# One definition of the vocabulary, in the service the probes now live in.
# Re-exported here because the router still decides the 503 on readiness.
HEALTHY = health_service.HEALTHY
DEGRADED = health_service.DEGRADED
UNAVAILABLE = health_service.UNAVAILABLE

_STARTED_AT = time.monotonic()


@router.get(
    "/health",
    summary="Liveness probe (public)",
    description=(
        "Unauthenticated on purpose: the SPA uses it to tell 'backend is down' apart from "
        "'you are signed out'. Returns no internal detail."
    ),
)
def health() -> dict[str, Any]:
    return {
        "status": HEALTHY,
        "app": settings.app_name,
        "version": settings.app_version,
        "environment": settings.environment,
        "uptimeSeconds": round(time.monotonic() - _STARTED_AT, 1),
    }


@router.get(
    "/health/ready",
    summary="Readiness probe (public, aggregate only)",
    description=(
        "Aggregate readiness for orchestrators. Responds 503 when the service cannot serve "
        "traffic. Component detail requires a session - see the endpoints below."
    ),
)
def readiness(response: Response, db: Session = Depends(get_db)) -> dict[str, Any]:
    database = health_service.database_health(db)
    telemetry = health_service.telemetry_health()

    overall = health_service.worst([database["status"], telemetry["status"]])
    if overall == UNAVAILABLE:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE

    return {
        "status": overall,
        "components": {
            "database": database["status"],
            "telemetry": telemetry["status"],
            "realtime": HEALTHY,
            # Reported, but deliberately NOT part of the readiness decision:
            # the service is perfectly able to serve traffic with no model, no
            # AI provider and no threat intelligence.
            "ml": health_service.ml_health()["status"],
            "ai": health_service.ai_health()["status"],
            "threatIntel": health_service.threat_intel_health()["status"],
            "enrichment": health_service.enrichment_health()["status"],
        },
    }


@router.get(
    "/health/database",
    summary="Database health",
    description="Round-trips a trivial query and reports the latency and dialect.",
)
def database_health(
    db: Session = Depends(get_db),
    _: User = Depends(require(Permission.TELEMETRY_READ)),
) -> dict[str, Any]:
    return health_service.database_health(db)


@router.get(
    "/health/telemetry",
    summary="Telemetry pipeline health",
    description=(
        "Reports whether the collector is running and whether it has produced a tick "
        "recently. A collector that is 'running' but silent is degraded, not healthy."
    ),
)
def telemetry_health(
    _: User = Depends(require(Permission.TELEMETRY_READ)),
) -> dict[str, Any]:
    return health_service.telemetry_health()


@router.get(
    "/health/realtime",
    summary="WebSocket service health",
    description="Connected client count and stream configuration.",
)
def realtime_health(
    _: User = Depends(require(Permission.TELEMETRY_READ)),
) -> dict[str, Any]:
    return health_service.realtime_health()


@router.get(
    "/health/ml",
    summary="Anomaly detector health",
    description=(
        "Reports degraded rather than unavailable when no model is loaded: rules-only "
        "detection is a supported operating mode, not a failure."
    ),
)
def ml_health(
    _: User = Depends(require(Permission.TELEMETRY_READ)),
) -> dict[str, Any]:
    return health_service.ml_health()


@router.get(
    "/health/ai",
    summary="AI analyst health",
    description="Provider availability and remaining daily budget. Never includes a key.",
)
def ai_health(
    _: User = Depends(require(Permission.TELEMETRY_READ)),
) -> dict[str, Any]:
    return health_service.ai_health()


@router.get(
    "/health/enrichment",
    summary="Background enrichment health",
    description=(
        "Queue depth and drop count for the worker that runs threat intelligence and "
        "correlation off the ingestion path. Dropped work costs context, not detection."
    ),
)
def enrichment_health(
    _: User = Depends(require(Permission.TELEMETRY_READ)),
) -> dict[str, Any]:
    return health_service.enrichment_health()


@router.get(
    "/health/system",
    summary="Full system status",
    description=(
        "Every component in one response, for the status panel in the SOC console."
    ),
)
def system_health(
    db: Session = Depends(get_db),
    _: User = Depends(require(Permission.TELEMETRY_READ)),
) -> dict[str, Any]:
    database = health_service.database_health(db)
    telemetry = health_service.telemetry_health()
    realtime = health_service.realtime_health()

    ml = health_service.ml_health()
    ai = health_service.ai_health()
    threat_intel = health_service.threat_intel_health()
    enrichment = health_service.enrichment_health()

    return {
        # Only the components the SOC cannot work without decide the overall
        # status. ML, AI and threat intelligence are enrichment.
        "status": health_service.worst([database["status"], telemetry["status"], realtime["status"]]),
        "checkedAt": datetime.now(timezone.utc).isoformat(),
        "app": {
            "status": HEALTHY,
            "name": settings.app_name,
            "version": settings.app_version,
            "environment": settings.environment,
            "uptimeSeconds": round(time.monotonic() - _STARTED_AT, 1),
        },
        "database": database,
        "telemetry": telemetry,
        "realtime": realtime,
        "ml": ml,
        "ai": ai,
        "threatIntel": threat_intel,
        "enrichment": enrichment,
    }
