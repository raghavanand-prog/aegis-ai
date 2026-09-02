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
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.api.deps import require
from app.core.config import settings
from app.core.database import get_db
from app.core.rbac import Permission
from app.models.user import User
from app.telemetry.collector import collector
from app.ws.manager import manager

router = APIRouter(tags=["health"])

HEALTHY = "healthy"
DEGRADED = "degraded"
UNAVAILABLE = "unavailable"

_STARTED_AT = time.monotonic()

#: Telemetry is considered stalled after this many missed intervals.
STALL_INTERVALS = 3


def _database_health(db: Session) -> dict[str, Any]:
    started = time.perf_counter()
    try:
        db.execute(text("SELECT 1"))
        return {
            "status": HEALTHY,
            "latencyMs": round((time.perf_counter() - started) * 1000, 2),
            "dialect": db.bind.dialect.name if db.bind else "unknown",
        }
    except Exception as exc:  # noqa: BLE001 - a probe reports, it does not raise
        return {
            "status": UNAVAILABLE,
            "latencyMs": round((time.perf_counter() - started) * 1000, 2),
            # Type only: a connection string in a health response is a leak.
            "error": type(exc).__name__,
        }


def _telemetry_health() -> dict[str, Any]:
    state = collector.status()

    if not settings.telemetry_enabled:
        return {
            "status": DEGRADED,
            "reason": "telemetry disabled by configuration",
            "running": False,
            "eventsIngested": state["eventsIngested"],
        }

    if not state["running"]:
        return {"status": UNAVAILABLE, "reason": "collector is not running", "running": False}

    stalled = False
    seconds_since_tick: float | None = None
    if state["lastTickAt"]:
        last = datetime.fromisoformat(state["lastTickAt"])
        seconds_since_tick = (datetime.now(timezone.utc) - last).total_seconds()
        stalled = seconds_since_tick > state["intervalSeconds"] * STALL_INTERVALS

    return {
        "status": DEGRADED if stalled else HEALTHY,
        "reason": "no collection tick within the expected window" if stalled else None,
        "running": True,
        "intervalSeconds": state["intervalSeconds"],
        "eventsIngested": state["eventsIngested"],
        "errors": state["errors"],
        "secondsSinceLastTick": round(seconds_since_tick, 1) if seconds_since_tick else None,
        "sources": state["sources"],
    }


def _realtime_health() -> dict[str, Any]:
    return {
        "status": HEALTHY,
        "connectedClients": manager.connection_count,
        "authRequired": settings.ws_require_auth,
        "heartbeatSeconds": settings.ws_heartbeat_seconds,
    }


def _ml_health() -> dict[str, Any]:
    """ML is optional: unavailable is degraded, never a service outage.

    A SOC running on deterministic rules alone is a working SOC. The state that
    matters here is whether the reason is understood, which it always is.
    """
    from app.ml.inference import engine as inference_engine

    state = inference_engine.engine.status()
    if not state["available"]:
        # `reason` is always populated when unavailable - see
        # InferenceEngine.unavailable_reason.
        return {"status": DEGRADED, "reason": state["reason"], "available": False}
    return {
        "status": HEALTHY,
        "available": True,
        "model": f"{state['modelName']}@{state['modelVersion']}",
        "featureSchemaVersion": state["featureSchemaVersion"],
        "eventsScored": state["eventsScored"],
        "anomaliesFlagged": state["anomaliesFlagged"],
        "failures": state["failures"],
    }


def _ai_health() -> dict[str, Any]:
    from app.ai import service as ai_service

    state = ai_service.status()
    return {
        "status": HEALTHY if state["available"] else DEGRADED,
        "available": state["available"],
        "provider": state["provider"],
        "reason": state.get("reason"),
        "isTemplateProvider": state.get("isTemplateProvider", False),
        "budget": state.get("budget", {}),
    }


def _threat_intel_health() -> dict[str, Any]:
    from app.threatintel import service as threat_intel_service

    state = threat_intel_service.status()
    return {
        "status": HEALTHY if state["configured"] else DEGRADED,
        "provider": state["provider"],
        "configured": state["configured"],
        "reason": (
            None
            if state["configured"]
            else "No threat intelligence provider is configured."
        ),
        "budget": state["budget"],
    }


def _enrichment_health() -> dict[str, Any]:
    from app.services.enrichment_service import worker

    state = worker.status()
    if not state["enabled"]:
        return {
            "status": DEGRADED,
            "reason": "Background enrichment is disabled (ENRICHMENT_ENABLED=false)",
            **state,
        }
    if not state["running"]:
        return {"status": UNAVAILABLE, "reason": "Enrichment worker is not running", **state}
    return {
        "status": DEGRADED if state["degraded"] else HEALTHY,
        "reason": (
            "Enrichment is falling behind ingestion; threat intelligence and "
            "correlation are being skipped for some events. Detection is unaffected."
            if state["degraded"]
            else None
        ),
        **state,
    }


def _worst(statuses: list[str]) -> str:
    if UNAVAILABLE in statuses:
        return UNAVAILABLE
    if DEGRADED in statuses:
        return DEGRADED
    return HEALTHY


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
    database = _database_health(db)
    telemetry = _telemetry_health()

    overall = _worst([database["status"], telemetry["status"]])
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
            "ml": _ml_health()["status"],
            "ai": _ai_health()["status"],
            "threatIntel": _threat_intel_health()["status"],
            "enrichment": _enrichment_health()["status"],
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
    return _database_health(db)


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
    return _telemetry_health()


@router.get(
    "/health/realtime",
    summary="WebSocket service health",
    description="Connected client count and stream configuration.",
)
def realtime_health(
    _: User = Depends(require(Permission.TELEMETRY_READ)),
) -> dict[str, Any]:
    return _realtime_health()


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
    return _ml_health()


@router.get(
    "/health/ai",
    summary="AI analyst health",
    description="Provider availability and remaining daily budget. Never includes a key.",
)
def ai_health(
    _: User = Depends(require(Permission.TELEMETRY_READ)),
) -> dict[str, Any]:
    return _ai_health()


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
    return _enrichment_health()


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
    database = _database_health(db)
    telemetry = _telemetry_health()
    realtime = _realtime_health()

    ml = _ml_health()
    ai = _ai_health()
    threat_intel = _threat_intel_health()
    enrichment = _enrichment_health()

    return {
        # Only the components the SOC cannot work without decide the overall
        # status. ML, AI and threat intelligence are enrichment.
        "status": _worst([database["status"], telemetry["status"], realtime["status"]]),
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
