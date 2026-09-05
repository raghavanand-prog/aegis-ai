"""What state each subsystem is in.

These probes used to live inside ``app/api/v1/health.py``, where they were
private to the router. Phase F needed them somewhere an evidence provider could
also reach: a provider that projects ML inferences has to be able to say
"degraded, no model is loaded" rather than returning nothing and letting the
absence speak for itself.

The alternative was for each provider to ask its own subsystem directly. That
would have produced a second opinion about the same component - ``/health/ml``
saying one thing and the ML evidence provider another, on the same page, about
the same engine. So the probes moved here and both callers use them.

Every probe follows the same two rules the router already followed:

* **A probe reports, it never raises.** A failing component must produce a
  status, not an exception that removes the status page along with it.
* **A probe never returns detail that identifies infrastructure.** Exception
  types, not messages; no connection strings, paths or keys. These responses
  reach a browser.

Three states, and they are not interchangeable:

``healthy``      the component is doing its job
``degraded``     reachable but not fully working, or deliberately switched off
``unavailable``  not usable at all
"""

from __future__ import annotations

import time
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import text
from sqlalchemy.orm import Session

from app.core.config import settings
from app.telemetry.collector import collector
from app.ws.manager import manager

HEALTHY = "healthy"
DEGRADED = "degraded"
UNAVAILABLE = "unavailable"

#: Telemetry is considered stalled after this many missed intervals.
STALL_INTERVALS = 3


def worst(statuses: list[str]) -> str:
    """The status an operator should act on, given several."""
    if UNAVAILABLE in statuses:
        return UNAVAILABLE
    if DEGRADED in statuses:
        return DEGRADED
    return HEALTHY


def database_health(db: Session) -> dict[str, Any]:
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


def telemetry_health() -> dict[str, Any]:
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


def realtime_health() -> dict[str, Any]:
    return {
        "status": HEALTHY,
        "connectedClients": manager.connection_count,
        "authRequired": settings.ws_require_auth,
        "heartbeatSeconds": settings.ws_heartbeat_seconds,
    }


def ml_health() -> dict[str, Any]:
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


def ai_health() -> dict[str, Any]:
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


def threat_intel_health() -> dict[str, Any]:
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


def enrichment_health() -> dict[str, Any]:
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
