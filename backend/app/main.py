"""AEGISX backend application entrypoint.

    telemetry -> normalization -> detection -> PostgreSQL -> WebSocket -> SOC UI
"""

from __future__ import annotations

import asyncio
import logging
import sys
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

# Fail loudly and early on an unsupported interpreter: PEP 604 unions
# (`str | None`) are resolved at runtime by Pydantic, so 3.9 fails deep inside
# model construction with an error that says nothing useful.
if sys.version_info < (3, 10):  # noqa: UP036 # pragma: no cover - the guard exists precisely for 3.9 interpreters
    raise RuntimeError(
        "AEGISX requires Python 3.10 or newer (3.11+ recommended); "
        f"this interpreter is {sys.version.split()[0]}. "
        "Recreate the virtualenv: python3.11 -m venv .venv"
    )

from app.api.v1 import api_router  # noqa: E402
from app.core.config import settings  # noqa: E402
from app.core.init_db import bootstrap  # noqa: E402
from app.core.logging_config import configure_logging  # noqa: E402
from app.core.middleware import (  # noqa: E402
    BodySizeLimitMiddleware,
    RateLimitMiddleware,
    RequestContextMiddleware,
    SecurityHeadersMiddleware,
)
from app.services.enrichment_service import worker as enrichment_worker  # noqa: E402
from app.telemetry.collector import collector  # noqa: E402
from app.ws.manager import manager  # noqa: E402

configure_logging()
logger = logging.getLogger("aegisx")

OPENAPI_TAGS = [
    {
        "name": "auth",
        "description": (
            "Sign-in, session management and the RBAC matrix. Passwords are stored as "
            "PBKDF2-HMAC-SHA256 digests and never returned."
        ),
    },
    {
        "name": "events",
        "description": (
            "Normalized security events from the telemetry pipeline, including the "
            "detection explanations attached to each one, and promotion into incidents."
        ),
    },
    {
        "name": "incidents",
        "description": (
            "Analyst-facing incidents: creation, assignment, status, timeline and recorded "
            "response actions. Response actions are recorded, never executed."
        ),
    },
    {
        "name": "detection",
        "description": (
            "Detection engine transparency: the versioned rule catalogue and the measured "
            "quality of those rules against a labelled dataset. Deterministic rules only - "
            "no machine learning is involved."
        ),
    },
    {
        "name": "iocs",
        "description": "Indicators of compromise extracted from telemetry and linked to events.",
    },
    {
        "name": "notifications",
        "description": "Analyst notifications raised by high and critical activity.",
    },
    {
        "name": "analytics",
        "description": (
            "Aggregations computed from stored rows at query time. Nothing on this surface "
            "is precomputed or fabricated."
        ),
    },
    {
        "name": "telemetry",
        "description": (
            "Collector status and manual collection. External telemetry sources are refused "
            "unless explicitly enabled in configuration."
        ),
    },
    {
        "name": "ml",
        "description": (
            "The anomaly detection model: its feature schema, registered versions, "
            "risk-scoring weights, and what it concluded about a specific event. "
            "Scores are anomaly rankings, never probabilities."
        ),
    },
    {
        "name": "sequences",
        "description": (
            "Correlated groups of related events. A sequence is a finding, not an "
            "incident - promotion is always an analyst decision."
        ),
    },
    {
        "name": "threat-intel",
        "description": (
            "External reputation enrichment through a provider abstraction. API keys "
            "live on the server and never appear in any payload here."
        ),
    },
    {
        "name": "ai",
        "description": (
            "Evidence-grounded AI analysis of an incident. The analyst reasons only "
            "from a supplied evidence package, its answers are checked against that "
            "package, and it changes nothing in the platform."
        ),
    },
    {"name": "audit", "description": "Append-only trail of analyst and system actions."},
    {
        "name": "health",
        "description": (
            "Liveness, readiness and per-component health. Components report healthy, "
            "degraded or unavailable."
        ),
    },
    {"name": "realtime", "description": "Authenticated WebSocket stream of live activity."},
]

API_DESCRIPTION = """
Security operations backend for AEGISX: telemetry ingestion, normalization,
deterministic detection, incident management, audit logging and realtime streaming.

**Authentication** - obtain a token from `POST /api/v1/auth/login` and send it as
`Authorization: Bearer <token>`. Tokens carry the user's token version, so a password
change or `POST /api/v1/auth/logout-all` revokes them immediately.

**Authorization** - every route is guarded by a permission from the role matrix
(`GET /api/v1/auth/permissions`). The UI hiding a control is never the security boundary.

**Detection (V3)** - hybrid. Deterministic, versioned rules remain the backbone and every
rule detection carries the reason it fired. An unsupervised anomaly model adds a second,
independent signal, and a correlation engine groups related events into sequences. Risk is
a transparent weighted sum of those signals, and `riskSignals` on every event says exactly
what contributed. An anomaly alone can never make an event high risk.

**AI** - the AI analyst is not a detector. It receives a structured evidence package built
from what the rules, the model and the correlator already found, and explains it. Its
output is checked against that package, stored with any grounding warnings, labelled
AI-generated, and never changes an incident's severity, status or risk score.

**Degradation** - ML, threat intelligence and the AI analyst are all optional. With every
one of them unavailable, ingestion, rule detection, incidents, analytics and the live
stream work unchanged, and the affected surfaces report why they are empty.
""".strip()


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings.validate_runtime()
    manager.bind_loop(asyncio.get_running_loop())

    try:
        bootstrap()
    except Exception:  # noqa: BLE001 - a database outage must not crash startup
        logger.exception("Database bootstrap failed; the API will report degraded readiness")

    # Load the active anomaly model before telemetry starts, so the first event
    # ingested is scored. A missing or unloadable model is logged and the
    # pipeline runs rules-only - it is never a startup failure.
    if settings.ml_enabled:
        try:
            from app.core.database import SessionLocal
            from app.ml.inference import engine as inference_engine

            with SessionLocal() as db:
                if inference_engine.engine.load_active(db):
                    logger.info(
                        "Anomaly model ready",
                        extra={
                            "model": inference_engine.engine.status()["modelVersion"],
                            "operation": "startup",
                        },
                    )
                else:
                    logger.warning(
                        "Running without an anomaly model: %s",
                        inference_engine.engine.status()["reason"],
                    )
        except Exception:  # noqa: BLE001 - ML must never block startup
            logger.exception("ML initialisation failed; continuing with rules-only detection")

    if settings.enrichment_enabled:
        enrichment_worker.start()
    else:
        logger.info("Background enrichment disabled (ENRICHMENT_ENABLED=false)")

    if settings.telemetry_enabled:
        await collector.start()
    else:
        logger.info("Telemetry collector disabled (TELEMETRY_ENABLED=false)")

    logger.info(
        "%s %s ready",
        settings.app_name,
        settings.app_version,
        extra={"environment": settings.environment, "operation": "startup"},
    )
    try:
        yield
    finally:
        await collector.stop()
        enrichment_worker.stop()


app = FastAPI(
    title=settings.app_name,
    version=settings.app_version,
    description=API_DESCRIPTION,
    openapi_tags=OPENAPI_TAGS,
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
    contact={"name": "AEGISX", "url": "https://github.com/"},
    license_info={"name": "See repository"},
)

# Registration order matters: Starlette runs the LAST registered middleware
# first, so this leaves CORS outermost (preflights always answered), then
# request context (every request gets an id and a log line), then security
# headers, then the rate limiter, then the body size guard.
app.add_middleware(BodySizeLimitMiddleware)
app.add_middleware(RateLimitMiddleware)
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(RequestContextMiddleware)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origin_list,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "X-Request-ID"],
    expose_headers=["X-Request-ID"],
    max_age=600,
)


def _request_id(request: Request) -> str | None:
    return getattr(request.state, "request_id", None)


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(
    request: Request, exc: RequestValidationError
) -> JSONResponse:
    """Return field-level validation errors without echoing submitted values.

    The default handler includes the offending input, which would put passwords
    into logs and responses the moment a login payload fails validation.
    """
    errors: list[dict[str, Any]] = [
        {
            "field": ".".join(str(part) for part in error.get("loc", ()) if part != "body"),
            "message": error.get("msg", "Invalid value"),
            "type": error.get("type", "value_error"),
        }
        for error in exc.errors()
    ]
    return JSONResponse(
        status_code=422,
        content={
            "detail": "Request validation failed",
            "errors": errors,
            "requestId": _request_id(request),
        },
    )


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    """Log the detail, return none of it.

    The request id is echoed so an analyst can quote it and an engineer can find
    the matching structured log line.
    """
    logger.exception(
        "unhandled error",
        extra={
            "method": request.method,
            "path": request.url.path,
            "result": "error",
            "errorType": type(exc).__name__,
        },
    )
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"detail": "Internal server error", "requestId": _request_id(request)},
    )


@app.get("/", tags=["health"], summary="Service metadata")
def root() -> dict[str, str]:
    return {
        "name": settings.app_name,
        "version": settings.app_version,
        "docs": "/docs",
        "api": settings.api_v1_prefix,
    }


app.include_router(api_router, prefix=settings.api_v1_prefix)
