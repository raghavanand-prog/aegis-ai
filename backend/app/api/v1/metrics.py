"""The metrics scrape endpoint.

Prometheus text exposition, from the in-process registry. No library, no push
gateway, no external collector - see ``app/observability/__init__.py``.

**It requires a session.** That is a deliberate departure from the usual
practice of leaving ``/metrics`` open on an internal port, and the reason is
what these particular metrics are: request rates by route, events ingested,
incidents opened by severity, response actions refused. Unauthenticated, that
is a public description of how much security activity this organisation is
handling and when it drops off. The counters carry no user, incident or
account identifiers - see the note in ``instruments`` - but volume alone is
worth protecting.

Gated on ``telemetry:read``, the same permission the component health
endpoints use, which a viewer holds. A scraper therefore needs a service
account, which is a real operational cost and the right trade for a security
platform.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends
from fastapi.responses import PlainTextResponse

from app.api.deps import require
from app.core.rbac import Permission
from app.models.user import User
from app.observability import instruments

router = APIRouter(tags=["observability"])

#: The content type Prometheus expects. Version 0.0.4 of the text format.
CONTENT_TYPE = "text/plain; version=0.0.4; charset=utf-8"


@router.get(
    "/metrics",
    response_class=PlainTextResponse,
    summary="Prometheus metrics",
    description=(
        "In-process counters, gauges and histograms in the Prometheus text exposition "
        "format. Requires a session: unauthenticated, request rates and incident volumes "
        "describe how much security activity this organisation handles and when it stops. "
        "No metric is labelled by user, incident, account or indicator."
    ),
)
def metrics(
    _: User = Depends(require(Permission.TELEMETRY_READ)),
) -> PlainTextResponse:
    return PlainTextResponse(content=instruments.snapshot(), media_type=CONTENT_TYPE)
