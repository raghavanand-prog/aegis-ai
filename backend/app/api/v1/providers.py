"""Which evidence sources are answering.

One route. It exists because the evidence set already reports *degraded*
providers per incident, and that is the wrong place to learn that the anomaly
model has not been loaded since the service started - by then an analyst is
mid-investigation and reading a footnote.

The status this returns is the same three-word vocabulary as ``/health/*``, and
comes from the same probes: the providers ask ``app.services.health_service``,
so this endpoint and ``/health/system`` cannot disagree about the same
subsystem.

Gated on ``telemetry:read``, which a viewer holds. Knowing which sources are
answering is part of reading an incident honestly rather than an administrative
privilege - an analyst who cannot tell "nothing was found" from "nothing was
asked" is being misled, whatever their role.

What is deliberately not here: no way to enable, disable, reconfigure or
retry a provider. This is a window, not a control panel.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends

from app.api.deps import require
from app.core.rbac import Permission
from app.evidence import registry
from app.models.user import User
from app.services import health_service

router = APIRouter(prefix="/providers", tags=["providers"])


@router.get(
    "",
    summary="Evidence providers and their health",
    description=(
        "Every registered evidence provider, the evidence kinds it can emit, whether it "
        "reaches outside the platform, and what state it is in. `status` is the worst of "
        "them, so a reader does not have to scan the list to find the bad news."
    ),
)
def list_providers(
    _: User = Depends(require(Permission.TELEMETRY_READ)),
) -> dict[str, Any]:
    described = registry.describe()
    statuses = [entry["health"]["status"] for entry in described]

    return {
        "status": health_service.worst(statuses),
        "total": len(described),
        "degraded": sum(1 for value in statuses if value != health_service.HEALTHY),
        "providers": described,
    }
