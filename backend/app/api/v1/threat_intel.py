"""Threat intelligence endpoints.

The frontend never talks to a reputation provider. It asks AEGISX, AEGISX asks
the provider using a key that only ever exists on the server, and the key is
absent from every payload on this router. That is the whole reason these
endpoints exist rather than the browser calling VirusTotal directly.

Reading a cached verdict is a viewer action. *Triggering* a lookup reaches
outside the estate and consumes a metered quota, so it requires an analyst.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import client_ip, require
from app.core.database import get_db
from app.core.rbac import Permission
from app.models.enums import AuditAction, IOCType
from app.models.threat_intel import ThreatIntelResult
from app.models.user import User
from app.repositories.ioc_repository import ioc_repository
from app.schemas.common import Message
from app.services import audit_service
from app.threatintel import service as threat_intel_service
from app.threatintel.validation import InvalidIndicator, validate

router = APIRouter(prefix="/threat-intel", tags=["threat-intel"])


@router.get(
    "/status",
    summary="Enrichment status",
    description=(
        "Which provider is configured, whether it has credentials, and how much of the "
        "daily lookup budget is left. Never includes the API key."
    ),
)
def threat_intel_status(
    _: User = Depends(require(Permission.THREAT_INTEL_READ)),
) -> dict[str, Any]:
    return threat_intel_service.status()


@router.get(
    "/ioc/{ioc_value:path}",
    summary="Cached reputation for one indicator",
    description=(
        "Returns the stored verdict without contacting the provider. A `status` other "
        "than `ok` means no verdict was obtained - which is not the same as the "
        "indicator being clean, and the payload says so.\n\n"
        "An indicator AEGISX will not look up externally (an internal address, a "
        "documentation range, an unsupported type) returns 200 with an empty result "
        "list and `notLookedUp` explaining why. Reading is not an action, so being "
        "out of scope is an answer here rather than a client error - which is what "
        "keeps the investigation UI from firing requests it knows will be refused."
    ),
    responses={
        404: {"model": Message, "description": "No cached verdict for this indicator"},
    },
)
def get_ioc_intel(
    ioc_value: str,
    db: Session = Depends(get_db),
    _: User = Depends(require(Permission.THREAT_INTEL_READ)),
    ioc_type: IOCType = Query(default=IOCType.IP, alias="type"),
) -> dict[str, Any]:
    try:
        indicator = validate(ioc_type.value, ioc_value)
    except InvalidIndicator as exc:
        return {
            "indicator": ioc_value,
            "indicatorType": ioc_type.value,
            "results": [],
            "notLookedUp": str(exc),
        }

    rows = list(
        db.scalars(
            select(ThreatIntelResult).where(
                ThreatIntelResult.ioc_type == ioc_type.value,
                ThreatIntelResult.ioc_value == indicator,
            )
        )
    )
    if not rows:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=(
                f"No threat intelligence has been looked up for {indicator}. "
                "Trigger enrichment to fetch it."
            ),
        )

    return {
        "indicator": indicator,
        "indicatorType": ioc_type.value,
        "results": [threat_intel_service.to_dict(row) for row in rows],
        "notLookedUp": None,
    }


@router.post(
    "/ioc/{ioc_value:path}/enrich",
    summary="Look up an indicator now",
    description=(
        "Contacts the configured provider (subject to cache, budget and rate limits) "
        "and stores the result. Analyst role required - this reaches outside the estate "
        "and spends quota. The lookup is audited.\n\n"
        "Private, loopback, link-local and reserved addresses are refused before any "
        "request is built: sending internal addressing to a third party leaks topology, "
        "and an unvalidated indicator in an outbound URL is an SSRF primitive."
    ),
    responses={
        400: {"model": Message, "description": "Indicator is malformed or out of scope"},
        503: {"model": Message, "description": "No provider configured"},
    },
)
def enrich_ioc(
    ioc_value: str,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(require(Permission.THREAT_INTEL_ENRICH)),
    ioc_type: IOCType = Query(default=IOCType.IP, alias="type"),
    force: bool = Query(default=False, description="Bypass the cache."),
) -> dict[str, Any]:
    try:
        indicator = validate(ioc_type.value, ioc_value)
    except InvalidIndicator as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)
        ) from exc

    known = ioc_repository.get_by_value(db, ioc_type.value, indicator)
    result = threat_intel_service.enrich_indicator(
        db, ioc_type.value, indicator, ioc=known, force=force
    )

    audit_service.record(
        db,
        action=AuditAction.THREAT_INTEL_LOOKUP,
        user=user,
        target_type="ioc",
        target_id=indicator,
        ip_address=client_ip(request),
        details={
            "type": ioc_type.value,
            "provider": threat_intel_service.get_provider().name,
            "forced": force,
            "outcome": result.status if result else "skipped",
        },
    )
    db.commit()

    if result is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=(
                "Threat intelligence is disabled, or this indicator type is not "
                "supported by the configured provider."
            ),
        )
    return threat_intel_service.to_dict(result)


@router.get(
    "",
    summary="Recent threat intelligence verdicts",
    description="Stored verdicts, newest first. No provider is contacted.",
)
def list_results(
    db: Session = Depends(get_db),
    _: User = Depends(require(Permission.THREAT_INTEL_READ)),
    reputation: str | None = Query(default=None, max_length=16),
    limit: int = Query(default=50, ge=1, le=200),
) -> dict[str, Any]:
    stmt = (
        select(ThreatIntelResult)
        .order_by(ThreatIntelResult.looked_up_at.desc())
        .limit(limit)
    )
    if reputation:
        stmt = stmt.where(ThreatIntelResult.reputation == reputation)

    rows = list(db.scalars(stmt))
    return {
        "results": [threat_intel_service.to_dict(row) for row in rows],
        "total": len(rows),
        "status": threat_intel_service.status(),
    }
