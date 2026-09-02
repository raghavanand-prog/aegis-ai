"""Threat intelligence enrichment.

    indicator -> validate -> cache? -> budget? -> provider -> store -> attach

Caching is not an optimisation here, it is a correctness requirement. Reputation
services rate-limit aggressively (VirusTotal's free tier allows four requests a
minute), a busy SOC stream produces the same handful of indicators over and
over, and every avoided request is one that cannot fail.

Cache entries carry the outcome, not just the verdict, and their lifetime
depends on it: a real answer is reused for the configured TTL, while a timeout
or a rate limit is retried after a short backoff. Caching a failure for a day
would turn a thirty-second provider blip into a day of missing enrichment.
"""

from __future__ import annotations

import logging
import threading
from datetime import date, datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.models.enums import ThreatIntelReputation, ThreatIntelStatus
from app.models.ioc import IOC
from app.models.threat_intel import ThreatIntelResult
from app.threatintel.base import IntelLookup, ThreatIntelProvider
from app.threatintel.providers.null import NullProvider
from app.threatintel.providers.virustotal import VirusTotalProvider
from app.threatintel.validation import InvalidIndicator, validate

logger = logging.getLogger(__name__)


def _iso(value) -> str | None:  # noqa: ANN001 - datetime | None
    """UTC-stamped ISO string, or None. See app.schemas.common.as_utc."""
    from app.schemas.common import as_utc

    stamped = as_utc(value)
    return stamped.isoformat() if stamped else None

#: How long a *failed* lookup is remembered before another attempt is made.
#: Short on purpose - a provider outage should self-heal within minutes.
FAILURE_RETRY_MINUTES = 15

_PROVIDERS: dict[str, type[ThreatIntelProvider]] = {
    "virustotal": VirusTotalProvider,
    "none": NullProvider,
}


class _Budget:
    """Per-process daily cap on outbound lookups.

    A runaway enrichment loop against a metered API is a real way to lose money
    and get an account suspended, so the ceiling is enforced here rather than
    trusted to the provider's own limits.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._day: date | None = None
        self._used = 0

    def take(self, limit: int) -> bool:
        today = datetime.now(timezone.utc).date()
        with self._lock:
            if self._day != today:
                self._day = today
                self._used = 0
            if self._used >= limit:
                return False
            self._used += 1
            return True

    def snapshot(self, limit: int) -> dict[str, int | str | None]:
        with self._lock:
            return {
                "day": self._day.isoformat() if self._day else None,
                "used": self._used,
                "limit": limit,
                "remaining": max(limit - self._used, 0),
            }


_budget = _Budget()
_provider_lock = threading.Lock()
_provider: ThreatIntelProvider | None = None
#: The configuration value the cached provider was built from. Compared against
#: settings rather than comparing the provider's own name, so an explicitly
#: installed provider is not thrown away for "not matching the config".
_provider_source: str | None = None
#: True when a provider was installed explicitly rather than derived from
#: configuration. Pinned providers are never rebuilt.
_provider_pinned = False


def get_provider() -> ThreatIntelProvider:
    """The configured provider, built once per process."""
    global _provider, _provider_source
    with _provider_lock:
        if _provider_pinned and _provider is not None:
            return _provider
        if _provider is None or _provider_source != settings.threat_intel_provider:
            factory = _PROVIDERS.get(settings.threat_intel_provider, NullProvider)
            _provider = factory()
            _provider_source = settings.threat_intel_provider
        return _provider


def reset_provider() -> None:
    """Drop the cached provider, pinned or not. Used by tests."""
    global _provider, _provider_source, _provider_pinned
    with _provider_lock:
        _provider = None
        _provider_source = None
        _provider_pinned = False


def set_provider(provider: ThreatIntelProvider | None) -> None:
    """Install a provider explicitly. Used by tests; not reachable from the API."""
    global _provider, _provider_pinned, _provider_source
    with _provider_lock:
        _provider = provider
        _provider_pinned = provider is not None
        _provider_source = provider.name if provider is not None else None


# --------------------------------------------------------------------------- cache
def cached_result(
    db: Session, provider: str, ioc_type: str, value: str
) -> ThreatIntelResult | None:
    return db.scalar(
        select(ThreatIntelResult).where(
            ThreatIntelResult.provider == provider,
            ThreatIntelResult.ioc_type == ioc_type,
            ThreatIntelResult.ioc_value == value,
        )
    )


def _is_fresh(result: ThreatIntelResult, now: datetime) -> bool:
    if result.expires_at is None:
        return False
    expires = result.expires_at
    if expires.tzinfo is None:
        expires = expires.replace(tzinfo=timezone.utc)
    return expires > now


def _ttl_for(status: ThreatIntelStatus) -> timedelta:
    if status in {ThreatIntelStatus.OK, ThreatIntelStatus.NOT_FOUND}:
        return timedelta(hours=settings.threat_intel_cache_ttl_hours)
    return timedelta(minutes=FAILURE_RETRY_MINUTES)


def _persist(
    db: Session, lookup: IntelLookup, *, ioc: IOC | None, now: datetime
) -> ThreatIntelResult:
    result = cached_result(db, lookup.provider, lookup.ioc_type, lookup.ioc_value)
    if result is None:
        result = ThreatIntelResult(
            provider=lookup.provider,
            ioc_type=lookup.ioc_type,
            ioc_value=lookup.ioc_value,
        )
        db.add(result)

    result.ioc_id = ioc.id if ioc is not None else result.ioc_id
    result.status = lookup.status.value
    result.reputation = lookup.reputation.value
    result.confidence = max(0, min(int(lookup.confidence), 100))
    result.malicious_count = lookup.malicious_count
    result.suspicious_count = lookup.suspicious_count
    result.harmless_count = lookup.harmless_count
    result.undetected_count = lookup.undetected_count
    result.last_analysis_at = lookup.last_analysis_at
    result.looked_up_at = now
    result.expires_at = now + _ttl_for(lookup.status)
    result.error = lookup.error
    result.details = lookup.details or {}
    db.flush()
    return result


# --------------------------------------------------------------------------- API
def enrich_indicator(
    db: Session,
    ioc_type: str,
    value: str,
    *,
    ioc: IOC | None = None,
    force: bool = False,
) -> ThreatIntelResult | None:
    """Look up one indicator, using the cache unless ``force`` is set.

    Returns ``None`` only when the indicator is one AEGISX will not send
    externally at all (an internal address, a malformed value, an unsupported
    type). Every other outcome - including every kind of failure - is a stored,
    inspectable row.
    """
    if not settings.threat_intel_enabled:
        return None

    provider = get_provider()
    now = datetime.now(timezone.utc)

    try:
        indicator = validate(ioc_type, value)
    except InvalidIndicator as exc:
        # Not an error worth a row: these indicators are simply out of scope.
        logger.debug("Skipping threat intel lookup: %s", exc)
        return None

    if ioc_type not in provider.supports:
        return None

    existing = cached_result(db, provider.name, ioc_type, indicator)
    if existing is not None and not force and _is_fresh(existing, now):
        return existing

    if not provider.configured:
        return _persist(
            db,
            IntelLookup.failed(
                provider.name,
                ioc_type,
                indicator,
                ThreatIntelStatus.UNAVAILABLE,
                f"{provider.name} is not configured",
            ),
            ioc=ioc,
            now=now,
        )

    if not _budget.take(settings.threat_intel_daily_budget):
        logger.warning("Threat intelligence daily budget exhausted; serving stale or none")
        if existing is not None:
            return existing
        return _persist(
            db,
            IntelLookup.failed(
                provider.name,
                ioc_type,
                indicator,
                ThreatIntelStatus.RATE_LIMITED,
                "AEGISX daily lookup budget exhausted",
            ),
            ioc=ioc,
            now=now,
        )

    lookup = provider.lookup(ioc_type, indicator)
    result = _persist(db, lookup, ioc=ioc, now=now)

    if lookup.reputation is ThreatIntelReputation.MALICIOUS and ioc is not None:
        # An external malicious verdict is worth reflecting on the indicator
        # itself, where the IOC views already read from.
        ioc.severity = "Critical"
        ioc.confidence = max(ioc.confidence, min(lookup.confidence or 80, 95))
        db.flush()

    return result


def enrich_iocs(db: Session, iocs: list[IOC], *, force: bool = False) -> list[ThreatIntelResult]:
    """Enrich a batch of indicators, skipping anything out of scope."""
    results: list[ThreatIntelResult] = []
    for ioc in iocs:
        result = enrich_indicator(db, ioc.type, ioc.value, ioc=ioc, force=force)
        if result is not None:
            results.append(result)
    return results


def results_for_values(
    db: Session, pairs: list[tuple[str, str]]
) -> dict[tuple[str, str], ThreatIntelResult]:
    """Cached verdicts for (type, value) pairs, without triggering lookups."""
    if not pairs:
        return {}
    values = [value for _, value in pairs]
    rows = db.scalars(
        select(ThreatIntelResult).where(ThreatIntelResult.ioc_value.in_(values))
    )
    return {(row.ioc_type, row.ioc_value): row for row in rows}


def to_dict(result: ThreatIntelResult) -> dict:
    return {
        "provider": result.provider,
        "iocType": result.ioc_type,
        "iocValue": result.ioc_value,
        "status": result.status,
        "reputation": result.reputation,
        "confidence": result.confidence,
        "maliciousCount": result.malicious_count,
        "suspiciousCount": result.suspicious_count,
        "harmlessCount": result.harmless_count,
        "undetectedCount": result.undetected_count,
        "lastAnalysisAt": _iso(result.last_analysis_at),
        "lookedUpAt": _iso(result.looked_up_at),
        "expiresAt": _iso(result.expires_at),
        "error": result.error,
        "details": result.details or {},
        "isActionable": result.is_actionable,
    }


def status() -> dict:
    """Enrichment health, for /health and the settings surface."""
    provider = get_provider()
    return {
        "enabled": settings.threat_intel_enabled,
        "provider": provider.name,
        "configured": provider.configured,
        "supports": sorted(provider.supports),
        "cacheTtlHours": settings.threat_intel_cache_ttl_hours,
        "failureRetryMinutes": FAILURE_RETRY_MINUTES,
        "budget": _budget.snapshot(settings.threat_intel_daily_budget),
    }
