"""VirusTotal provider.

The API key is read from configuration on the server and sent in a request
header. It is never returned by any endpoint, never logged, and never reaches
the browser - the frontend talks only to the AEGISX backend, which is what
keeps the key out of a bundle anyone can read.

Failure handling is the substance of this class:

* HTTP 404  -> ``not_found``. VirusTotal has no record; that is information,
  not an error, and it is not the same as "harmless".
* HTTP 429  -> ``rate_limited``. The free tier allows four lookups a minute,
  which any real SOC stream will exceed immediately.
* timeout   -> ``timeout``
* anything else -> ``error``

Every one of those returns a result object. Nothing raises into the caller.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any
from urllib.parse import quote

from app.core.config import settings
from app.models.enums import ThreatIntelReputation, ThreatIntelStatus
from app.threatintel.base import IntelLookup, ThreatIntelProvider
from app.threatintel.validation import InvalidIndicator, validate

logger = logging.getLogger(__name__)

API_ROOT = "https://www.virustotal.com/api/v3"

#: How the indicator type maps onto a VirusTotal collection.
_COLLECTIONS = {
    "ip": "ip_addresses",
    "domain": "domains",
    "hash": "files",
    "url": "urls",
}

#: A single vendor flagging something is noise; a handful agreeing is a signal.
MALICIOUS_THRESHOLD = 3
SUSPICIOUS_THRESHOLD = 1


class VirusTotalProvider(ThreatIntelProvider):
    name = "virustotal"
    supports = frozenset({"ip", "domain", "hash", "url"})

    def __init__(self, api_key: str | None = None, timeout: float | None = None) -> None:
        self._api_key = api_key if api_key is not None else settings.virustotal_api_key
        self._timeout = timeout if timeout is not None else settings.threat_intel_timeout_seconds

    @property
    def configured(self) -> bool:
        return bool(self._api_key)

    # ------------------------------------------------------------------ lookup
    def lookup(self, ioc_type: str, value: str) -> IntelLookup:
        if not self.configured:
            return IntelLookup.failed(
                self.name,
                ioc_type,
                value,
                ThreatIntelStatus.UNAVAILABLE,
                "VIRUSTOTAL_API_KEY is not configured",
            )

        collection = _COLLECTIONS.get(ioc_type.lower())
        if collection is None:
            return IntelLookup.failed(
                self.name,
                ioc_type,
                value,
                ThreatIntelStatus.UNAVAILABLE,
                f"{ioc_type} is not supported by this provider",
            )

        try:
            indicator = validate(ioc_type, value)
        except InvalidIndicator as exc:
            # Refused before any request is built - see threatintel/validation.py.
            return IntelLookup.failed(
                self.name, ioc_type, value, ThreatIntelStatus.ERROR, str(exc)
            )

        try:
            import httpx
        except ImportError:  # pragma: no cover - httpx ships with the backend
            return IntelLookup.failed(
                self.name, ioc_type, indicator, ThreatIntelStatus.UNAVAILABLE, "httpx is not installed"
            )

        # URLs are addressed by a base64url digest of the URL itself.
        resource = indicator
        if ioc_type.lower() == "url":
            import base64

            resource = base64.urlsafe_b64encode(indicator.encode()).decode().strip("=")

        url = f"{API_ROOT}/{collection}/{quote(resource, safe='')}"

        try:
            with httpx.Client(
                timeout=self._timeout,
                # Redirects are refused: following one would let a response
                # steer the client at an address validation already rejected.
                follow_redirects=False,
            ) as client:
                response = client.get(url, headers={"x-apikey": self._api_key})
        except httpx.TimeoutException:
            logger.warning("VirusTotal lookup timed out for a %s indicator", ioc_type)
            return IntelLookup.failed(
                self.name, ioc_type, indicator, ThreatIntelStatus.TIMEOUT, "Provider timed out"
            )
        except Exception as exc:  # noqa: BLE001 - enrichment never breaks ingestion
            logger.warning("VirusTotal lookup failed: %s", type(exc).__name__)
            return IntelLookup.failed(
                self.name, ioc_type, indicator, ThreatIntelStatus.ERROR, type(exc).__name__
            )

        if response.status_code == 404:
            return IntelLookup(
                provider=self.name,
                ioc_type=ioc_type,
                ioc_value=indicator,
                status=ThreatIntelStatus.NOT_FOUND,
                reputation=ThreatIntelReputation.UNKNOWN,
                details={"httpStatus": 404},
            )
        if response.status_code == 429:
            return IntelLookup.failed(
                self.name,
                ioc_type,
                indicator,
                ThreatIntelStatus.RATE_LIMITED,
                "Provider rate limit reached",
            )
        if response.status_code in (401, 403):
            return IntelLookup.failed(
                self.name,
                ioc_type,
                indicator,
                ThreatIntelStatus.ERROR,
                # Deliberately vague: never echo the key or its prefix.
                "Provider rejected the configured credentials",
            )
        if response.status_code >= 400:
            return IntelLookup.failed(
                self.name,
                ioc_type,
                indicator,
                ThreatIntelStatus.ERROR,
                f"Provider returned HTTP {response.status_code}",
            )

        try:
            payload = response.json()
        except ValueError:
            return IntelLookup.failed(
                self.name, ioc_type, indicator, ThreatIntelStatus.ERROR, "Malformed provider response"
            )

        return self._parse(ioc_type, indicator, payload)

    # ------------------------------------------------------------------ parse
    def _parse(self, ioc_type: str, indicator: str, payload: dict[str, Any]) -> IntelLookup:
        attributes = ((payload or {}).get("data") or {}).get("attributes") or {}
        stats = attributes.get("last_analysis_stats") or {}

        malicious = int(stats.get("malicious", 0) or 0)
        suspicious = int(stats.get("suspicious", 0) or 0)
        harmless = int(stats.get("harmless", 0) or 0)
        undetected = int(stats.get("undetected", 0) or 0)
        total = malicious + suspicious + harmless + undetected

        if malicious >= MALICIOUS_THRESHOLD:
            reputation = ThreatIntelReputation.MALICIOUS
        elif malicious + suspicious >= SUSPICIOUS_THRESHOLD:
            reputation = ThreatIntelReputation.SUSPICIOUS
        elif total > 0:
            reputation = ThreatIntelReputation.HARMLESS
        else:
            # No engine has an opinion. Saying "harmless" here would invent a
            # verdict nobody gave.
            reputation = ThreatIntelReputation.UNKNOWN

        # Share of engines that flagged it. Provider agreement, not a
        # probability that the indicator is malicious.
        confidence = int(round(100 * (malicious + suspicious) / total)) if total else 0

        last_analysis = attributes.get("last_analysis_date")
        analysed_at = None
        if isinstance(last_analysis, (int, float)):
            analysed_at = datetime.fromtimestamp(last_analysis, tz=timezone.utc)

        return IntelLookup(
            provider=self.name,
            ioc_type=ioc_type,
            ioc_value=indicator,
            status=ThreatIntelStatus.OK,
            reputation=reputation,
            confidence=confidence,
            malicious_count=malicious,
            suspicious_count=suspicious,
            harmless_count=harmless,
            undetected_count=undetected,
            last_analysis_at=analysed_at,
            # A trimmed subset. The full body echoes submitted content back and
            # can be large; neither belongs in our database.
            details={
                "engines": total,
                "reputationScore": attributes.get("reputation"),
                "categories": sorted(
                    {str(v) for v in (attributes.get("categories") or {}).values()}
                )[:8],
                "country": attributes.get("country"),
                "asOwner": attributes.get("as_owner"),
                "meaningfulName": attributes.get("meaningful_name"),
            },
        )
