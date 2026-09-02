"""Threat intelligence provider abstraction.

The platform talks to providers through this interface and nothing else. There
is no VirusTotal-shaped field anywhere in the models, the services or the API:
adding AbuseIPDB, GreyNoise or NVD later means writing one class, not editing
the pipeline.

Every provider must satisfy three contracts:

1. **It never raises into the caller.** A lookup returns a
   :class:`IntelLookup` whose ``status`` says what happened - ``ok``,
   ``not_found``, ``timeout``, ``rate_limited``, ``error``, ``unavailable``.
   Threat intelligence is enrichment; it must never be able to stop an event
   being ingested.
2. **A failure is never reported as a clean verdict.** ``unknown`` reputation
   with an error status means "we could not find out", which is a completely
   different fact from "this indicator is harmless".
3. **It never returns the API key, and never logs it.**
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from app.models.enums import ThreatIntelReputation, ThreatIntelStatus

#: Indicator kinds a provider may be asked about. Anything else is refused
#: before a request is built - an allowlist, because the indicator value ends
#: up in an outbound URL.
SUPPORTED_IOC_TYPES = frozenset({"ip", "domain", "url", "hash"})


@dataclass
class IntelLookup:
    """The outcome of one provider lookup for one indicator."""

    provider: str
    ioc_type: str
    ioc_value: str
    status: ThreatIntelStatus
    reputation: ThreatIntelReputation = ThreatIntelReputation.UNKNOWN
    confidence: int = 0
    malicious_count: int = 0
    suspicious_count: int = 0
    harmless_count: int = 0
    undetected_count: int = 0
    last_analysis_at: datetime | None = None
    error: str | None = None
    details: dict[str, Any] = field(default_factory=dict)

    @property
    def is_actionable(self) -> bool:
        return self.status is ThreatIntelStatus.OK

    @classmethod
    def failed(
        cls,
        provider: str,
        ioc_type: str,
        ioc_value: str,
        status: ThreatIntelStatus,
        error: str | None = None,
    ) -> IntelLookup:
        """A lookup that produced no verdict. Reputation stays ``unknown``."""
        return cls(
            provider=provider,
            ioc_type=ioc_type,
            ioc_value=ioc_value,
            status=status,
            reputation=ThreatIntelReputation.UNKNOWN,
            error=error,
        )


class ThreatIntelProvider(ABC):
    """One external reputation source."""

    #: Stable identifier stored on every cached result.
    name: str = "unknown"
    #: Indicator kinds this provider can answer for.
    supports: frozenset[str] = SUPPORTED_IOC_TYPES

    @abstractmethod
    def lookup(self, ioc_type: str, value: str) -> IntelLookup:
        """Return a verdict for one indicator. Must not raise."""

    @property
    def configured(self) -> bool:
        """True when the provider has everything it needs to answer."""
        return True

    def health(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "configured": self.configured,
            "supports": sorted(self.supports),
        }
