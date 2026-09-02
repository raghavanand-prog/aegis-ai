"""Null provider.

Used when no external provider is configured. It answers every lookup with
``unavailable`` and a reason, which is what the UI renders as "threat
intelligence is not configured" - an honest empty state rather than a blank
panel or, worse, an implied clean bill of health.
"""

from __future__ import annotations

from app.models.enums import ThreatIntelStatus
from app.threatintel.base import IntelLookup, ThreatIntelProvider


class NullProvider(ThreatIntelProvider):
    name = "none"
    supports = frozenset()

    @property
    def configured(self) -> bool:
        return False

    def lookup(self, ioc_type: str, value: str) -> IntelLookup:
        return IntelLookup.failed(
            self.name,
            ioc_type,
            value,
            ThreatIntelStatus.UNAVAILABLE,
            "No threat intelligence provider is configured (THREAT_INTEL_PROVIDER=none)",
        )
