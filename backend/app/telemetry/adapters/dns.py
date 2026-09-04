"""Recursive DNS resolver query logs.

The mapping below is the V6 implementation, moved rather than rewritten. Its
output is pinned by ``test_telemetry_normalizer_characterization.py``: this file
changing what the detection engine sees is a deliberate act, never a side effect
of the V7 refactor.
"""

from __future__ import annotations

from typing import Any

from app.models.enums import Severity, SourceType
from app.telemetry.adapters.base import TelemetryAdapter, candidate, ioc


def _normalize_dns(raw: dict[str, Any]) -> dict[str, Any]:
    domain = raw.get("query")
    periodic = bool(raw.get("periodic"))
    return candidate(
        event_type="dns_query",
        title=f"DNS {raw.get('query_type')} query for {domain}",
        description=(
            f"{raw.get('client_ip')} resolved {domain} ({raw.get('response_code')})."
            + (f" {raw.get('query_count')} queries at a fixed interval." if periodic else "")
        ),
        severity=Severity.MEDIUM.value if periodic else Severity.LOW.value,
        source_ip=raw.get("client_ip"),
        destination_ip=raw.get("resolved_ip"),
        normalized_data={
            "query": domain,
            "query_type": raw.get("query_type"),
            "response_code": raw.get("response_code"),
            "query_count": raw.get("query_count", 0),
            "periodic": periodic,
            "interval_seconds": raw.get("interval_seconds"),
        },
        iocs=[ioc for ioc in [ioc("domain", domain if periodic else None)] if ioc],
    )


class DnsAdapter(TelemetryAdapter):
    name = "dns"
    source_names = ("DNS Resolver",)
    source_type = SourceType.DNS
    fallback_for = SourceType.DNS

    def parse(self, raw: dict[str, Any]):
        return self.from_candidate(_normalize_dns(raw))
