"""Perimeter firewall connection logs.

The mapping below is the V6 implementation, moved rather than rewritten. Its
output is pinned by ``test_telemetry_normalizer_characterization.py``: this file
changing what the detection engine sees is a deliberate act, never a side effect
of the V7 refactor.
"""

from __future__ import annotations

from typing import Any

from app.models.enums import Severity, SourceType
from app.telemetry.adapters.base import TelemetryAdapter, candidate, ioc


def _normalize_firewall(raw: dict[str, Any]) -> dict[str, Any]:
    if raw.get("action") == "deny":
        ports = int(raw.get("distinct_ports", 0) or 0)
        return candidate(
            event_type="firewall_deny",
            title=f"Blocked connections from {raw.get('src_ip')}",
            description=(
                f"{raw.get('deny_count')} denied {raw.get('protocol')} connections across "
                f"{ports} ports towards {raw.get('dst_ip')}."
            ),
            severity=Severity.MEDIUM.value if ports >= 20 else Severity.LOW.value,
            source_ip=raw.get("src_ip"),
            destination_ip=raw.get("dst_ip"),
            destination_port=raw.get("dst_port"),
            normalized_data={
                "action": "deny",
                "protocol": raw.get("protocol"),
                "distinct_ports": ports,
                "deny_count": raw.get("deny_count"),
                "rule": raw.get("rule"),
            },
            iocs=[ioc for ioc in [ioc("ip", raw.get("src_ip"))] if ioc],
        )

    return candidate(
        event_type="firewall_allow",
        title=f"Outbound connection to {raw.get('dst_ip')}",
        description=(
            f"{raw.get('protocol')} {raw.get('src_ip')} -> {raw.get('dst_ip')}:"
            f"{raw.get('dst_port')} permitted by {raw.get('rule')}."
        ),
        severity=Severity.LOW.value,
        source_ip=raw.get("src_ip"),
        destination_ip=raw.get("dst_ip"),
        destination_port=raw.get("dst_port"),
        normalized_data={
            "action": "allow",
            "protocol": raw.get("protocol"),
            "bytes_out": raw.get("bytes_out"),
            "rule": raw.get("rule"),
        },
    )


class FirewallAdapter(TelemetryAdapter):
    name = "firewall"
    source_names = ("Perimeter Firewall",)
    source_type = SourceType.FIREWALL
    fallback_for = SourceType.FIREWALL

    def parse(self, raw: dict[str, Any]):
        return self.from_candidate(_normalize_firewall(raw))
