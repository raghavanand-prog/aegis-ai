"""Sysmon (Windows System Monitor).

The mapping below is the V6 implementation, moved rather than rewritten. Its
output is pinned by ``test_telemetry_normalizer_characterization.py``: this file
changing what the detection engine sees is a deliberate act, never a side effect
of the V7 refactor.
"""

from __future__ import annotations

from typing import Any

from app.models.enums import Severity, SourceType
from app.telemetry.adapters.base import TelemetryAdapter, candidate


def _normalize_sysmon(raw: dict[str, Any]) -> dict[str, Any]:
    event_id = int(raw.get("EventID", 0) or 0)
    image = raw.get("Image") or ""
    process_name = image.split("\\")[-1] if image else None

    if event_id == 10:
        source_image = raw.get("SourceImage") or ""
        return candidate(
            event_type="credential_access",
            title="Process accessed LSASS memory",
            description=(
                f"{source_image} opened {raw.get('TargetImage')} with access "
                f"{raw.get('GrantedAccess')} on {raw.get('Computer')}."
            ),
            severity=Severity.HIGH.value,
            hostname=raw.get("Computer"),
            username=raw.get("User"),
            process=source_image.split("\\")[-1] if source_image else None,
            normalized_data={
                "sysmon_event_id": event_id,
                "source_image": source_image,
                "target_image": raw.get("TargetImage"),
                "granted_access": raw.get("GrantedAccess"),
            },
        )

    command_line = raw.get("CommandLine")
    return candidate(
        event_type="process_creation",
        title=f"Process created: {process_name or 'unknown'}",
        description=f"{command_line} started by {raw.get('ParentImage')} on {raw.get('Computer')}.",
        severity=Severity.LOW.value,
        hostname=raw.get("Computer"),
        username=raw.get("User"),
        process=process_name,
        command_line=command_line,
        normalized_data={
            "sysmon_event_id": event_id,
            "parent_image": raw.get("ParentImage"),
            "process_id": raw.get("ProcessId"),
            "image": image,
        },
    )


class SysmonAdapter(TelemetryAdapter):
    name = "sysmon"
    source_names = ("Sysmon",)
    source_type = SourceType.ENDPOINT
    fallback_for = SourceType.ENDPOINT

    def parse(self, raw: dict[str, Any]):
        return self.from_candidate(_normalize_sysmon(raw))
