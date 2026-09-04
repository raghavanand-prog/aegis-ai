"""Linux auditd / syslog authentication records.

The mapping below is the V6 implementation, moved rather than rewritten. Its
output is pinned by ``test_telemetry_normalizer_characterization.py``: this file
changing what the detection engine sees is a deliberate act, never a side effect
of the V7 refactor.
"""

from __future__ import annotations

from typing import Any

from app.models.enums import Severity, SourceType
from app.telemetry.adapters.base import TelemetryAdapter, candidate


def _normalize_linux(raw: dict[str, Any]) -> dict[str, Any]:
    if raw.get("facility") == "sudo":
        return candidate(
            event_type="privilege_escalation",
            title=f"Privileged command run by {raw.get('user')}",
            description=f"{raw.get('user')} executed {raw.get('command')} on {raw.get('host')}.",
            severity=Severity.MEDIUM.value,
            hostname=raw.get("host"),
            username=raw.get("user"),
            process="sudo",
            command_line=raw.get("command"),
            normalized_data={
                "facility": "sudo",
                "privilege_change": bool(raw.get("privilege_change")),
                "result": raw.get("result"),
            },
        )

    return candidate(
        event_type="auth_success",
        title=f"SSH login accepted for {raw.get('user')}",
        description=(
            f"{raw.get('auth_method')} authentication from {raw.get('src_ip')} on {raw.get('host')}."
        ),
        severity=Severity.LOW.value,
        hostname=raw.get("host"),
        username=raw.get("user"),
        source_ip=raw.get("src_ip"),
        process="sshd",
        normalized_data={
            "facility": "sshd",
            "auth_method": raw.get("auth_method"),
            "result": raw.get("result"),
        },
    )


class LinuxAdapter(TelemetryAdapter):
    name = "linux"
    source_names = ("Linux Auditd",)
    source_type = SourceType.OPERATING_SYSTEM
    fallback_for = SourceType.OPERATING_SYSTEM

    def parse(self, raw: dict[str, Any]):
        return self.from_candidate(_normalize_linux(raw))
