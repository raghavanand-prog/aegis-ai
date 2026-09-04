"""Microsoft Defender for Endpoint.

The mapping below is the V6 implementation, moved rather than rewritten. Its
output is pinned by ``test_telemetry_normalizer_characterization.py``: this file
changing what the detection engine sees is a deliberate act, never a side effect
of the V7 refactor.
"""

from __future__ import annotations

from typing import Any

from app.models.enums import Severity, SourceType
from app.telemetry.adapters.base import TelemetryAdapter, candidate, ioc


def _normalize_defender(raw: dict[str, Any]) -> dict[str, Any]:
    action = raw.get("ActionType", "")
    if action == "AntivirusDetection":
        threat = raw.get("ThreatName", "Unknown threat")
        return candidate(
            event_type="malware_detected",
            title=f"Malware detected: {threat}",
            description=(
                f"{threat} found in {raw.get('FileName')} on {raw.get('DeviceName')}; "
                f"action taken: {raw.get('RemediationAction')}."
            ),
            severity=Severity.HIGH.value,
            hostname=raw.get("DeviceName"),
            username=raw.get("AccountName"),
            process=raw.get("InitiatingProcessFileName"),
            normalized_data={
                "threat_name": threat,
                "file_name": raw.get("FileName"),
                "sha256": raw.get("SHA256"),
                "remediation": raw.get("RemediationAction"),
                "vendor_severity": raw.get("Severity"),
            },
            iocs=[ioc for ioc in [ioc("hash", raw.get("SHA256"))] if ioc],
        )

    return candidate(
        event_type="antivirus_scan",
        title="Antivirus scan completed",
        description=(
            f"{raw.get('ScanType')} scan on {raw.get('DeviceName')} covered "
            f"{raw.get('FilesScanned')} files with {raw.get('ThreatsFound', 0)} detections."
        ),
        severity=Severity.LOW.value,
        hostname=raw.get("DeviceName"),
        normalized_data={
            "scan_type": raw.get("ScanType"),
            "files_scanned": raw.get("FilesScanned"),
            "threats_found": raw.get("ThreatsFound", 0),
        },
    )


class DefenderAdapter(TelemetryAdapter):
    name = "defender"
    source_names = ("Microsoft Defender",)
    source_type = SourceType.ENDPOINT

    def parse(self, raw: dict[str, Any]):
        return self.from_candidate(_normalize_defender(raw))
