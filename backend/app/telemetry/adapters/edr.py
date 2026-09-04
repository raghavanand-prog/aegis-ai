"""Generic EDR agent detections.

The mapping below is the V6 implementation, moved rather than rewritten. Its
output is pinned by ``test_telemetry_normalizer_characterization.py``: this file
changing what the detection engine sees is a deliberate act, never a side effect
of the V7 refactor.
"""

from __future__ import annotations

from typing import Any

from app.models.enums import Severity, SourceType
from app.telemetry.adapters.base import TelemetryAdapter, candidate, ioc

#: Outbound volume (bytes) at which an EDR transfer record is treated as an
#: exfiltration-shaped event. Matches the detection engine's own threshold.
EDR_EXFIL_BYTES = 500_000_000


def _edr_event_type(raw: dict[str, Any]) -> str:
    """Classify an EDR record from what it reports, not by elimination.

    Regression guard: this used to be a two-way branch that labelled every
    non-ransomware EDR record as ``data_exfiltration``, which handed the
    detection engine a pre-cooked verdict for benign file activity.
    """
    if raw.get("encryption_suspected"):
        return "ransomware_behavior"

    tactic = str(raw.get("tactic", "") or "").lower()
    bytes_out = raw.get("bytes_out") or 0
    try:
        bytes_out = int(bytes_out)
    except (TypeError, ValueError):
        bytes_out = 0

    if tactic == "exfiltration" or bytes_out >= EDR_EXFIL_BYTES:
        return "data_exfiltration"
    return "edr_detection"


def _normalize_edr(raw: dict[str, Any]) -> dict[str, Any]:
    technique = raw.get("technique")
    event_type = _edr_event_type(raw)
    is_ransomware = event_type == "ransomware_behavior"
    process = (raw.get("process") or "").split("\\")[-1] or None

    vendor_severity = str(raw.get("severity", "") or "").capitalize()
    if is_ransomware:
        severity = Severity.CRITICAL.value
    elif event_type == "data_exfiltration":
        severity = Severity.HIGH.value
    elif vendor_severity in {s.value for s in Severity}:
        severity = vendor_severity
    else:
        severity = Severity.LOW.value

    return candidate(
        event_type=event_type,
        title=raw.get("detection_name", "EDR detection"),
        description=(
            f"{raw.get('detection_name')} on {raw.get('hostname')} "
            f"({raw.get('tactic')} / {technique})."
        ),
        severity=severity,
        hostname=raw.get("hostname"),
        username=raw.get("user"),
        process=process,
        command_line=raw.get("command_line"),
        destination_ip=raw.get("dst_ip"),
        mitre_techniques=[technique] if technique else [],
        normalized_data={
            "detection_name": raw.get("detection_name"),
            "tactic": raw.get("tactic"),
            "files_modified": raw.get("files_modified", 0),
            "encryption_suspected": is_ransomware,
            "bytes_out": raw.get("bytes_out", 0),
            "vendor_severity": raw.get("severity"),
        },
        iocs=[ioc for ioc in [ioc("ip", raw.get("dst_ip"))] if ioc],
    )


class EdrAdapter(TelemetryAdapter):
    name = "edr"
    source_names = ("EDR Agent",)
    source_type = SourceType.EDR
    fallback_for = SourceType.EDR

    def parse(self, raw: dict[str, Any]):
        return self.from_candidate(_normalize_edr(raw))
