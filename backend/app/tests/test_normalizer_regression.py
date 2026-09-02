"""Regression tests for normalization defects found by measurement.

Each test here exists because a specific bug reached the detection engine.
"""

from __future__ import annotations

from app.detection import evaluate
from app.models.enums import Severity, SourceType
from app.telemetry.base import RawTelemetry
from app.telemetry.normalizer import normalize


def _edr_record(raw: dict) -> RawTelemetry:
    return RawTelemetry(
        source="EDR Agent", source_type=SourceType.EDR, raw=raw, raw_log="[EDR] test"
    )


def test_benign_edr_file_activity_is_not_labelled_exfiltration() -> None:
    """Found by the V2 detection evaluation.

    The EDR normalizer used to label every non-ransomware record as
    ``data_exfiltration``. A backup agent writing files therefore arrived at the
    detection engine pre-labelled as exfiltration and DET-EXFIL-001 fired on it:
    72 false positives on the evaluation set and 45% rule precision.
    """
    candidate = normalize(
        _edr_record(
            {
                "detection_name": "FileActivity.BulkWrite",
                "hostname": "EVAL-WIN-001",
                "user": "svc.backup",
                "process": "C:\\Program Files\\backup\\agent.exe",
                "files_modified": 150,
                "encryption_suspected": False,
                "tactic": "None",
                "severity": "Low",
            }
        )
    )

    assert candidate["event_type"] == "edr_detection"
    assert candidate["severity"] == Severity.LOW.value
    assert not evaluate(candidate, base_severity=candidate["severity"]).matched


def test_edr_exfiltration_is_still_recognised() -> None:
    candidate = normalize(
        _edr_record(
            {
                "detection_name": "Exfiltration.LargeOutboundTransfer",
                "hostname": "EVAL-WIN-002",
                "user": "j.smith",
                "process": "C:\\Windows\\System32\\certutil.exe",
                "bytes_out": 2_000_000_000,
                "dst_ip": "203.0.113.4",
                "tactic": "Exfiltration",
                "technique": "T1041",
                "severity": "High",
            }
        )
    )

    assert candidate["event_type"] == "data_exfiltration"
    result = evaluate(candidate, base_severity=candidate["severity"])
    assert "DET-EXFIL-001" in result.matched_rules


def test_edr_ransomware_is_still_recognised() -> None:
    candidate = normalize(
        _edr_record(
            {
                "detection_name": "Ransomware.Behavioral.MassEncryption",
                "hostname": "EVAL-WIN-003",
                "user": "a.sharma",
                "process": "C:\\Users\\Public\\svchost.exe",
                "files_modified": 4000,
                "encryption_suspected": True,
                "tactic": "Impact",
                "technique": "T1486",
                "severity": "Critical",
            }
        )
    )

    assert candidate["event_type"] == "ransomware_behavior"
    result = evaluate(candidate, base_severity=candidate["severity"])
    assert "DET-RANSOM-001" in result.matched_rules
    assert result.severity == Severity.CRITICAL.value
