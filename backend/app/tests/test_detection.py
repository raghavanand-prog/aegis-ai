"""Detection rule unit tests."""

from __future__ import annotations

from app.detection.rules import evaluate
from app.models.enums import Severity


def test_benign_event_matches_nothing() -> None:
    result = evaluate(
        {
            "event_type": "process_creation",
            "process": "chrome.exe",
            "command_line": "chrome.exe --profile-directory=Default",
            "normalized_data": {},
        }
    )
    assert not result.matched
    assert result.risk_score == 0
    assert result.severity == Severity.LOW.value


def test_encoded_powershell_is_flagged_high() -> None:
    result = evaluate(
        {
            "event_type": "process_creation",
            "process": "powershell.exe",
            "command_line": "powershell.exe -nop -w hidden -enc " + "A" * 64,
            "normalized_data": {},
        }
    )
    assert "DET-PS-001" in result.matched_rules
    assert result.severity == Severity.HIGH.value
    assert "T1059.001" in result.mitre_techniques


def test_lsass_access_is_critical() -> None:
    result = evaluate(
        {
            "event_type": "credential_access",
            "process": "procdump64.exe",
            "normalized_data": {"target_image": "C:\\Windows\\System32\\lsass.exe"},
        }
    )
    assert result.severity == Severity.CRITICAL.value
    assert "T1003.001" in result.mitre_techniques


def test_brute_force_needs_a_burst_not_a_single_failure() -> None:
    single = evaluate({"event_type": "auth_failure", "normalized_data": {"failure_count": 1}})
    burst = evaluate({"event_type": "auth_failure", "normalized_data": {"failure_count": 12}})
    assert not single.matched
    assert "DET-AUTH-001" in burst.matched_rules


def test_risk_score_is_capped() -> None:
    result = evaluate(
        {
            "event_type": "ransomware_behavior",
            "process": "powershell.exe",
            "command_line": "powershell.exe -enc " + "B" * 80,
            "normalized_data": {
                "target_image": "lsass.exe",
                "files_modified": 5000,
                "encryption_suspected": True,
                "bytes_out": 900_000_000,
            },
        }
    )
    assert result.risk_score == 100
    assert result.severity == Severity.CRITICAL.value


def test_a_broken_rule_cannot_drop_telemetry() -> None:
    """Malformed input must not raise out of the engine."""
    result = evaluate({"normalized_data": "not-a-dict", "command_line": None})
    assert result.severity == Severity.LOW.value
