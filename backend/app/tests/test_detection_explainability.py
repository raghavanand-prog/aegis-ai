"""Rule identity, versioning and explainability (V2)."""

from __future__ import annotations

from app.detection import LEGACY_RULE_IDS, RULES, RULES_BY_ID, catalogue, evaluate
from app.models.enums import Severity


def test_every_rule_has_a_stable_id_and_version() -> None:
    ids = [rule.id for rule in RULES]
    assert len(ids) == len(set(ids)), "rule ids must be unique"
    for rule in RULES:
        assert rule.id.startswith("DET-")
        assert rule.version
        assert rule.labels, f"{rule.id} must declare the labels it targets"
        assert rule.description


def test_v1_rule_ids_still_resolve() -> None:
    """Detections stored before the V2 rename must stay interpretable."""
    assert LEGACY_RULE_IDS["AEGIS-R002"] == "DET-PS-001"
    assert LEGACY_RULE_IDS["AEGIS-R005"] == "DET-CRED-001"
    assert len(LEGACY_RULE_IDS) == len(RULES)
    for legacy_id, new_id in LEGACY_RULE_IDS.items():
        assert new_id in RULES_BY_ID, f"{legacy_id} maps to an unknown rule"


def test_detection_explains_itself() -> None:
    result = evaluate(
        {
            "event_type": "process_creation",
            "process": "powershell.exe",
            "command_line": "powershell.exe -nop -w hidden -enc " + "A" * 80,
            "normalized_data": {},
        }
    )

    assert len(result.detections) == 1
    detection = result.detections[0]

    assert detection.rule_id == "DET-PS-001"
    assert detection.rule_version == "1.0"
    assert detection.rule_name == "Suspicious PowerShell"
    assert "encoded" in detection.reason.lower()
    assert detection.severity == Severity.HIGH.value
    assert detection.risk_contribution == 50
    assert detection.mitre_techniques == ["T1059.001", "T1027"]
    assert detection.matched_at


def test_reason_quotes_the_evidence_that_triggered_the_rule() -> None:
    result = evaluate(
        {
            "event_type": "auth_failure",
            "username": "j.smith",
            "source_ip": "203.0.113.9",
            "normalized_data": {"failure_count": 41},
        }
    )
    reason = result.detections[0].reason
    assert "41" in reason
    assert "j.smith" in reason
    assert "203.0.113.9" in reason


def test_detections_serialize_for_storage_and_api() -> None:
    result = evaluate(
        {
            "event_type": "credential_access",
            "process": "procdump64.exe",
            "normalized_data": {"target_image": "lsass.exe", "granted_access": "0x1010"},
        }
    )
    payload = result.detections_as_dicts()[0]

    assert set(payload) == {
        "ruleId",
        "ruleVersion",
        "ruleName",
        "reason",
        "severity",
        "riskContribution",
        "mitreTechniques",
        "matchedAt",
    }


def test_catalogue_is_machine_readable() -> None:
    entries = catalogue()
    assert len(entries) == len(RULES)
    powershell = next(entry for entry in entries if entry["id"] == "DET-PS-001")
    assert powershell["legacyId"] == "AEGIS-R002"
    assert powershell["mitreTechniques"] == ["T1059.001", "T1027"]
    assert powershell["labels"] == ["SUSPICIOUS_POWERSHELL"]


def test_evaluation_records_its_own_duration() -> None:
    result = evaluate({"event_type": "process_creation", "normalized_data": {}})
    assert result.duration_ms >= 0.0
