"""Correlation, AI, threat-intelligence and degraded-mode evaluation harnesses.

These tests check that each harness measures what it claims and refuses to
report what it cannot measure. They are small on purpose - the harnesses' own
output is the evidence, and what needs guarding is that the output stays honest.
"""

from __future__ import annotations

from app.evaluation.correlation_eval import run_correlation_evaluation
from app.evaluation.system_eval import (
    evaluate_ai_analyst,
    evaluate_degraded_modes,
    evaluate_threat_intelligence,
)

# ------------------------------------------------------------- correlation


def test_correlation_evaluation_recovers_injected_campaigns(db) -> None:
    report = run_correlation_evaluation(
        db, campaigns_per_kind=3, background_events=40, seed=99
    )
    totals = report.totals

    assert totals["campaignsInjected"] == 9
    assert totals["eventsIngested"] > 0
    # The credential-attack pattern is the one AEGISX was built around; if it
    # stops recovering campaigns, correlation has regressed.
    credential = next(
        entry for entry in report.campaigns if "credential" in entry["kind"]
    )
    assert credential["detected"] > 0


def test_correlation_purity_is_measured_not_assumed(db) -> None:
    """Purity is the metric that catches over-grouping; it must be a number."""
    report = run_correlation_evaluation(
        db, campaigns_per_kind=3, background_events=40, seed=101
    )
    for row in report.sequences:
        if row["matchedCampaign"] is not None:
            assert row["purity"] is not None
            assert 0.0 < row["purity"] <= 1.0


def test_correlation_report_refuses_to_generalise(db) -> None:
    report = run_correlation_evaluation(
        db, campaigns_per_kind=2, background_events=20, seed=7
    )
    joined = " ".join(report.notes).lower()
    assert "not evidence about real attacks" in joined
    assert "attack-graph" in joined
    assert "not a production throughput claim" in joined


def test_correlation_evaluation_is_reproducible(db) -> None:
    first = run_correlation_evaluation(
        db, campaigns_per_kind=2, background_events=20, seed=55
    )
    db.rollback()
    second = run_correlation_evaluation(
        db, campaigns_per_kind=2, background_events=20, seed=55
    )
    assert (
        first.totals["campaignsInjected"] == second.totals["campaignsInjected"]
    )
    assert first.totals["eventsIngested"] == second.totals["eventsIngested"]


# ---------------------------------------------------------------- AI analyst


def test_ai_evaluation_labels_mock_results_as_mock(db) -> None:
    """A template-provider result must never be presented as a model result."""
    result = evaluate_ai_analyst(db, [])
    payload = result.to_dict()
    if payload["isTemplateProvider"]:
        assert "MOCK" in payload["resultLabel"]
        assert "not a language model" in payload["resultLabel"]


def test_ai_evaluation_reports_a_reason_when_unavailable(db, monkeypatch) -> None:
    from app.ai import service as ai_service

    monkeypatch.setattr(
        ai_service,
        "status",
        lambda: {"available": False, "reason": "AI is disabled in this configuration."},
    )
    result = evaluate_ai_analyst(db, [])
    assert result.unavailable_reason == "AI is disabled in this configuration."
    assert result.totals == {}


# -------------------------------------------------------- threat intelligence


def test_threat_intel_evaluation_refuses_to_invent_enrichment_metrics(db) -> None:
    """With no provider, the honest answer is a stated absence."""
    payload = evaluate_threat_intelligence(db)
    assert payload["enrichmentMeasured"] is False
    if not payload["configured"]:
        assert "NOT AVAILABLE" in payload["unavailableReason"]
    joined = " ".join(payload["notes"]).lower()
    assert "fabricated" in joined


def test_documentation_and_private_addresses_are_refused(db) -> None:
    """Why enrichment is silent on synthetic telemetry, measured not assumed."""
    payload = evaluate_threat_intelligence(db)
    probes = {row["value"]: row for row in payload["ssrfValidation"]["probes"]}

    assert probes["203.0.113.10"]["accepted"] is False
    assert probes["10.0.0.5"]["accepted"] is False
    assert probes["127.0.0.1"]["accepted"] is False
    # The cloud metadata endpoint is the one that turns an SSRF into a
    # credential theft, so it gets its own assertion.
    assert probes["169.254.169.254"]["accepted"] is False
    assert payload["ssrfValidation"]["allRefused"] is True


# -------------------------------------------------------------- degraded mode


def test_optional_subsystem_failure_never_stops_ingestion() -> None:
    """The V3 architectural guarantee, exercised rather than asserted."""
    payload = evaluate_degraded_modes()
    assert payload["ingestionSurvivedEveryScenario"] is True
    for scenario in payload["scenarios"]:
        assert scenario["eventsNormalized"] > 0, scenario["scenario"]
        # Rules must keep firing with every optional subsystem broken.
        assert scenario["ruleDetections"] > 0, scenario["scenario"]


def test_a_corrupt_or_mismatched_artifact_is_refused() -> None:
    payload = evaluate_degraded_modes()
    scenarios = {entry["scenario"]: entry for entry in payload["scenarios"]}

    assert scenarios["ml_artifact_corrupt"]["subsystemState"]["refused"] is True
    assert scenarios["ml_digest_mismatch"]["subsystemState"]["refused"] is True


def test_an_unloaded_model_declines_with_a_reason() -> None:
    """'No model running' and 'no anomalies found' are different facts."""
    payload = evaluate_degraded_modes()
    scenarios = {entry["scenario"]: entry for entry in payload["scenarios"]}
    state = scenarios["ml_never_loaded"]["subsystemState"]

    assert state["available"] is False
    assert state["reason"], "an unavailable engine must say why"
    assert state["scoreReturned"] is None


def test_every_degraded_state_carries_a_reason() -> None:
    payload = evaluate_degraded_modes()
    assert payload["everyUnavailableStateCarriesAReason"] is True
