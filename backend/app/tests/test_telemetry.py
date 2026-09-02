"""Telemetry generation, normalization and collection."""

from __future__ import annotations

import pytest

from app.models.enums import Severity
from app.telemetry.base import RawTelemetry
from app.telemetry.collector import ExternalSourceRefused, TelemetryCollector
from app.telemetry.normalizer import NormalizationError, normalize
from app.telemetry.sources.synthetic import SyntheticTelemetrySource


def test_generator_produces_clearly_synthetic_records() -> None:
    source = SyntheticTelemetrySource(seed=7)
    records = list(source.collect(40))

    assert len(records) == 40
    for record in records:
        assert record.is_synthetic
        assert record.raw.get("synthetic") is True
        assert record.raw_log


def test_generator_covers_every_configured_vendor() -> None:
    source = SyntheticTelemetrySource(seed=11)
    names = {record.source for record in source.collect(400)}
    assert {
        "Microsoft Defender",
        "Sysmon",
        "Entra ID",
        "Perimeter Firewall",
        "DNS Resolver",
        "Linux Auditd",
        "EDR Agent",
    } <= names


def test_every_generated_record_normalizes() -> None:
    source = SyntheticTelemetrySource(seed=3)
    for record in source.collect(300):
        candidate = normalize(record)
        assert candidate["source"] == record.source
        assert candidate["event_type"]
        assert candidate["title"]
        assert candidate["severity"] in {s.value for s in Severity}


def test_unknown_source_is_rejected() -> None:
    class Mystery:
        pass

    record = RawTelemetry(
        source="Unknown Vendor",
        source_type=type("X", (), {"value": "weird"})(),  # not a real SourceType
        raw={},
        raw_log="",
    )
    with pytest.raises((NormalizationError, KeyError, TypeError, AttributeError)):
        normalize(record)


def test_collector_persists_normalized_events(db) -> None:
    collector = TelemetryCollector(
        [SyntheticTelemetrySource(seed=5)], interval_seconds=1, events_per_tick=5
    )
    events = collector.collect_once(db, broadcast=False)
    db.commit()

    assert len(events) == 5
    for event in events:
        assert event.event_id.startswith("EVT-")
        assert event.raw_log
        assert event.is_synthetic
        assert event.normalized_data is not None


def test_external_sources_are_refused_without_explicit_opt_in() -> None:
    class ProductionSIEM(SyntheticTelemetrySource):
        name = "Production SIEM"
        is_external = True

    with pytest.raises(ExternalSourceRefused):
        TelemetryCollector([ProductionSIEM()])


def test_collector_status_reports_sources() -> None:
    collector = TelemetryCollector([SyntheticTelemetrySource(seed=1)])
    status = collector.status()
    assert status["running"] is False
    assert status["externalSourcesAllowed"] is False
    assert status["sources"][0]["name"] == "Synthetic Telemetry"
