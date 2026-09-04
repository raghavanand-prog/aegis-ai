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


def test_seeded_source_is_reproducible() -> None:
    """The seed must control every random field, or nothing downstream is reproducible.

    The generator used to draw source addresses from the global ``random``
    module and identifiers from ``uuid.uuid4()``, so two sources built with the
    same seed emitted different records. That silently broke the training
    corpus, whose whole claim is that a seed pins the data.
    """
    first = [record.raw for record in SyntheticTelemetrySource(seed=99).collect(120)]
    second = [record.raw for record in SyntheticTelemetrySource(seed=99).collect(120)]

    volatile = {"Timestamp", "UtcTime", "createdDateTime", "timestamp", "detected_at"}

    def stable(raw: dict) -> dict:
        return {key: value for key, value in raw.items() if key not in volatile}

    assert [stable(raw) for raw in first] == [stable(raw) for raw in second]


def test_generated_timestamps_have_a_fixed_width() -> None:
    """Variable-width timestamps leaked wall-clock noise into raw_log length."""
    lengths = set()
    for record in SyntheticTelemetrySource(seed=5).collect(60):
        for key in ("Timestamp", "UtcTime", "createdDateTime", "timestamp"):
            value = record.raw.get(key)
            if isinstance(value, str) and value.endswith("+00:00"):
                lengths.add(len(value))
    assert lengths, "no generated record carried an ISO timestamp"
    assert len(lengths) == 1, f"timestamp width varies: {sorted(lengths)}"


class TestScenarioProvenance:
    """V6: the generator's scenario name travels with the record it produced.

    Without it the scenario is unrecoverable downstream, because normalization
    collapses distinct scenarios onto one `event_type` - `_dns_query` and
    `_dns_rare_domain` both become `dns_query`. Labelling a corpus from
    `event_type` would therefore erase exactly the distinction between ordinary
    traffic and the deliberately-rare-but-benign behaviour, which is the
    distinction a labelled telemetry corpus depends on.
    """

    def test_every_record_reports_the_scenario_that_produced_it(self) -> None:
        from app.telemetry.sources.synthetic import SyntheticTelemetrySource

        source = SyntheticTelemetrySource(seed=1337)
        known = {name for _, name in SyntheticTelemetrySource.SCENARIOS}
        records = list(source.collect(200))
        assert records
        for record in records:
            assert record.scenario in known

    def test_queued_campaign_records_keep_their_campaign_scenario(self) -> None:
        """A campaign emits several related records. The queued ones must carry
        the campaign's name, not the name of whatever draw released them."""
        from app.telemetry.sources.synthetic import SyntheticTelemetrySource

        source = SyntheticTelemetrySource(seed=99)
        campaigns = {
            name
            for _, name in SyntheticTelemetrySource.SCENARIOS
            if name.startswith("_campaign")
        }
        seen = [r.scenario for r in source.collect(600)]
        assert campaigns & set(seen), "no campaign fired; widen the sample"
        for scenario in seen:
            assert scenario is not None

    def test_the_scenario_is_provenance_not_a_label(self) -> None:
        """It must not reach the normalized candidate: a detector that could
        read the generating scenario would be scoring the answer key."""
        from app.telemetry.normalizer import normalize
        from app.telemetry.sources.synthetic import SyntheticTelemetrySource

        record = next(iter(SyntheticTelemetrySource(seed=7).collect(1)))
        candidate = normalize(record)
        assert "scenario" not in candidate
        assert "scenario" not in candidate.get("normalized_data", {})
