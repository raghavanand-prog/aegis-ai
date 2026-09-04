"""The telemetry source abstraction and the CloudTrail source (V7 Phases 4-5).

V6 recorded the leak this closes: "``telemetry/normalizer.py`` hard-codes vendor
schemas (``_normalize_defender``); that leak is documented and unfixed. Adding a
source by appending another branch would deepen it."

The five properties the V7 brief asks for are the five classes below, in order.
The sixth - that V4/V5/V6 behaviour is intact - is held by digest in
``test_telemetry_normalizer_characterization.py``, which is a stronger check
than anything here and was recorded before any of this code existed.
"""

from __future__ import annotations

import dataclasses
import gzip
import json

import pytest

from app.models.enums import SourceType
from app.telemetry import adapters
from app.telemetry.adapters.base import AdapterError, TelemetryAdapter
from app.telemetry.adapters.cloudtrail import CloudTrailAdapter
from app.telemetry.base import RawTelemetry
from app.telemetry.canonical import (
    CANONICAL_FIELDS,
    RESOLUTION_EXACT,
    RESOLUTION_FALLBACK,
    CanonicalEvent,
)
from app.telemetry.normalizer import (
    NormalizationError,
    normalize,
    normalize_with_provenance,
)
from app.telemetry.sources.cloudtrail_file import CloudTrailFileSource


def _record(source: str, source_type: SourceType, raw: dict) -> RawTelemetry:
    return RawTelemetry(
        source=source, source_type=source_type, raw=raw, raw_log=f"[{source}] test"
    )


def _cloudtrail(**overrides) -> dict:
    base = {
        "eventVersion": "1.09",
        "userIdentity": {
            "type": "IAMUser",
            "principalId": "AIDATEST",
            "arn": "arn:aws:iam::123456789012:user/test.user",
            "accountId": "123456789012",
            "userName": "test.user",
        },
        "eventTime": "2026-09-02T02:44:19Z",
        "eventSource": "s3.amazonaws.com",
        "eventName": "ListBuckets",
        "awsRegion": "eu-west-2",
        "sourceIPAddress": "198.51.100.20",
        "userAgent": "aws-cli/2.15.0",
        "recipientAccountId": "123456789012",
    }
    base.update(overrides)
    return base


# --------------------------------------------------------------------------
# 1. Source-specific fields do not leak into the canonical contract
# --------------------------------------------------------------------------
class TestVendorFieldsDoNotLeak:
    def test_the_canonical_contract_has_a_fixed_field_set(self) -> None:
        """The contract is checkable because it is a class rather than whatever
        keys the mappers happened to agree on."""
        actual = {f.name for f in dataclasses.fields(CanonicalEvent)}
        assert actual == CANONICAL_FIELDS

    def test_no_vendor_key_reaches_a_canonical_field(self) -> None:
        """AWS-specific keys must be readable but never depended on."""
        event = CloudTrailAdapter().parse(_cloudtrail())

        assert "aws_event_name" not in CANONICAL_FIELDS
        assert event.vendor_fields["aws_event_name"] == "ListBuckets"
        assert event.vendor_fields["principal_arn"].startswith("arn:aws:iam::")
        # The canonical fields carry only the normalized meaning.
        assert event.username == "test.user"
        assert event.event_type == "cloud_api_call"

    def test_an_adapter_emitting_a_non_canonical_field_is_refused(self) -> None:
        """The leak, caught at the seam rather than discovered downstream."""
        with pytest.raises(AdapterError, match="non-canonical field"):
            TelemetryAdapter.from_candidate(
                {
                    "event_type": "cloud_api_call",
                    "title": "t",
                    "aws_account_id": "123456789012",
                }
            )

    def test_vendor_detail_survives_into_normalized_data(self) -> None:
        """Not leaking is not the same as discarding: an analyst still needs it."""
        candidate = normalize(
            _record("AWS CloudTrail", SourceType.CLOUD, _cloudtrail())
        )

        assert candidate["normalized_data"]["aws_region"] == "eu-west-2"
        assert candidate["normalized_data"]["user_agent"] == "aws-cli/2.15.0"


# --------------------------------------------------------------------------
# 2. Multiple adapters produce the canonical representation
# --------------------------------------------------------------------------
class TestManyAdaptersOneContract:
    CASES = (
        ("Sysmon", SourceType.ENDPOINT, {"EventID": 1, "Computer": "H", "Image": "a.exe"}),
        ("Entra ID", SourceType.IDENTITY, {"userPrincipalName": "u@x", "resultType": "0"}),
        ("DNS Resolver", SourceType.DNS, {"query": "example.com", "query_type": "A"}),
        ("AWS CloudTrail", SourceType.CLOUD, None),
    )

    def test_every_registered_adapter_returns_a_canonical_event(self) -> None:
        for source, source_type, raw in self.CASES:
            record = _record(source, source_type, raw if raw is not None else _cloudtrail())
            event, _ = normalize_with_provenance(record)

            assert isinstance(event, CanonicalEvent), source
            assert event.event_type, source
            assert event.title, source

    def test_sources_of_different_shapes_reach_one_candidate_shape(self) -> None:
        """A CloudTrail API call has no host or process; a Sysmon record has no
        region. Both arrive as the same set of keys."""
        cloud = normalize(_record("AWS CloudTrail", SourceType.CLOUD, _cloudtrail()))
        endpoint = normalize(
            _record(
                "Sysmon",
                SourceType.ENDPOINT,
                {"EventID": 1, "Computer": "H", "Image": "C:\\a.exe"},
            )
        )

        assert set(cloud) == set(endpoint)
        assert cloud["hostname"] is None
        assert endpoint["hostname"] == "H"


# --------------------------------------------------------------------------
# 3. Unsupported / invalid source data fails safely
# --------------------------------------------------------------------------
class TestInvalidInputFailsSafely:
    def test_an_unknown_source_of_an_unknown_class_is_refused(self) -> None:
        with pytest.raises(NormalizationError, match="No telemetry adapter"):
            normalize(_record("Some New Product", SourceType.APPLICATION, {"a": 1}))

    def test_a_cloud_source_is_not_silently_parsed_as_cloudtrail(self) -> None:
        """The V6 failure mode, closed for new classes.

        ``FALLBACK_BY_TYPE`` used to hand any unrecognised source of a known
        class to whichever adapter held that class, producing confident nonsense
        with nothing recorded. CloudTrail declares no ``fallback_for``, so an
        unknown cloud product is refused instead of guessed at.
        """
        with pytest.raises(NormalizationError, match="No telemetry adapter"):
            normalize(_record("Some Other Cloud", SourceType.CLOUD, _cloudtrail()))

    def test_a_malformed_record_is_refused_not_half_mapped(self) -> None:
        with pytest.raises(NormalizationError, match="could not map a record"):
            normalize(_record("AWS CloudTrail", SourceType.CLOUD, {"eventVersion": "1.09"}))

    def test_the_collector_survives_an_unmappable_record(self, db) -> None:
        """A source that raised would take the whole ingestion loop down."""
        from app.telemetry.collector import TelemetryCollector

        class BrokenSource(CloudTrailFileSource):
            def collect(self, count: int = 1):
                return [_record("AWS CloudTrail", SourceType.CLOUD, {"nope": True})]

        collector = TelemetryCollector(sources=[BrokenSource()])
        ingested = collector.collect_once(db, broadcast=False)

        assert ingested == []
        assert collector.status()["errors"] >= 1

    def test_a_corrupt_fixture_file_is_skipped_not_fatal(self, tmp_path) -> None:
        (tmp_path / "good.json").write_text(json.dumps({"Records": [_cloudtrail()]}))
        (tmp_path / "bad.json").write_text("{ not json")
        (tmp_path / "bad.gz").write_bytes(b"not gzip either")

        source = CloudTrailFileSource(tmp_path, repeat=False)
        records = list(source.collect(10))

        assert len(records) == 1
        assert source.health()["unreadableFiles"] == 2

    def test_a_gzipped_trail_file_is_read(self, tmp_path) -> None:
        """CloudTrail delivers gzipped JSON; the fixtures should not be a
        special case that the live shape would not exercise."""
        payload = json.dumps({"Records": [_cloudtrail(), _cloudtrail()]}).encode()
        (tmp_path / "trail.json.gz").write_bytes(gzip.compress(payload))

        assert len(list(CloudTrailFileSource(tmp_path, repeat=False).collect(10))) == 2


# --------------------------------------------------------------------------
# 4. Provenance is retained
# --------------------------------------------------------------------------
class TestProvenanceIsRetained:
    def test_an_exact_match_records_which_adapter_ran(self) -> None:
        _, provenance = normalize_with_provenance(
            _record("AWS CloudTrail", SourceType.CLOUD, _cloudtrail())
        )

        assert provenance.adapter == "cloudtrail"
        assert provenance.resolution == RESOLUTION_EXACT
        assert provenance.source == "AWS CloudTrail"
        assert provenance.is_synthetic is True

    def test_a_fallback_is_recorded_rather_than_silent(self) -> None:
        """V6 fell back too. It just never said so anywhere."""
        _, provenance = normalize_with_provenance(
            _record("Unknown EDR Product", SourceType.EDR, {"detection_name": "X"})
        )

        assert provenance.resolution == RESOLUTION_FALLBACK
        assert provenance.adapter == "edr"

    def test_the_scenario_still_never_reaches_the_candidate(self) -> None:
        """V6's invariant, re-asserted across the refactor: a detector able to
        read the generating scenario would be scoring the answer key."""
        record = _record("AWS CloudTrail", SourceType.CLOUD, _cloudtrail())
        record.scenario = "credential_abuse"

        candidate = normalize(record)

        assert "scenario" not in candidate
        assert "credential_abuse" not in json.dumps(candidate, default=str)

    def test_a_source_cannot_be_registered_twice(self) -> None:
        class Duplicate(TelemetryAdapter):
            name = "duplicate"
            source_names = ("AWS CloudTrail",)

            def parse(self, raw):  # pragma: no cover - never reached
                raise AdapterError("unused")

        with pytest.raises(ValueError, match="already registered"):
            adapters.register(Duplicate())


# --------------------------------------------------------------------------
# 5. The CloudTrail source is honest about being simulated
# --------------------------------------------------------------------------
class TestTheSourceIsLabelledSimulated:
    def test_every_record_is_marked_synthetic(self) -> None:
        for record in CloudTrailFileSource(repeat=False).collect(50):
            assert record.is_synthetic is True

    def test_health_says_it_is_a_fixture(self) -> None:
        health = CloudTrailFileSource(repeat=False).health()

        assert health["simulated"] is True
        assert health["mode"] == "fixture"
        assert health["recordsAvailable"] >= 8

    def test_the_shipped_fixtures_all_parse(self) -> None:
        records = list(CloudTrailFileSource(repeat=False).collect(100))

        assert len(records) >= 8
        for record in records:
            event, provenance = normalize_with_provenance(record)
            assert provenance.resolution == RESOLUTION_EXACT
            assert event.event_type

    def test_the_records_own_time_is_used_not_the_wall_clock(self) -> None:
        """Behavioural features are stateful and ordered. Stamping a replayed
        trail with "now" would collapse a day of activity into one instant."""
        records = list(CloudTrailFileSource(repeat=False).collect(3))

        assert records[0].received_at.year == 2026
        assert records[0].received_at.month == 9
        assert records[0].received_at.isoformat().startswith("2026-09-01T08:14:02")
