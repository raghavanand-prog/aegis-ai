"""CloudTrail from fixture file to persisted alert (V7 Phase 5).

The point of this module is that there is no shortcut in it. A record enters as
the JSON AWS would have written, and comes out the far end as a stored ``Event``
carrying detections, having gone through the same collector, adapter, normalizer,
feature extractor and detection engine as every other source. Nothing about
CloudTrail is special-cased anywhere on that path, which is the claim Phase 4's
abstraction was making and this is where it is checked.

**Everything here is simulated.** The fixtures are hand-written to the public
CloudTrail schema; no AWS account, credential or API call is involved, and
nothing measured here is evidence about real cloud activity.
"""

from __future__ import annotations

from sqlalchemy import select

from app.models.event import Event
from app.telemetry.collector import TelemetryCollector
from app.telemetry.sources.cloudtrail_file import CloudTrailFileSource


def _ingest(db, *, count: int = 20) -> list[Event]:
    collector = TelemetryCollector(
        sources=[CloudTrailFileSource(repeat=False)], events_per_tick=count
    )
    return collector.collect_once(db, broadcast=False)


class TestTheWholePathRuns:
    def test_fixtures_become_persisted_events(self, db) -> None:
        ingested = _ingest(db)

        assert len(ingested) >= 8
        stored = db.scalars(
            select(Event).where(Event.source == "AWS CloudTrail")
        ).all()
        assert len(stored) >= 8

    def test_events_carry_cloud_provenance(self, db) -> None:
        ingested = _ingest(db)

        for event in ingested:
            assert event.source == "AWS CloudTrail"
            assert event.source_type == "cloud"
            # Simulated, and the row says so rather than the README alone.
            assert event.is_synthetic is True

    def test_the_aws_detail_an_analyst_needs_survives(self, db) -> None:
        ingested = _ingest(db)
        by_name = {
            (event.normalized_data or {}).get("aws_event_name"): event
            for event in ingested
        }

        attach = by_name["AttachUserPolicy"]
        assert attach.normalized_data["aws_region"] == "us-east-1"
        assert attach.normalized_data["principal_arn"].endswith("user/svc.pipeline")
        assert (
            attach.normalized_data["request_parameters"]["policyArn"]
            == "arn:aws:iam::aws:policy/AdministratorAccess"
        )


class TestDetectionFiresOnCloudActivity:
    def _by_type(self, events: list[Event]) -> dict[str, Event]:
        return {event.event_type: event for event in events}

    def test_a_privilege_grant_is_detected(self, db) -> None:
        """DET-PRIV-001, reached from a cloud record through the same rule the
        Linux sudo path uses. The mapping onto an existing event type is what
        makes that possible."""
        events = self._by_type(_ingest(db))

        escalation = events["privilege_escalation"]
        rules = [
            detection["ruleId"] for detection in (escalation.detections or [])
        ]
        assert "DET-PRIV-001" in rules

    def test_a_secret_read_is_detected(self, db) -> None:
        events = self._by_type(_ingest(db))

        credential = events["credential_access"]
        rules = [d["ruleId"] for d in (credential.detections or [])]
        assert "DET-CRED-001" in rules

    def test_a_large_transfer_is_detected(self, db) -> None:
        events = self._by_type(_ingest(db))

        exfil = events["data_exfiltration"]
        rules = [d["ruleId"] for d in (exfil.detections or [])]
        assert "DET-EXFIL-001" in rules

    def test_benign_baseline_activity_does_not_fire(self, db) -> None:
        """A source that made everything look malicious would be worse than no
        source: V4 measured exactly that defect in the EDR mapper."""
        events = _ingest(db)
        benign = [
            event
            for event in events
            if (event.normalized_data or {}).get("aws_event_name")
            in {"ListBuckets", "DescribeInstances"}
        ]

        assert benign, "the baseline fixture should have produced events"
        for event in benign:
            assert not (event.detections or []), event.title

    def test_a_denied_call_is_recorded_without_a_rule_claiming_it(self, db) -> None:
        """A denied API call is not a failed sign-in, and stretching it onto
        ``auth_failure`` would have made a cloud-detection capability appear to
        exist because a rule happened to match."""
        events = self._by_type(_ingest(db))

        denied = events["cloud_api_denied"]
        assert denied.normalized_data["error_code"] == "AccessDenied"
        assert not (denied.detections or [])


class TestFeaturesAreExtractable:
    def test_a_cloud_event_produces_a_full_feature_vector(self, db) -> None:
        """The anomaly model must be able to score a cloud event, or the source
        reaches the rules and stops there."""
        from app.ml.features import FEATURE_NAMES, FeatureExtractor

        ingested = _ingest(db)
        extractor = FeatureExtractor()

        for event in ingested[:5]:
            values = extractor.extract(
                {
                    "event_type": event.event_type,
                    "severity": event.severity,
                    "source_type": event.source_type,
                    "hostname": event.hostname,
                    "username": event.username,
                    "source_ip": event.source_ip,
                    "destination_ip": event.destination_ip,
                    "destination_port": event.destination_port,
                    "process": event.process,
                    "command_line": event.command_line,
                    "raw_log": event.raw_log,
                    "normalized_data": event.normalized_data or {},
                    "timestamp": event.timestamp,
                },
                observe=True,
            ).values

            assert len(values) == len(FEATURE_NAMES)
            assert all(isinstance(value, float) for value in values)
