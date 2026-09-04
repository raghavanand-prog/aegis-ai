"""Decision-bound evidence integrity, tested as pure logic.

No database, no session, no HTTP. What is checked here is the classification
that decides whether a decision still rests on the evidence it was taken on -
and, just as importantly, whether a change is the kind that should raise an
alarm or the kind that happens every time a threat-intelligence cache
refreshes. A control that fires on the second one gets switched off, and then
it is not protecting anything.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from app.evidence.binding import (
    MAX_SNAPSHOT_ENTRIES,
    DriftVerdict,
    EvidenceSnapshot,
    SnapshotEntry,
    classify_drift,
    manifest_for,
)
from app.evidence.models import (
    EvidenceItem,
    EvidenceKind,
    EvidenceOrigin,
    Integrity,
    Provenance,
)

NOW = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)


def entry(
    evidence_id: str = "EV-aaaa000000000000",
    digest: str = "d" * 64,
    integrity: Integrity = Integrity.WRITE_ONCE,
    kind: str = "event",
    provider: str = "aegisx.telemetry",
) -> SnapshotEntry:
    return SnapshotEntry(
        evidence_id=evidence_id,
        content_digest=digest,
        integrity=integrity,
        kind=kind,
        provider=provider,
    )


def snapshot(*entries: SnapshotEntry, **kwargs) -> EvidenceSnapshot:
    return EvidenceSnapshot.from_entries(list(entries), **kwargs)


def item(
    source_ref: str = "event:EVT-000001",
    kind: EvidenceKind = EvidenceKind.EVENT,
    content: dict | None = None,
    integrity: Integrity = Integrity.WRITE_ONCE,
) -> EvidenceItem:
    return EvidenceItem(
        kind=kind,
        title="something happened",
        content=content if content is not None else {"a": 1},
        provenance=Provenance(
            provider="aegisx.telemetry",
            source_ref=source_ref,
            origin=EvidenceOrigin.OBSERVED,
            integrity=integrity,
            observed_at=NOW,
            collected_at=NOW,
        ),
    )


# --- The snapshot ---------------------------------------------------------


class TestSnapshot:
    def test_it_is_built_from_evidence_items(self) -> None:
        built = EvidenceSnapshot.from_items([item(), item(source_ref="event:EVT-000002")])
        assert len(built.entries) == 2
        assert all(e.content_digest for e in built.entries)

    def test_the_manifest_matches_the_evidence_set_computation(self) -> None:
        """The snapshot and the live set must agree, or a binding taken from
        one could never be compared with the other."""
        items = [item(), item(source_ref="event:EVT-000002")]
        built = EvidenceSnapshot.from_items(items)

        expected = manifest_for(
            (i.evidence_id, i.content_digest) for i in items
        )
        assert built.manifest_digest == expected

    def test_the_manifest_ignores_ordering(self) -> None:
        first = EvidenceSnapshot.from_items([item(), item(source_ref="event:EVT-000002")])
        second = EvidenceSnapshot.from_items([item(source_ref="event:EVT-000002"), item()])
        assert first.manifest_digest == second.manifest_digest

    def test_it_records_which_providers_were_degraded(self) -> None:
        """A decision taken while a provider was down was taken on partial
        evidence, and that is as important as evidence changing afterwards."""
        built = EvidenceSnapshot.from_items(
            [item()],
            degraded=[{"provider": "aegisx.ml", "status": "unavailable", "reason": "x"}],
        )
        assert built.degraded_providers[0]["provider"] == "aegisx.ml"
        assert not built.was_complete

    def test_a_snapshot_with_every_provider_answering_is_complete(self) -> None:
        assert snapshot(entry()).was_complete

    def test_it_survives_a_round_trip_through_json(self) -> None:
        """It is persisted as JSON and read back to verify a decision months
        later. Anything lost in the round trip is attribution lost."""
        import json

        original = EvidenceSnapshot.from_items(
            [item(), item(source_ref="ml_inference:3", integrity=Integrity.APPEND_ONLY)],
            degraded=[{"provider": "aegisx.ai", "status": "degraded", "reason": "no key"}],
        )
        restored = EvidenceSnapshot.from_dict(json.loads(json.dumps(original.to_dict())))

        assert restored.manifest_digest == original.manifest_digest
        assert restored.entries == original.entries
        assert restored.degraded_providers == original.degraded_providers
        assert restored.truncated == original.truncated

    def test_it_is_frozen(self) -> None:
        with pytest.raises((AttributeError, TypeError)):
            snapshot(entry()).manifest_digest = "x"  # type: ignore[misc]


class TestTruncation:
    def test_a_huge_snapshot_keeps_the_manifest_and_says_it_truncated(self) -> None:
        """Detection stays complete even when attribution cannot.

        The manifest covers every item however many there are. The per-item
        map is what gets capped, so the honest report is "something changed and
        I cannot tell you which item", never a clean verdict.
        """
        many = [
            item(source_ref=f"event:EVT-{index:06d}")
            for index in range(MAX_SNAPSHOT_ENTRIES + 10)
        ]
        built = EvidenceSnapshot.from_items(many)

        assert built.truncated
        assert len(built.entries) == MAX_SNAPSHOT_ENTRIES
        assert built.entry_count == MAX_SNAPSHOT_ENTRIES + 10
        # The manifest still covers all of them.
        assert built.manifest_digest == manifest_for(
            (i.evidence_id, i.content_digest) for i in many
        )

    def test_an_ordinary_snapshot_is_not_truncated(self) -> None:
        assert not EvidenceSnapshot.from_items([item()]).truncated


# --- The classification ---------------------------------------------------


class TestDriftClassification:
    def test_identical_evidence_is_unchanged(self) -> None:
        before = snapshot(entry())
        report = classify_drift(before, snapshot(entry()))
        assert report.verdict is DriftVerdict.UNCHANGED
        assert not report.undermines_decision

    def test_two_empty_sets_are_unchanged(self) -> None:
        assert classify_drift(snapshot(), snapshot()).verdict is DriftVerdict.UNCHANGED

    def test_additions_alone_are_extended(self) -> None:
        before = snapshot(entry())
        after = snapshot(entry(), entry(evidence_id="EV-bbbb000000000000"))

        report = classify_drift(before, after)
        assert report.verdict is DriftVerdict.EXTENDED
        assert report.added == ("EV-bbbb000000000000",)
        assert not report.removed
        assert not report.changed
        # New evidence does not undermine what the decision rested on - but it
        # is still worth an analyst's attention, so it is never silent.
        assert not report.undermines_decision

    def test_a_changed_mutable_item_is_a_refresh(self) -> None:
        """The threat-intelligence case. Mechanically expected; materially
        important, because the verdict behind the decision may have inverted."""
        before = snapshot(
            entry(integrity=Integrity.MUTABLE, kind="threat_intel", provider="aegisx.threatintel")
        )
        after = snapshot(
            entry(
                digest="e" * 64,
                integrity=Integrity.MUTABLE,
                kind="threat_intel",
                provider="aegisx.threatintel",
            )
        )

        report = classify_drift(before, after)
        assert report.verdict is DriftVerdict.REFRESHED
        assert report.changed[0].evidence_id == "EV-aaaa000000000000"
        assert report.changed[0].integrity is Integrity.MUTABLE
        # A refresh is NOT benign: the basis of the decision moved.
        assert report.undermines_decision

    @pytest.mark.parametrize(
        "integrity", [Integrity.WRITE_ONCE, Integrity.APPEND_ONLY]
    )
    def test_a_changed_immutable_item_is_tampering(self, integrity) -> None:
        """The application has no path that rewrites these. If one changed,
        something outside the application did it."""
        before = snapshot(entry(integrity=integrity))
        after = snapshot(entry(digest="e" * 64, integrity=integrity))

        report = classify_drift(before, after)
        assert report.verdict is DriftVerdict.TAMPERED
        assert report.undermines_decision

    def test_a_removal_is_tampering_even_for_a_mutable_item(self) -> None:
        """Evidence does not disappear through any supported operation.

        Classifying a removal as merely a refresh would let the most damaging
        change - deleting the finding a closure rested on - be reported as
        routine cache churn.
        """
        before = snapshot(entry(integrity=Integrity.MUTABLE))
        report = classify_drift(before, snapshot())

        assert report.verdict is DriftVerdict.TAMPERED
        assert report.removed == ("EV-aaaa000000000000",)


class TestSeverityOrdering:
    """When several kinds of drift happen at once, the worst one wins."""

    def test_a_refresh_outranks_an_addition(self) -> None:
        before = snapshot(entry(integrity=Integrity.MUTABLE))
        after = snapshot(
            entry(digest="e" * 64, integrity=Integrity.MUTABLE),
            entry(evidence_id="EV-bbbb000000000000"),
        )
        report = classify_drift(before, after)
        assert report.verdict is DriftVerdict.REFRESHED
        assert report.added == ("EV-bbbb000000000000",)

    def test_tampering_outranks_a_refresh(self) -> None:
        before = snapshot(
            entry(integrity=Integrity.MUTABLE),
            entry(evidence_id="EV-bbbb000000000000", integrity=Integrity.WRITE_ONCE),
        )
        after = snapshot(
            entry(digest="e" * 64, integrity=Integrity.MUTABLE),
            entry(
                evidence_id="EV-bbbb000000000000",
                digest="f" * 64,
                integrity=Integrity.WRITE_ONCE,
            ),
        )
        assert classify_drift(before, after).verdict is DriftVerdict.TAMPERED

    def test_a_removal_outranks_everything_else(self) -> None:
        before = snapshot(
            entry(),
            entry(evidence_id="EV-bbbb000000000000", integrity=Integrity.MUTABLE),
        )
        after = snapshot(entry(evidence_id="EV-cccc000000000000"))
        report = classify_drift(before, after)
        assert report.verdict is DriftVerdict.TAMPERED
        assert set(report.removed) == {"EV-aaaa000000000000", "EV-bbbb000000000000"}

    def test_the_verdicts_have_a_defined_order(self) -> None:
        assert (
            DriftVerdict.UNCHANGED.severity
            < DriftVerdict.EXTENDED.severity
            < DriftVerdict.REFRESHED.severity
            < DriftVerdict.TAMPERED.severity
        )


class TestIncompleteAttribution:
    def test_a_truncated_snapshot_never_reports_a_clean_verdict_when_the_manifest_moved(
        self,
    ) -> None:
        """The dangerous failure: reporting UNCHANGED because the item that
        moved was one of the ones the cap dropped."""
        before = EvidenceSnapshot.from_entries(
            [entry()], manifest_digest="0" * 64, truncated=True, entry_count=9999
        )
        after = snapshot(entry())

        report = classify_drift(before, after)
        assert report.verdict is not DriftVerdict.UNCHANGED
        assert not report.attribution_complete

    def test_a_complete_snapshot_reports_complete_attribution(self) -> None:
        report = classify_drift(snapshot(entry()), snapshot(entry()))
        assert report.attribution_complete

    def test_the_manifest_is_authoritative_for_detection(self) -> None:
        """Even truncated, an unchanged manifest proves nothing moved."""
        before = EvidenceSnapshot.from_entries(
            [entry()], truncated=True, entry_count=9999
        )
        after = EvidenceSnapshot.from_entries(
            [entry()], manifest_digest=before.manifest_digest, truncated=True, entry_count=9999
        )
        assert classify_drift(before, after).verdict is DriftVerdict.UNCHANGED


class TestReportShape:
    def test_the_report_serializes(self) -> None:
        import json

        before = snapshot(entry(integrity=Integrity.MUTABLE))
        after = snapshot(entry(digest="e" * 64, integrity=Integrity.MUTABLE))
        payload = classify_drift(before, after).to_dict()

        json.dumps(payload)
        assert payload["verdict"] == "refreshed"
        assert payload["undermines_decision"] is True
        assert payload["changed"][0]["integrity"] == "mutable"

    def test_a_changed_entry_carries_both_digests(self) -> None:
        """"It changed" is not actionable. "It changed from this to that" is."""
        before = snapshot(entry(integrity=Integrity.MUTABLE))
        after = snapshot(entry(digest="e" * 64, integrity=Integrity.MUTABLE))
        changed = classify_drift(before, after).changed[0]

        assert changed.digest_at_decision == "d" * 64
        assert changed.digest_now == "e" * 64
