"""Adjudication: the step between a feedback record and a training set (V7).

Before V7 there was no such step. ``datasets.build`` took every current
training-eligible row, so two analysts who disagreed about one event produced
two dataset members with opposite ``binary_label`` and a model was fitted on
both answers, silently. ``TestDisagreementReachesNoVerdict`` and
``TestDatasetsRefuseUnadjudicatedFeedback`` are the tests that would have caught
that; the rest hold the properties the fix depends on.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from app.adaptation.feedback import adjudication, datasets
from app.adaptation.feedback import service as feedback_service
from app.adaptation.feedback.adjudication import ConsensusStatus
from app.adaptation.feedback.labels import FeedbackLabel, FeedbackTargetType
from app.models.adaptation import AnalystFeedback


def _submit(db, target_id: int, label: FeedbackLabel, analyst: str, **kwargs):
    return feedback_service.submit(
        db,
        target_type=FeedbackTargetType.EVENT,
        target_id=target_id,
        label=label,
        analyst=analyst,
        source="simulation",
        **kwargs,
    )


def _vote(analyst: str, label: FeedbackLabel, confidence: float | None = None):
    return adjudication.AnalystVote(
        analyst=analyst,
        feedback_id=abs(hash(analyst)) % 10_000,
        label=label.value,
        binary_label=label.binary_label,
        confidence=confidence,
    )


def _adjudicate(votes, **kwargs):
    return adjudication.adjudicate(votes, target_type="event", target_id=1, **kwargs)


class TestAgreementReachesAVerdict:
    def test_a_single_claim_is_unanimous(self) -> None:
        verdict = _adjudicate([_vote("a@x", FeedbackLabel.CONFIRMED_MALICIOUS)])

        assert verdict.status is ConsensusStatus.UNANIMOUS
        assert verdict.binary_label is True
        assert verdict.is_training_eligible

    def test_analysts_agreeing_reach_one_verdict(self) -> None:
        verdict = _adjudicate(
            [
                _vote("a@x", FeedbackLabel.FALSE_POSITIVE),
                _vote("b@x", FeedbackLabel.BENIGN),
            ]
        )

        # Different labels, same position on the axis that matters.
        assert verdict.status is ConsensusStatus.UNANIMOUS
        assert verdict.binary_label is False
        assert verdict.agreeing == 2
        assert verdict.dissenting == 0


class TestDisagreementReachesNoVerdict:
    def test_conflicting_analysts_produce_no_label(self) -> None:
        """The defect this module exists for.

        Two analysts, opposite conclusions, neither superseded. Before V7 both
        rows became training members with opposite binary labels.
        """
        verdict = _adjudicate(
            [
                _vote("a@x", FeedbackLabel.TRUE_POSITIVE),
                _vote("b@x", FeedbackLabel.FALSE_POSITIVE),
            ]
        )

        assert verdict.status is ConsensusStatus.CONFLICTED
        assert verdict.binary_label is None
        assert not verdict.is_training_eligible

    def test_the_split_is_reported_even_though_it_is_unresolved(self) -> None:
        """A conflicted target still has to be legible to whoever reviews it."""
        verdict = _adjudicate(
            [
                _vote("a@x", FeedbackLabel.TRUE_POSITIVE),
                _vote("b@x", FeedbackLabel.TRUE_POSITIVE),
                _vote("c@x", FeedbackLabel.BENIGN),
            ]
        )

        assert verdict.status is ConsensusStatus.CONFLICTED
        assert verdict.agreeing == 2
        assert verdict.dissenting == 1
        assert verdict.binary_label is None

    def test_a_majority_carries_only_under_the_majority_policy(self) -> None:
        votes = [
            _vote("a@x", FeedbackLabel.CONFIRMED_MALICIOUS),
            _vote("b@x", FeedbackLabel.TRUE_POSITIVE),
            _vote("c@x", FeedbackLabel.BENIGN),
        ]

        assert _adjudicate(votes).status is ConsensusStatus.CONFLICTED

        resolved = _adjudicate(votes, policy=adjudication.POLICY_MAJORITY)
        assert resolved.status is ConsensusStatus.MAJORITY
        assert resolved.binary_label is True
        assert resolved.is_training_eligible

    def test_a_tie_is_conflicted_under_every_policy(self) -> None:
        votes = [
            _vote("a@x", FeedbackLabel.TRUE_POSITIVE),
            _vote("b@x", FeedbackLabel.BENIGN),
        ]

        for policy in adjudication.POLICIES:
            assert _adjudicate(votes, policy=policy).status is ConsensusStatus.CONFLICTED


class TestAbstentionsAreNotAgreement:
    def test_only_abstentions_is_insufficient_not_benign(self) -> None:
        """`suspicious` and `uncertain` carry no position. Counting either as a
        side would record an analyst's hesitation as a conclusion."""
        verdict = _adjudicate(
            [
                _vote("a@x", FeedbackLabel.SUSPICIOUS),
                _vote("b@x", FeedbackLabel.UNCERTAIN),
            ]
        )

        assert verdict.status is ConsensusStatus.INSUFFICIENT
        assert verdict.binary_label is None
        assert verdict.abstaining == 2
        assert not verdict.is_training_eligible

    def test_an_abstention_does_not_break_agreement(self) -> None:
        verdict = _adjudicate(
            [
                _vote("a@x", FeedbackLabel.BENIGN),
                _vote("b@x", FeedbackLabel.UNCERTAIN),
            ]
        )

        assert verdict.status is ConsensusStatus.UNANIMOUS
        assert verdict.binary_label is False
        assert verdict.abstaining == 1
        assert verdict.agreeing == 1

    def test_no_feedback_at_all_is_insufficient(self) -> None:
        assert _adjudicate([]).status is ConsensusStatus.INSUFFICIENT


class TestConfidenceIsReportedNotDecisive:
    def test_a_confident_minority_does_not_win(self) -> None:
        """Confidence is self-reported. Letting it settle a disagreement would
        let one over-confident analyst overrule two careful ones."""
        verdict = _adjudicate(
            [
                _vote("loud@x", FeedbackLabel.TRUE_POSITIVE, confidence=1.0),
                _vote("a@x", FeedbackLabel.BENIGN, confidence=0.2),
                _vote("b@x", FeedbackLabel.BENIGN, confidence=0.2),
            ],
            policy=adjudication.POLICY_MAJORITY,
        )

        assert verdict.binary_label is False
        assert verdict.agreeing == 2

    def test_the_weight_behind_each_side_is_available(self) -> None:
        verdict = _adjudicate(
            [
                _vote("a@x", FeedbackLabel.BENIGN, confidence=0.9),
                _vote("b@x", FeedbackLabel.BENIGN, confidence=0.5),
            ]
        )

        assert verdict.agreeing_weight == pytest.approx(1.4)
        assert verdict.dissenting_weight == 0.0

    def test_an_unstated_confidence_contributes_nothing(self) -> None:
        """A null confidence is not 1.0. Treating it as certainty would invent
        a claim the analyst never made."""
        verdict = _adjudicate(
            [
                _vote("a@x", FeedbackLabel.BENIGN, confidence=None),
                _vote("b@x", FeedbackLabel.BENIGN, confidence=0.5),
            ]
        )

        assert verdict.agreeing_weight == pytest.approx(0.5)
        assert verdict.agreeing == 2


class TestOneAnalystHasOneVoice:
    def test_repeated_claims_by_one_analyst_count_once(self, db) -> None:
        """Otherwise a single person outvotes a colleague by being verbose."""
        _submit(db, 7101, FeedbackLabel.BENIGN, "loud@x")
        _submit(db, 7101, FeedbackLabel.BENIGN, "loud@x")
        _submit(db, 7101, FeedbackLabel.TRUE_POSITIVE, "other@x")

        verdict = adjudication.for_target(
            db, target_type=FeedbackTargetType.EVENT, target_id=7101
        )

        assert len(verdict.votes) == 2
        assert verdict.status is ConsensusStatus.CONFLICTED

    def test_the_latest_claim_is_the_one_that_counts(self, db) -> None:
        _submit(db, 7102, FeedbackLabel.TRUE_POSITIVE, "a@x")
        _submit(db, 7102, FeedbackLabel.BENIGN, "a@x")

        verdict = adjudication.for_target(
            db, target_type=FeedbackTargetType.EVENT, target_id=7102
        )

        assert verdict.status is ConsensusStatus.UNANIMOUS
        assert verdict.binary_label is False

    def test_a_superseded_claim_is_not_a_vote(self, db) -> None:
        original = _submit(db, 7103, FeedbackLabel.TRUE_POSITIVE, "a@x")
        feedback_service.correct(
            db,
            feedback_id=original.id,
            label=FeedbackLabel.FALSE_POSITIVE,
            analyst="a@x",
            reason="Reviewed the host; it was a backup job.",
        )

        verdict = adjudication.for_target(
            db, target_type=FeedbackTargetType.EVENT, target_id=7103
        )

        assert verdict.status is ConsensusStatus.UNANIMOUS
        assert verdict.binary_label is False


class TestDatasetsRefuseUnadjudicatedFeedback:
    def test_a_disputed_target_contributes_nothing(self, db) -> None:
        """The end-to-end form of the defect: a contradiction must not become
        two training examples."""
        _submit(db, 7201, FeedbackLabel.TRUE_POSITIVE, "a@x")
        _submit(db, 7201, FeedbackLabel.FALSE_POSITIVE, "b@x")
        _submit(db, 7202, FeedbackLabel.BENIGN, "a@x")

        dataset = datasets.build(db, name="v7-conflict", version="1.0", created_by="test")

        assert dataset.sample_count == 1
        assert {member.target_id for member in dataset.members} == {7202}

    def test_the_exclusion_is_recorded_not_silent(self, db) -> None:
        """A snapshot that quietly dropped a disputed target would hide the
        disagreement as effectively as one that trained on it."""
        _submit(db, 7211, FeedbackLabel.TRUE_POSITIVE, "a@x")
        _submit(db, 7211, FeedbackLabel.FALSE_POSITIVE, "b@x")
        _submit(db, 7212, FeedbackLabel.BENIGN, "a@x")

        dataset = datasets.build(db, name="v7-provenance", version="1.0", created_by="test")

        recorded = dataset.selection["adjudication"]
        assert recorded["policy"] == adjudication.POLICY_UNANIMOUS
        assert recorded["conflictedTargets"] == ["event:7211"]
        assert recorded["excludedRows"] == 2
        assert recorded["targets"] == 2

    def test_a_wholly_disputed_selection_is_refused(self, db) -> None:
        _submit(db, 7221, FeedbackLabel.TRUE_POSITIVE, "a@x")
        _submit(db, 7221, FeedbackLabel.FALSE_POSITIVE, "b@x")

        with pytest.raises(ValueError, match="no adjudicated feedback"):
            datasets.build(db, name="v7-all-conflict", version="1.0", created_by="test")

    def test_the_losing_minority_does_not_travel_under_majority(self, db) -> None:
        """Under the majority policy the verdict is one label, so the dissenting
        rows must not arrive carrying the opposite one."""
        _submit(db, 7231, FeedbackLabel.BENIGN, "a@x")
        _submit(db, 7231, FeedbackLabel.BENIGN, "b@x")
        _submit(db, 7231, FeedbackLabel.TRUE_POSITIVE, "c@x")

        dataset = datasets.build(
            db,
            name="v7-majority",
            version="1.0",
            created_by="test",
            adjudication_policy=adjudication.POLICY_MAJORITY,
        )

        assert dataset.sample_count == 2
        assert {member.binary_label for member in dataset.members} == {False}

    def test_agreement_is_unaffected(self, db) -> None:
        """Adjudication must not change what an undisputed selection contains -
        otherwise it would move every result built on one."""
        _submit(db, 7241, FeedbackLabel.TRUE_POSITIVE, "a@x")
        _submit(db, 7242, FeedbackLabel.FALSE_POSITIVE, "a@x")
        _submit(db, 7243, FeedbackLabel.BENIGN, "b@x")

        dataset = datasets.build(db, name="v7-agree", version="1.0", created_by="test")

        assert dataset.sample_count == 3
        assert dataset.selection["adjudication"]["conflictedTargets"] == []


class TestAnalystIdentityIsAuditable:
    def test_identity_and_role_are_recorded_when_supplied(self, db) -> None:
        record = _submit(
            db, 7301, FeedbackLabel.BENIGN, "a@x", analyst_id=42, analyst_role="analyst"
        )

        assert record.analyst_id == 42
        assert record.analyst_role == "analyst"

    def test_simulated_feedback_has_no_account(self, db) -> None:
        """A null is a fact here, not a gap: minting a synthetic user would make
        a generated claim indistinguishable from a human's."""
        record = _submit(db, 7302, FeedbackLabel.BENIGN, "sim")

        assert record.analyst_id is None
        assert record.analyst_role is None

    def test_a_correction_is_attributed_to_whoever_made_it(self, db) -> None:
        original = _submit(
            db, 7303, FeedbackLabel.TRUE_POSITIVE, "junior@x", analyst_id=1,
            analyst_role="analyst",
        )
        correction = feedback_service.correct(
            db,
            feedback_id=original.id,
            label=FeedbackLabel.FALSE_POSITIVE,
            analyst="senior@x",
            analyst_id=2,
            analyst_role="admin",
            reason="Confirmed benign with the host owner.",
        )

        assert correction.analyst_id == 2
        assert correction.analyst_role == "admin"
        # The original is untouched: it still records what the junior analyst
        # concluded, and under what authority.
        assert original.analyst_id == 1
        assert original.analyst_role == "analyst"


@pytest.fixture()
def an_event(db):
    """An event the feedback API can address, created without ingestion.

    Deliberately **not** `POST /api/v1/events`. That path queues the event to the
    background enrichment worker, which runs correlation on its own session and
    commits on its own thread - so an API-ingested event keeps being written to
    after the test that made it has finished. Combined with the suite's shared
    database that is a race, and it is one this module is especially placed to
    lose: it sorts near the front, so anything it leaves running overlaps almost
    everything else.

    Creating the row directly gives the API something real to resolve while
    touching nothing else, and the row is removed afterwards because the
    endpoint under test commits.
    """
    from app.models.event import Event
    from app.repositories.event_repository import event_repository

    event = event_repository.create(
        db,
        Event(
            timestamp=datetime.now(timezone.utc),
            source="Sysmon",
            source_type="endpoint",
            event_type="process_creation",
            title="Process created: powershell.exe",
            severity="Low",
            status="New",
            risk_score=10,
            risk_level="Low",
            risk_signals=[],
            hostname="V7-ADJ-001",
            username="v7.adjudication",
            raw_log="[Sysmon:1] V7-ADJ-001 adjudication fixture",
            normalized_data={},
            mitre_techniques=[],
            detection_rules=[],
            detections=[],
        ),
    )
    db.commit()
    yield event

    db.query(AnalystFeedback).filter(
        AnalystFeedback.target_type == "event",
        AnalystFeedback.target_id == event.id,
    ).delete(synchronize_session=False)
    db.delete(event)
    db.commit()


class TestApiRecordsTheAuthenticatedUser:
    def test_submitting_feedback_records_identity_and_role(
        self, client, auth_headers, an_event
    ) -> None:
        """Identity comes from the authenticated session, never the payload -
        a claim able to name its own author would not be evidence about
        anything."""
        response = client.post(
            "/api/v1/adaptation/feedback",
            headers=auth_headers,
            json={
                "targetType": "event",
                "targetId": an_event.event_id,
                "label": "benign",
                "comment": "Known maintenance window.",
            },
        )

        assert response.status_code == 201, response.text
        body = response.json()
        assert body["analystId"] is not None
        assert body["analystRole"] in {"admin", "analyst", "viewer"}
        assert body["analyst"].endswith("@aegisx.dev")
