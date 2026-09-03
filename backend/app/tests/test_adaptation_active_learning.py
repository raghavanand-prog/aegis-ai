"""Active learning (V5 Phase E).

Active learning here answers exactly one question: *which events would an
analyst's time be best spent on?* It ranks and explains. It never labels, never
trains, and never adds anything to a dataset.

That boundary is the whole reason the module is separate from Phase F. The
failure mode it exists to prevent is a system that decides a sample is
interesting and then decides what its label should be.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.adaptation.active_learning import selectors


def _ingest(client: TestClient, auth_headers: dict, **overrides) -> dict:
    """Put one event through the real ingestion path.

    Real ingestion rather than a fixture row on purpose: the review queue reads
    detection_rules and ML inferences, and both are produced by that path.
    """
    payload = {
        "source": "Sysmon",
        "sourceType": "endpoint",
        "eventType": "process_creation",
        "title": "Process created: powershell.exe",
        "description": "Encoded PowerShell launched from Word.",
        "severity": "Low",
        "hostname": "SYN-WIN-100",
        "username": "al.tester",
        "process": "powershell.exe",
        "commandLine": "powershell.exe -nop -w hidden -enc " + "Q" * 64,
        "rawLog": "[Sysmon:1] SYN-WIN-100 encoded PowerShell",
        "normalizedData": {"parent_image": "winword.exe"},
    }
    payload.update(overrides)
    response = client.post("/api/v1/events", json=payload, headers=auth_headers)
    assert response.status_code == 201, response.text
    return response.json()


class TestUncertainty:
    def test_a_score_at_the_threshold_is_maximally_uncertain(self) -> None:
        assert selectors.uncertainty(0.65, threshold=0.65) == pytest.approx(1.0)

    def test_confident_scores_are_less_uncertain_than_borderline_ones(self) -> None:
        borderline = selectors.uncertainty(0.64, threshold=0.65)
        confident = selectors.uncertainty(0.05, threshold=0.65)
        assert borderline > confident

    def test_uncertainty_is_symmetric_around_the_threshold(self) -> None:
        """A near miss and a near hit are equally worth an analyst's attention."""
        assert selectors.uncertainty(0.60, threshold=0.65) == pytest.approx(
            selectors.uncertainty(0.70, threshold=0.65)
        )

    def test_uncertainty_is_bounded(self) -> None:
        for score in (0.0, 0.25, 0.65, 0.9, 1.0):
            assert 0.0 <= selectors.uncertainty(score, threshold=0.65) <= 1.0


class TestDisagreement:
    def test_rules_and_ml_disagreeing_is_the_strongest_signal(self) -> None:
        """Where the two independent detectors disagree, one of them is wrong,
        and which one is a question only a human can settle."""
        assert selectors.disagreement(rule_hit=True, ml_flagged=False) == 1.0
        assert selectors.disagreement(rule_hit=False, ml_flagged=True) == 1.0

    def test_agreement_carries_no_review_value(self) -> None:
        assert selectors.disagreement(rule_hit=True, ml_flagged=True) == 0.0
        assert selectors.disagreement(rule_hit=False, ml_flagged=False) == 0.0


class TestCandidateSelection:
    def test_candidates_are_ranked_and_every_one_carries_a_reason(
        self, db, client, auth_headers
    ) -> None:
        from app.adaptation.active_learning import service

        _ingest(client, auth_headers, title="Active learning ranking probe")
        candidates = service.select_candidates(db, limit=10)
        assert candidates, "the queue should offer something to review"

        for candidate in candidates:
            assert candidate.reason, "a candidate without a reason cannot be triaged"
            assert 0.0 <= candidate.priority <= 1.0
        priorities = [candidate.priority for candidate in candidates]
        assert priorities == sorted(priorities, reverse=True)

    def test_events_that_already_have_feedback_are_not_asked_about_again(
        self, db, client, auth_headers
    ) -> None:
        from app.adaptation.active_learning import service
        from app.adaptation.feedback import service as feedback_service
        from app.adaptation.feedback.labels import FeedbackLabel, FeedbackTargetType
        from app.models.event import Event

        created = _ingest(client, auth_headers, title="Active learning exclusion probe")
        event = db.query(Event).filter(Event.event_id == created["id"]).one()

        before = {candidate.event_id for candidate in service.select_candidates(db, limit=500)}
        feedback_service.submit(
            db,
            target_type=FeedbackTargetType.EVENT,
            target_id=event.id,
            label=FeedbackLabel.BENIGN,
            analyst="analyst@aegisx.dev",
        )
        after = {candidate.event_id for candidate in service.select_candidates(db, limit=500)}

        assert event.id not in after
        assert before - after == {event.id} or event.id not in before

    def test_selection_is_deterministic(self, db, client, auth_headers) -> None:
        from app.adaptation.active_learning import service

        first = [c.event_id for c in service.select_candidates(db, limit=20)]
        second = [c.event_id for c in service.select_candidates(db, limit=20)]
        assert first == second

    def test_the_limit_is_respected(self, db, client, auth_headers) -> None:
        from app.adaptation.active_learning import service

        assert len(service.select_candidates(db, limit=3)) <= 3


class TestSelectionNeverTrains:
    def test_selecting_candidates_writes_nothing(self, db, client, auth_headers) -> None:
        """The hard line for this phase: a recommendation is not a label, and a
        label is not a training set. Selection must leave no trace."""
        from app.adaptation.active_learning import service
        from app.models.adaptation import AnalystFeedback, FeedbackDataset
        from app.models.ml import MLModel

        counts_before = (
            db.query(AnalystFeedback).count(),
            db.query(FeedbackDataset).count(),
            db.query(MLModel).count(),
        )
        service.select_candidates(db, limit=50)
        counts_after = (
            db.query(AnalystFeedback).count(),
            db.query(FeedbackDataset).count(),
            db.query(MLModel).count(),
        )
        assert counts_before == counts_after


class TestActiveLearningAPI:
    def test_the_review_queue_is_readable(self, client, auth_headers) -> None:
        response = client.get("/api/v1/adaptation/review-queue", headers=auth_headers)
        assert response.status_code == 200, response.text
        body = response.json()
        assert "candidates" in body
        assert "interpretation" in body

    def test_the_queue_says_it_is_a_recommendation_not_a_label(
        self, client, auth_headers
    ) -> None:
        response = client.get("/api/v1/adaptation/review-queue", headers=auth_headers)
        assert "recommend" in response.json()["interpretation"].lower()

    def test_no_endpoint_can_add_a_sample_to_training(self) -> None:
        from app.main import app

        schema = app.openapi()
        queue_paths = {
            path: methods
            for path, methods in schema["paths"].items()
            if "review-queue" in path
        }
        assert queue_paths, "the review queue should be mounted"
        for path, methods in queue_paths.items():
            assert set(methods) <= {"get"}, f"{path} exposes a write method: {sorted(methods)}"
