"""Analyst feedback (V5 Phase B).

Feedback is the input to every adaptation decision AEGISX will later make, so
these tests hold the line on two things the rest of V5 depends on: a feedback
row is a *claim by a named analyst at a point in time*, not a fact, and it is
never rewritten in place.
"""

from __future__ import annotations

import pytest

from app.adaptation.feedback.labels import FeedbackLabel, FeedbackTargetType


class TestFeedbackVocabulary:
    def test_the_six_analyst_labels_exist(self) -> None:
        assert {label.value for label in FeedbackLabel} == {
            "true_positive",
            "false_positive",
            "benign",
            "suspicious",
            "confirmed_malicious",
            "uncertain",
        }

    def test_uncertain_is_not_a_verdict(self) -> None:
        """An uncertain label must never be counted as agreement or disagreement.

        Treating it as either is how a training set quietly acquires the
        analyst's hesitation as ground truth.
        """
        assert FeedbackLabel.UNCERTAIN.is_verdict is False
        assert FeedbackLabel.TRUE_POSITIVE.is_verdict is True
        assert FeedbackLabel.FALSE_POSITIVE.is_verdict is True

    def test_only_confident_labels_are_training_eligible(self) -> None:
        """Suspicious and uncertain describe a state of investigation, not a class."""
        eligible = {label for label in FeedbackLabel if label.is_training_eligible}
        assert eligible == {
            FeedbackLabel.TRUE_POSITIVE,
            FeedbackLabel.FALSE_POSITIVE,
            FeedbackLabel.BENIGN,
            FeedbackLabel.CONFIRMED_MALICIOUS,
        }

    def test_labels_carry_a_binary_projection_only_where_one_is_defined(self) -> None:
        assert FeedbackLabel.FALSE_POSITIVE.binary_label is False
        assert FeedbackLabel.BENIGN.binary_label is False
        assert FeedbackLabel.TRUE_POSITIVE.binary_label is True
        assert FeedbackLabel.CONFIRMED_MALICIOUS.binary_label is True
        assert FeedbackLabel.SUSPICIOUS.binary_label is None
        assert FeedbackLabel.UNCERTAIN.binary_label is None

    def test_feedback_targets_the_three_soc_objects(self) -> None:
        assert {target.value for target in FeedbackTargetType} == {
            "event",
            "incident",
            "sequence",
        }


class TestFeedbackSubmission:
    def test_submitting_feedback_records_the_analyst_and_the_time(self, db) -> None:
        from app.adaptation.feedback import service as feedback_service

        record = feedback_service.submit(
            db,
            target_type=FeedbackTargetType.EVENT,
            target_id=1,
            label=FeedbackLabel.FALSE_POSITIVE,
            analyst="analyst@aegisx.dev",
            confidence=0.8,
            comment="Backup job, runs nightly.",
        )

        assert record.id is not None
        assert record.label == FeedbackLabel.FALSE_POSITIVE.value
        assert record.analyst == "analyst@aegisx.dev"
        assert record.submitted_at is not None
        assert record.superseded_by_id is None

    def test_confidence_outside_zero_to_one_is_refused(self, db) -> None:
        from app.adaptation.feedback import service as feedback_service

        with pytest.raises(ValueError, match="confidence"):
            feedback_service.submit(
                db,
                target_type=FeedbackTargetType.EVENT,
                target_id=1,
                label=FeedbackLabel.BENIGN,
                analyst="analyst@aegisx.dev",
                confidence=1.4,
            )

    def test_feedback_records_the_feature_schema_it_was_given(self, db) -> None:
        """A label is only meaningful against the features the analyst saw.

        Without the schema version, feedback collected before a schema change
        would silently be pooled with feedback collected after it.
        """
        from app.adaptation.feedback import service as feedback_service

        record = feedback_service.submit(
            db,
            target_type=FeedbackTargetType.EVENT,
            target_id=2,
            label=FeedbackLabel.TRUE_POSITIVE,
            analyst="analyst@aegisx.dev",
        )

        assert record.feature_schema_version == "1.0"

    def test_an_unconfirmed_mitre_technique_is_refused(self, db) -> None:
        """MITRE provenance survives into V5: feedback may confirm a technique,
        it may not invent one that looks authoritative."""
        from app.adaptation.feedback import service as feedback_service

        with pytest.raises(ValueError, match="MITRE"):
            feedback_service.submit(
                db,
                target_type=FeedbackTargetType.EVENT,
                target_id=3,
                label=FeedbackLabel.TRUE_POSITIVE,
                analyst="analyst@aegisx.dev",
                mitre_techniques=["not-a-technique"],
            )


class TestFeedbackIsAppendOnly:
    def test_a_correction_supersedes_rather_than_edits(self, db) -> None:
        from app.adaptation.feedback import service as feedback_service

        original = feedback_service.submit(
            db,
            target_type=FeedbackTargetType.EVENT,
            target_id=10,
            label=FeedbackLabel.FALSE_POSITIVE,
            analyst="analyst@aegisx.dev",
        )
        original_id = original.id

        correction = feedback_service.correct(
            db,
            feedback_id=original_id,
            label=FeedbackLabel.TRUE_POSITIVE,
            analyst="senior@aegisx.dev",
            reason="Confirmed malicious on host review.",
        )

        db.refresh(original)
        assert correction.id != original_id
        assert correction.supersedes_id == original_id
        assert original.superseded_by_id == correction.id
        # The original claim is preserved exactly as it was made.
        assert original.label == FeedbackLabel.FALSE_POSITIVE.value
        assert original.analyst == "analyst@aegisx.dev"

    def test_superseded_feedback_is_excluded_from_the_active_set(self, db) -> None:
        from app.adaptation.feedback import service as feedback_service

        original = feedback_service.submit(
            db,
            target_type=FeedbackTargetType.EVENT,
            target_id=11,
            label=FeedbackLabel.FALSE_POSITIVE,
            analyst="analyst@aegisx.dev",
        )
        correction = feedback_service.correct(
            db,
            feedback_id=original.id,
            label=FeedbackLabel.TRUE_POSITIVE,
            analyst="senior@aegisx.dev",
            reason="Reviewed.",
        )

        active = feedback_service.active_for_target(
            db, target_type=FeedbackTargetType.EVENT, target_id=11
        )

        assert [row.id for row in active] == [correction.id]

    def test_correcting_an_already_superseded_row_is_refused(self, db) -> None:
        """Otherwise two corrections of one claim produce two 'current' answers."""
        from app.adaptation.feedback import service as feedback_service

        original = feedback_service.submit(
            db,
            target_type=FeedbackTargetType.EVENT,
            target_id=12,
            label=FeedbackLabel.BENIGN,
            analyst="analyst@aegisx.dev",
        )
        feedback_service.correct(
            db,
            feedback_id=original.id,
            label=FeedbackLabel.TRUE_POSITIVE,
            analyst="senior@aegisx.dev",
            reason="First correction.",
        )

        with pytest.raises(ValueError, match="superseded"):
            feedback_service.correct(
                db,
                feedback_id=original.id,
                label=FeedbackLabel.FALSE_POSITIVE,
                analyst="other@aegisx.dev",
                reason="Second correction of the same row.",
            )
