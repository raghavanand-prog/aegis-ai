"""Feedback datasets (V5 Phase C).

A feedback dataset is the bridge between "an analyst said this" and "a model was
trained on that". It must therefore be a *snapshot*: fixed at the moment it is
built, identified by a fingerprint over its contents, and unchanged by anything
that happens to the underlying feedback afterwards.

Without that, a model's training data is whatever the feedback table happens to
say today, and no result over it can be reproduced.
"""

from __future__ import annotations

import pytest

from app.adaptation.feedback import service as feedback_service
from app.adaptation.feedback.labels import FeedbackLabel, FeedbackTargetType


def _submit(db, target_id: int, label: FeedbackLabel, analyst: str = "a@aegisx.dev"):
    return feedback_service.submit(
        db,
        target_type=FeedbackTargetType.EVENT,
        target_id=target_id,
        label=label,
        analyst=analyst,
        source="simulation",
    )


class TestDatasetMembership:
    def test_only_training_eligible_labels_are_included(self, db) -> None:
        """Suspicious and uncertain describe an investigation, not a class."""
        from app.adaptation.feedback import datasets

        _submit(db, 5001, FeedbackLabel.TRUE_POSITIVE)
        _submit(db, 5002, FeedbackLabel.FALSE_POSITIVE)
        _submit(db, 5003, FeedbackLabel.SUSPICIOUS)
        _submit(db, 5004, FeedbackLabel.UNCERTAIN)

        dataset = datasets.build(db, name="phase-c-eligible", version="1.0", created_by="test")

        labels = {member.label for member in dataset.members}
        assert labels == {"true_positive", "false_positive"}
        assert dataset.sample_count == 2

    def test_superseded_feedback_is_excluded(self, db) -> None:
        from app.adaptation.feedback import datasets

        original = _submit(db, 5010, FeedbackLabel.FALSE_POSITIVE)
        feedback_service.correct(
            db,
            feedback_id=original.id,
            label=FeedbackLabel.TRUE_POSITIVE,
            analyst="senior@aegisx.dev",
            reason="Reviewed.",
        )

        dataset = datasets.build(db, name="phase-c-superseded", version="1.0", created_by="test")

        included = {member.feedback_id for member in dataset.members}
        assert original.id not in included

    def test_building_an_empty_dataset_is_refused(self, db) -> None:
        """A dataset with no samples is not a dataset, and training on one
        would fail later with a far less obvious message."""
        from app.adaptation.feedback import datasets

        with pytest.raises(ValueError, match="no training-eligible feedback"):
            datasets.build(
                db,
                name="phase-c-empty",
                version="1.0",
                created_by="test",
                sources=["nonexistent-source"],
            )


class TestDatasetFingerprint:
    def test_identical_membership_produces_an_identical_fingerprint(self, db) -> None:
        from app.adaptation.feedback import datasets

        _submit(db, 5100, FeedbackLabel.TRUE_POSITIVE)
        _submit(db, 5101, FeedbackLabel.BENIGN)

        first = datasets.build(db, name="phase-c-fp-a", version="1.0", created_by="test")
        second = datasets.build(db, name="phase-c-fp-b", version="1.0", created_by="test")

        assert first.fingerprint == second.fingerprint
        assert len(first.fingerprint) == 16

    def test_a_changed_label_changes_the_fingerprint(self, db) -> None:
        from app.adaptation.feedback import datasets

        _submit(db, 5200, FeedbackLabel.TRUE_POSITIVE)
        before = datasets.build(db, name="phase-c-fp-c", version="1.0", created_by="test")

        _submit(db, 5201, FeedbackLabel.FALSE_POSITIVE)
        after = datasets.build(db, name="phase-c-fp-d", version="1.0", created_by="test")

        assert before.fingerprint != after.fingerprint


class TestDatasetIsASnapshot:
    def test_correcting_feedback_does_not_change_a_built_dataset(self, db) -> None:
        """The whole point. A model trained on version 1.0 must still be able to
        say what 1.0 contained, even after every label in it was revised."""
        from app.adaptation.feedback import datasets

        original = _submit(db, 5300, FeedbackLabel.FALSE_POSITIVE)
        dataset = datasets.build(db, name="phase-c-snapshot", version="1.0", created_by="test")
        fingerprint_before = dataset.fingerprint
        members_before = {(m.feedback_id, m.label) for m in dataset.members}

        feedback_service.correct(
            db,
            feedback_id=original.id,
            label=FeedbackLabel.TRUE_POSITIVE,
            analyst="senior@aegisx.dev",
            reason="Revised after review.",
        )
        db.refresh(dataset)

        assert dataset.fingerprint == fingerprint_before
        assert {(m.feedback_id, m.label) for m in dataset.members} == members_before

    def test_members_record_the_binary_projection_used_at_build_time(self, db) -> None:
        from app.adaptation.feedback import datasets

        _submit(db, 5400, FeedbackLabel.CONFIRMED_MALICIOUS)
        _submit(db, 5401, FeedbackLabel.BENIGN)

        dataset = datasets.build(db, name="phase-c-binary", version="1.0", created_by="test")

        projection = {member.label: member.binary_label for member in dataset.members}
        assert projection["confirmed_malicious"] is True
        assert projection["benign"] is False


class TestDatasetIdentity:
    def test_the_same_name_and_version_cannot_hold_different_data(self, db) -> None:
        """Mirrors evaluation_datasets: fingerprint is part of the identity, so
        two different snapshots cannot both claim to be 'v1.0'."""
        from app.adaptation.feedback import datasets

        _submit(db, 5500, FeedbackLabel.TRUE_POSITIVE)
        datasets.build(db, name="phase-c-identity", version="1.0", created_by="test")

        _submit(db, 5501, FeedbackLabel.BENIGN)
        with pytest.raises(ValueError, match="already exists"):
            datasets.build(db, name="phase-c-identity", version="1.0", created_by="test")

    def test_rebuilding_identical_data_returns_the_existing_snapshot(self, db) -> None:
        from app.adaptation.feedback import datasets

        _submit(db, 5600, FeedbackLabel.TRUE_POSITIVE)
        first = datasets.build(db, name="phase-c-rebuild", version="1.0", created_by="test")
        again = datasets.build(db, name="phase-c-rebuild", version="1.0", created_by="test")

        assert again.id == first.id


class TestSchemaVersionIsolation:
    def test_feedback_from_two_feature_schemas_cannot_be_pooled(self, db) -> None:
        """A label is a claim about the features the analyst saw. Pooling across
        a schema change would train on inputs that never coexisted."""
        from app.adaptation.feedback import datasets
        from app.models.adaptation import AnalystFeedback

        first = _submit(db, 5700, FeedbackLabel.TRUE_POSITIVE)
        second = _submit(db, 5701, FeedbackLabel.BENIGN)
        db.query(AnalystFeedback).filter(AnalystFeedback.id == second.id).update(
            {"feature_schema_version": "2.0"}
        )
        db.flush()

        with pytest.raises(ValueError, match="feature schema"):
            datasets.build(db, name="phase-c-schema", version="1.0", created_by="test")

        # Restricting to one schema is allowed and records which one.
        dataset = datasets.build(
            db,
            name="phase-c-schema-scoped",
            version="1.0",
            created_by="test",
            feature_schema_version="1.0",
        )
        assert dataset.feature_schema_version == "1.0"
        assert first.id in {member.feedback_id for member in dataset.members}


class TestFeedbackDatasetAPI:
    """Read-only. Building a dataset is an operator action, not an HTTP call:
    it fixes what a model will be trained on, and that decision is recorded
    against a named operator on the CLI rather than any authenticated user."""

    def test_datasets_are_listable_by_a_viewer(self, client, auth_headers) -> None:
        response = client.get("/api/v1/adaptation/datasets", headers=auth_headers)
        assert response.status_code == 200, response.text
        assert isinstance(response.json(), list)

    def test_an_unknown_dataset_is_a_404(self, client, auth_headers) -> None:
        response = client.get("/api/v1/adaptation/datasets/987654321", headers=auth_headers)
        assert response.status_code == 404

    def test_no_endpoint_can_build_a_dataset(self) -> None:
        from app.main import app

        schema = app.openapi()
        dataset_paths = {
            path: methods
            for path, methods in schema["paths"].items()
            if "/adaptation/datasets" in path
        }
        assert dataset_paths, "the dataset API should be mounted"
        for path, methods in dataset_paths.items():
            assert set(methods) <= {"get"}, f"{path} exposes a write method: {sorted(methods)}"
