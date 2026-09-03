"""Controlled retraining and candidate models (V5 Phase F).

A candidate is a trained model that is *not* serving and cannot begin serving by
existing. These tests hold that boundary:

- training a candidate never touches the active model;
- a candidate is registered in a state that inference will not load;
- training is reproducible, and the artifact digest proves it;
- nothing promotes a candidate merely because it was trained.
"""

from __future__ import annotations

import pytest

from app.models.enums import MLModelStatus


class TestCandidateStatuses:
    def test_the_lifecycle_states_exist(self) -> None:
        values = {status.value for status in MLModelStatus}
        assert {"candidate", "evaluating", "approved", "rejected", "rolled_back"} <= values

    def test_active_and_archived_are_preserved(self) -> None:
        """V3's states must survive: existing rows carry them."""
        assert MLModelStatus.ACTIVE.value == "active"
        assert MLModelStatus.ARCHIVED.value == "archived"
        assert MLModelStatus.FAILED.value == "failed"

    def test_only_approved_states_may_serve(self) -> None:
        from app.adaptation.candidates import lifecycle

        assert lifecycle.may_serve(MLModelStatus.APPROVED) is True
        assert lifecycle.may_serve(MLModelStatus.ACTIVE) is True
        # archived is the rollback target. Excluding it would make rollback
        # impossible, which would be the opposite of a safety property.
        assert lifecycle.may_serve(MLModelStatus.ARCHIVED) is True
        for status in (
            MLModelStatus.CANDIDATE,
            MLModelStatus.EVALUATING,
            MLModelStatus.REJECTED,
            MLModelStatus.ROLLED_BACK,
            MLModelStatus.FAILED,
        ):
            assert lifecycle.may_serve(status) is False, status


class TestCandidateTraining:
    def test_training_a_candidate_does_not_disturb_the_active_model(
        self, db, tmp_path
    ) -> None:
        """The central guarantee of the phase."""
        from app.adaptation.candidates import training
        from app.ml.registry import registry

        before = registry.get_active(db, "isolation_forest")
        before_identity = before.identity if before else None

        candidate = training.train_candidate(
            db,
            samples=400,
            seed=4242,
            directory=tmp_path,
            created_by="test",
        )

        after = registry.get_active(db, "isolation_forest")
        assert (after.identity if after else None) == before_identity
        assert candidate.status == MLModelStatus.CANDIDATE.value
        assert candidate.id != (before.id if before else None)

    def test_a_candidate_is_not_activated_by_being_trained(self, db, tmp_path) -> None:
        from app.adaptation.candidates import training

        candidate = training.train_candidate(
            db, samples=400, seed=4242, directory=tmp_path, created_by="test"
        )
        assert candidate.status != MLModelStatus.ACTIVE.value
        assert candidate.activated_at is None

    def test_training_is_reproducible(self, db, tmp_path) -> None:
        """Same seed, same corpus, same artifact digest. Without this a
        candidate's evaluation cannot be attributed to the candidate."""
        from app.adaptation.candidates import training

        first = training.train_candidate(
            db, samples=400, seed=99, directory=tmp_path / "a", created_by="test"
        )
        second = training.train_candidate(
            db, samples=400, seed=99, directory=tmp_path / "b", created_by="test"
        )
        assert first.artifact_sha256 == second.artifact_sha256

    def test_a_different_seed_produces_a_different_model(self, db, tmp_path) -> None:
        from app.adaptation.candidates import training

        first = training.train_candidate(
            db, samples=400, seed=1, directory=tmp_path / "c", created_by="test"
        )
        second = training.train_candidate(
            db, samples=400, seed=2, directory=tmp_path / "d", created_by="test"
        )
        assert first.artifact_sha256 != second.artifact_sha256

    def test_the_candidate_records_its_training_provenance(self, db, tmp_path) -> None:
        from app.adaptation.candidates import training

        candidate = training.train_candidate(
            db, samples=400, seed=4242, directory=tmp_path, created_by="operator@aegisx.dev"
        )

        assert candidate.parameters["seed"] == 4242
        assert candidate.dataset_fingerprint
        assert candidate.feature_schema_version
        assert candidate.artifact_sha256
        assert candidate.created_by == "operator@aegisx.dev"

    def test_a_candidate_never_overwrites_an_existing_artifact(self, db, tmp_path) -> None:
        from app.adaptation.candidates import training

        first = training.train_candidate(
            db, samples=400, seed=4242, directory=tmp_path, created_by="test"
        )
        second = training.train_candidate(
            db, samples=400, seed=4242, directory=tmp_path, created_by="test"
        )
        assert first.artifact_path != second.artifact_path


class TestCandidateIsolation:
    def test_the_inference_engine_refuses_to_load_a_candidate(self, db, tmp_path) -> None:
        """A candidate must not be able to serve, whatever asks it to."""
        from app.adaptation.candidates import training
        from app.ml.registry import registry
        from app.ml.registry.registry import RegistryError

        candidate = training.train_candidate(
            db, samples=400, seed=4242, directory=tmp_path, created_by="test"
        )

        with pytest.raises(RegistryError, match="not approved"):
            registry.activate_model(db, candidate)


class TestNoTrainingOverHttp:
    def test_no_endpoint_trains_a_candidate(self) -> None:
        from app.main import app

        schema = app.openapi()
        offenders = [
            path
            for path in schema["paths"]
            if "candidate" in path and "train" in path
        ]
        assert offenders == []


class TestPerCategoryEvaluation:
    """The gate added in V6 §10 is only useful if the evaluator supplies it."""

    def test_candidate_evaluation_reports_per_category_recall(
        self, db, tmp_path_factory
    ) -> None:
        from app.adaptation.candidates import evaluation, training
        from app.ml.registry import registry
        from app.models.enums import MLModelStatus

        directory = tmp_path_factory.mktemp("percat")
        incumbent = training.train_candidate(
            db, samples=600, seed=1337, directory=directory, created_by="test"
        )
        # Approved first: activate_model refuses anything else, which is the
        # invariant this suite must not route around.
        incumbent.status = MLModelStatus.APPROVED.value
        db.flush()
        registry.activate_model(db, incumbent)
        db.flush()
        candidate = training.train_candidate(
            db, samples=600, seed=4242, directory=directory, created_by="test"
        )

        report = evaluation.evaluate_candidate(
            db, candidate=candidate, samples_per_class=40
        )
        per_category = report["perCategory"]
        assert per_category, "per-category recall must be reported"
        for entry in per_category.values():
            assert "baselineRecall" in entry
            assert "candidateRecall" in entry
            assert "maliciousSamples" in entry

    def test_the_per_category_gate_is_no_longer_advisory_after_evaluation(
        self, db, tmp_path_factory
    ) -> None:
        """Once real per-category data exists the gate must actually bind,
        rather than remaining the advisory placeholder."""
        from app.adaptation.candidates import evaluation, training
        from app.ml.registry import registry
        from app.models.enums import MLModelStatus

        directory = tmp_path_factory.mktemp("percat2")
        incumbent = training.train_candidate(
            db, samples=600, seed=1337, directory=directory, created_by="test"
        )
        # Approved first: activate_model refuses anything else, which is the
        # invariant this suite must not route around.
        incumbent.status = MLModelStatus.APPROVED.value
        db.flush()
        registry.activate_model(db, incumbent)
        db.flush()
        candidate = training.train_candidate(
            db, samples=600, seed=4242, directory=directory, created_by="test"
        )

        report = evaluation.evaluate_candidate(
            db, candidate=candidate, samples_per_class=40
        )
        check = next(
            c for c in report["gates"]["checks"] if c["name"] == "per_category_recall"
        )
        assert not check["advisory"]
        assert check["status"] in {"ok", "failed"}
