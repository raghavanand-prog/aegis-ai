"""Shadow evaluation, gated deployment and rollback (V5 Phase I).

Three properties, in order of how much damage their absence would do:

1. A candidate scored in shadow must not influence a single production
   decision. Shadow mode exists to answer "what would it have done" without
   anyone finding out the hard way.
2. A model reaches production only by deploying an approved proposal. Not by
   being trained, not by scoring well, not by being the newest row.
3. Whatever goes wrong, the currently approved model keeps serving.
"""

from __future__ import annotations

import pytest

from app.models.enums import MLModelStatus, ProposalStatus, ProposalType


@pytest.fixture()
def deployed_model(db, tmp_path_factory):
    """An incumbent to compare against and roll back to.

    Trained through the candidate path and then activated deliberately, because
    that is the only route a model can legitimately take to production.
    """
    from app.adaptation.candidates import training
    from app.ml.registry import registry
    from app.models.enums import MLModelStatus as Status

    existing = registry.get_active(db, "isolation_forest")
    if existing is not None:
        return existing

    directory = tmp_path_factory.mktemp("incumbent")
    model = training.train_candidate(
        db, samples=600, seed=1337, directory=directory, created_by="bootstrap"
    )
    model.status = Status.APPROVED.value
    db.flush()
    registry.activate_model(db, model)
    db.flush()
    return model


def _candidate(db, tmp_path, seed: int = 4242):
    from app.adaptation.candidates import training

    return training.train_candidate(
        db, samples=600, seed=seed, directory=tmp_path, created_by="operator@aegisx.dev"
    )


def _model_proposal(db, candidate, *, validation=None):
    from app.adaptation.proposals import service as proposals
    from app.ml.registry import registry

    active = registry.get_active(db, candidate.name)
    return proposals.create(
        db,
        proposal_type=ProposalType.MODEL_UPDATE,
        title=f"Deploy {candidate.identity}",
        reason="Candidate outperformed the incumbent on the labelled corpus.",
        affected_component=f"ml.model.{candidate.name}",
        before_state={"identity": active.identity if active else None},
        after_state={"identity": candidate.identity},
        evidence={"candidateDigest": candidate.artifact_sha256},
        validation=validation if validation is not None else {"gates": {"passed": True}},
        candidate_model_id=candidate.id,
        proposed_by="analyst@aegisx.dev",
    )


class TestShadowEvaluation:
    def test_shadow_scoring_compares_without_changing_production(self, db, tmp_path, deployed_model) -> None:
        from app.adaptation.candidates import shadow
        from app.ml.registry import registry

        candidate = _candidate(db, tmp_path)
        baseline = registry.get_active(db, candidate.name)
        assert baseline is not None, "the suite needs a deployed model"

        result = shadow.compare(db, candidate=candidate, baseline=baseline, samples_per_class=6)

        assert result["agreements"] + result["disagreements"] == result["samples"]
        assert result["samples"] > 0
        # The production model is untouched, and the candidate has not moved.
        db.refresh(candidate)
        assert registry.get_active(db, candidate.name).id == baseline.id
        assert candidate.status == MLModelStatus.CANDIDATE.value

    def test_shadow_reports_where_the_two_models_would_differ(self, db, tmp_path, deployed_model) -> None:
        from app.adaptation.candidates import shadow
        from app.ml.registry import registry

        candidate = _candidate(db, tmp_path)
        baseline = registry.get_active(db, candidate.name)
        result = shadow.compare(db, candidate=candidate, baseline=baseline, samples_per_class=6)

        assert "candidateOnlyFlags" in result
        assert "baselineOnlyFlags" in result
        assert result["interpretation"]

    def test_shadow_never_writes_an_inference_row(self, db, tmp_path, deployed_model) -> None:
        """A shadow score is not a detection. Persisting it as one would put a
        candidate's opinion into the record an analyst reads."""
        from app.adaptation.candidates import shadow
        from app.ml.registry import registry
        from app.models.ml import MLInference

        candidate = _candidate(db, tmp_path)
        baseline = registry.get_active(db, candidate.name)
        before = db.query(MLInference).count()

        shadow.compare(db, candidate=candidate, baseline=baseline, samples_per_class=6)

        assert db.query(MLInference).count() == before


class TestApprovalMarksTheModelApproved:
    def test_approving_a_model_proposal_makes_the_candidate_approved(
        self, db, tmp_path, deployed_model
    ) -> None:
        """The only route out of `candidate`. Without this the deployment step
        would have to bypass the lifecycle gate to do its job."""
        from app.adaptation.proposals import service as proposals

        candidate = _candidate(db, tmp_path)
        proposal = _model_proposal(db, candidate)
        proposals.approve(db, proposal.id, approved_by="admin@aegisx.dev")
        db.refresh(candidate)

        assert candidate.status == MLModelStatus.APPROVED.value

    def test_rejecting_a_model_proposal_marks_the_candidate_rejected(
        self, db, tmp_path, deployed_model
    ) -> None:
        from app.adaptation.proposals import service as proposals

        candidate = _candidate(db, tmp_path)
        proposal = _model_proposal(db, candidate)
        proposals.reject(
            db, proposal.id, rejected_by="admin@aegisx.dev", reason="FPR too high."
        )
        db.refresh(candidate)

        assert candidate.status == MLModelStatus.REJECTED.value


class TestDeployment:
    def test_deploying_an_approved_proposal_activates_the_candidate(
        self, db, tmp_path, deployed_model
    ) -> None:
        from app.adaptation.deployment import service as deployment
        from app.adaptation.proposals import service as proposals
        from app.ml.registry import registry

        candidate = _candidate(db, tmp_path)
        proposal = _model_proposal(db, candidate)
        proposals.approve(db, proposal.id, approved_by="admin@aegisx.dev")

        deployment.deploy(db, proposal.id, deployed_by="admin@aegisx.dev")

        db.refresh(candidate)
        db.refresh(proposal)
        assert registry.get_active(db, candidate.name).id == candidate.id
        assert candidate.status == MLModelStatus.ACTIVE.value
        assert proposal.status == ProposalStatus.DEPLOYED.value
        assert proposal.rollback_state

    def test_deploying_an_unapproved_proposal_is_refused(self, db, tmp_path, deployed_model) -> None:
        from app.adaptation.deployment import service as deployment
        from app.ml.registry import registry

        candidate = _candidate(db, tmp_path)
        proposal = _model_proposal(db, candidate)
        before = registry.get_active(db, candidate.name)

        with pytest.raises(ValueError, match="approved"):
            deployment.deploy(db, proposal.id, deployed_by="admin@aegisx.dev")

        assert registry.get_active(db, candidate.name).id == before.id

    def test_a_tampered_artifact_is_refused_and_production_keeps_serving(
        self, db, tmp_path, deployed_model
    ) -> None:
        """§52 fail-safe: if deployment cannot proceed, the currently approved
        model must remain active."""
        from pathlib import Path

        from app.adaptation.deployment import service as deployment
        from app.adaptation.proposals import service as proposals
        from app.ml.registry import registry

        candidate = _candidate(db, tmp_path)
        proposal = _model_proposal(db, candidate)
        proposals.approve(db, proposal.id, approved_by="admin@aegisx.dev")
        before = registry.get_active(db, candidate.name)

        Path(candidate.artifact_path).write_bytes(b"tampered")

        with pytest.raises(ValueError, match="digest"):
            deployment.deploy(db, proposal.id, deployed_by="admin@aegisx.dev")

        assert registry.get_active(db, candidate.name).id == before.id
        db.refresh(proposal)
        assert proposal.status == ProposalStatus.APPROVED.value


class TestRollback:
    def test_rollback_restores_the_previous_model(self, db, tmp_path, deployed_model) -> None:
        from app.adaptation.deployment import service as deployment
        from app.adaptation.proposals import service as proposals
        from app.ml.registry import registry

        candidate = _candidate(db, tmp_path)
        previous = registry.get_active(db, candidate.name)
        proposal = _model_proposal(db, candidate)
        proposals.approve(db, proposal.id, approved_by="admin@aegisx.dev")
        deployment.deploy(db, proposal.id, deployed_by="admin@aegisx.dev")

        deployment.rollback(
            db, proposal.id, rolled_back_by="admin@aegisx.dev", reason="FPR spike."
        )

        db.refresh(proposal)
        db.refresh(candidate)
        assert registry.get_active(db, candidate.name).id == previous.id
        assert proposal.status == ProposalStatus.ROLLED_BACK.value
        # The withdrawn model is not archived: it failed in production, and that
        # is a different fact worth keeping.
        assert candidate.status == MLModelStatus.ROLLED_BACK.value

    def test_rolling_back_an_undeployed_proposal_is_refused(self, db, tmp_path, deployed_model) -> None:
        from app.adaptation.deployment import service as deployment
        from app.adaptation.proposals import service as proposals

        candidate = _candidate(db, tmp_path)
        proposal = _model_proposal(db, candidate)
        proposals.approve(db, proposal.id, approved_by="admin@aegisx.dev")

        with pytest.raises(ValueError, match="deployed"):
            deployment.rollback(
                db, proposal.id, rolled_back_by="admin@aegisx.dev", reason="x"
            )


ANALYST = {"email": "analyst.deploy@aegisx.dev", "password": "AnalystPassw0rd!"}


def _analyst_headers(client, admin_headers):
    client.post(
        "/api/v1/auth/users",
        json={
            "email": ANALYST["email"],
            "password": ANALYST["password"],
            "fullName": "Analyst",
            "role": "analyst",
        },
        headers=admin_headers,
    )
    response = client.post("/api/v1/auth/login", json=ANALYST)
    assert response.status_code == 200, response.text
    return {"Authorization": f"Bearer {response.json()['accessToken']}"}


def _api_proposal(client, headers):
    return client.post(
        "/api/v1/adaptation/proposals",
        json={
            "proposalType": "threshold_update",
            "title": "Raise the anomaly threshold",
            "reason": "False positives on backup traffic.",
            "affectedComponent": "ml.anomaly_threshold",
            "beforeState": {"threshold": 0.65},
            "afterState": {"threshold": 0.68},
            "evidence": {"feedbackIds": [1]},
        },
        headers=headers,
    ).json()


class TestDeploymentAPI:
    def test_an_analyst_may_not_deploy(self, client, auth_headers) -> None:
        analyst = _analyst_headers(client, auth_headers)
        created = _api_proposal(client, analyst)
        client.post(
            f"/api/v1/adaptation/proposals/{created['id']}/approve", headers=auth_headers
        )

        denied = client.post(
            f"/api/v1/adaptation/proposals/{created['id']}/deploy", headers=analyst
        )
        assert denied.status_code == 403

    def test_deploying_an_unapproved_proposal_is_a_conflict(
        self, client, auth_headers
    ) -> None:
        created = _api_proposal(client, auth_headers)
        response = client.post(
            f"/api/v1/adaptation/proposals/{created['id']}/deploy", headers=auth_headers
        )
        assert response.status_code == 409

    def test_deployment_and_rollback_are_audited(self, client, auth_headers) -> None:
        created = _api_proposal(client, auth_headers)
        client.post(
            f"/api/v1/adaptation/proposals/{created['id']}/approve", headers=auth_headers
        )
        deployed = client.post(
            f"/api/v1/adaptation/proposals/{created['id']}/deploy", headers=auth_headers
        )
        assert deployed.status_code == 200, deployed.text
        assert deployed.json()["status"] == "deployed"

        rolled = client.post(
            f"/api/v1/adaptation/proposals/{created['id']}/rollback",
            json={"reason": "False positives rose after the change."},
            headers=auth_headers,
        )
        assert rolled.status_code == 200, rolled.text
        assert rolled.json()["status"] == "rolled_back"

        for action in ("adaptation.proposal_deployed", "adaptation.proposal_rolled_back"):
            audit = client.get(
                "/api/v1/audit", params={"action": action}, headers=auth_headers
            )
            assert action in [entry["action"] for entry in audit.json()["items"]], action

    def test_rollback_requires_a_reason(self, client, auth_headers) -> None:
        created = _api_proposal(client, auth_headers)
        client.post(
            f"/api/v1/adaptation/proposals/{created['id']}/approve", headers=auth_headers
        )
        client.post(
            f"/api/v1/adaptation/proposals/{created['id']}/deploy", headers=auth_headers
        )
        response = client.post(
            f"/api/v1/adaptation/proposals/{created['id']}/rollback",
            json={"reason": ""},
            headers=auth_headers,
        )
        assert response.status_code == 422
