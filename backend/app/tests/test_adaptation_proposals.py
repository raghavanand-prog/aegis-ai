"""Adaptation proposals and the approval workflow (V5 Phase H).

This is where the human-in-the-loop requirement stops being a convention and
becomes structural. A proposal is the only route from "the system noticed
something" to "production behaviour changed", and it cannot travel that route
without a named person approving it.

The state machine is the safety property:

    pending -> approved -> deployed
            -> rejected
                          -> rolled_back

Nothing skips a step. Nothing self-approves. Nothing deploys because it scored
well.
"""

from __future__ import annotations

import pytest

from app.adaptation.proposals import service as proposals
from app.models.enums import ProposalStatus, ProposalType


class TestProposalVocabulary:
    def test_the_proposal_types_cover_what_v5_may_propose(self) -> None:
        assert {kind.value for kind in ProposalType} == {
            "model_update",
            "threshold_update",
            "feature_config_update",
            "detection_rule_recommendation",
            "correlation_pattern_recommendation",
        }

    def test_the_lifecycle_states_exist(self) -> None:
        assert {status.value for status in ProposalStatus} == {
            "pending",
            "approved",
            "rejected",
            "deployed",
            "rolled_back",
            "superseded",
        }


class TestProposalCreation:
    def test_a_proposal_records_everything_needed_to_review_it(self, db) -> None:
        proposal = proposals.create(
            db,
            proposal_type=ProposalType.THRESHOLD_UPDATE,
            title="Raise the anomaly threshold to 0.68",
            reason="Observed false-positive clustering on backup traffic.",
            affected_component="ml.anomaly_threshold",
            before_state={"threshold": 0.65},
            after_state={"threshold": 0.68},
            evidence={"feedbackIds": [1, 2, 3], "falsePositiveRate": 0.53},
            expected_impact={"fprChange": -0.12, "recallChange": -0.02},
            risk_assessment="Recall may fall on low-scoring true positives.",
            proposed_by="analyst@aegisx.dev",
        )

        assert proposal.id is not None
        assert proposal.status == ProposalStatus.PENDING.value
        assert proposal.proposed_by == "analyst@aegisx.dev"
        assert proposal.approved_by is None
        assert proposal.before_state == {"threshold": 0.65}
        assert proposal.after_state == {"threshold": 0.68}

    def test_a_proposal_without_evidence_is_refused(self, db) -> None:
        """A proposal is a request to change what the platform detects. Without
        evidence it is an opinion, and an approver has nothing to weigh."""
        with pytest.raises(ValueError, match="evidence"):
            proposals.create(
                db,
                proposal_type=ProposalType.THRESHOLD_UPDATE,
                title="Raise the threshold",
                reason="It feels high.",
                affected_component="ml.anomaly_threshold",
                before_state={"threshold": 0.65},
                after_state={"threshold": 0.68},
                evidence={},
                proposed_by="analyst@aegisx.dev",
            )

    def test_a_proposal_that_changes_nothing_is_refused(self, db) -> None:
        with pytest.raises(ValueError, match="identical"):
            proposals.create(
                db,
                proposal_type=ProposalType.THRESHOLD_UPDATE,
                title="Change nothing",
                reason="No-op.",
                affected_component="ml.anomaly_threshold",
                before_state={"threshold": 0.65},
                after_state={"threshold": 0.65},
                evidence={"note": "x"},
                proposed_by="analyst@aegisx.dev",
            )


class TestApproval:
    def _pending(self, db, **overrides):
        payload = {
            "proposal_type": ProposalType.THRESHOLD_UPDATE,
            "title": "Raise the anomaly threshold",
            "reason": "False positives on backup traffic.",
            "affected_component": "ml.anomaly_threshold",
            "before_state": {"threshold": 0.65},
            "after_state": {"threshold": 0.68},
            "evidence": {"feedbackIds": [1]},
            "proposed_by": "analyst@aegisx.dev",
        }
        payload.update(overrides)
        return proposals.create(db, **payload)

    def test_approval_records_a_different_actor_from_the_proposer(self, db) -> None:
        proposal = self._pending(db)
        approved = proposals.approve(db, proposal.id, approved_by="admin@aegisx.dev", approver_role="admin")

        assert approved.status == ProposalStatus.APPROVED.value
        assert approved.approved_by == "admin@aegisx.dev"
        assert approved.proposed_by == "analyst@aegisx.dev"
        assert approved.approved_at is not None

    def test_self_approval_is_refused(self, db) -> None:
        """Inverted in V7.

        This test used to assert that a self-approval succeeded and set
        ``self_approved = True`` - the honest record of a real gap, which the V6
        handoff named as "recorded, not prevented". V7 closed the gap, so the
        assertion had to change with the behaviour rather than the behaviour
        being bent to keep an old test green. The full invariant, including the
        edges, lives in ``test_adaptation_four_eyes.py``.
        """
        proposal = self._pending(db, proposed_by="admin@aegisx.dev")

        with pytest.raises(ValueError, match="cannot also approve"):
            proposals.approve(
                db, proposal.id, approved_by="admin@aegisx.dev", approver_role="admin"
            )

        assert proposal.status == ProposalStatus.PENDING.value
        assert proposal.self_approved is False

    def test_approval_alone_does_not_deploy(self, db) -> None:
        proposal = self._pending(db)
        approved = proposals.approve(db, proposal.id, approved_by="admin@aegisx.dev", approver_role="admin")

        assert approved.status == ProposalStatus.APPROVED.value
        assert approved.deployed_at is None

    def test_a_rejected_proposal_cannot_be_approved(self, db) -> None:
        proposal = self._pending(db)
        proposals.reject(db, proposal.id, rejected_by="admin@aegisx.dev", reason="Too risky.")

        with pytest.raises(ValueError, match="rejected"):
            proposals.approve(db, proposal.id, approved_by="admin@aegisx.dev", approver_role="admin")

    def test_rejection_requires_a_reason(self, db) -> None:
        proposal = self._pending(db)
        with pytest.raises(ValueError, match="reason"):
            proposals.reject(db, proposal.id, rejected_by="admin@aegisx.dev", reason="")

    def test_a_proposal_whose_gates_failed_cannot_be_approved(self, db) -> None:
        """The gates are not advisory. Approving past a failed gate would make
        the whole evaluation ceremonial."""
        proposal = self._pending(
            db,
            validation={"gates": {"passed": False, "failures": ["false positive rate"]}},
        )
        with pytest.raises(ValueError, match="gate"):
            proposals.approve(db, proposal.id, approved_by="admin@aegisx.dev", approver_role="admin")


class TestDeployment:
    def _approved(self, db):
        proposal = proposals.create(
            db,
            proposal_type=ProposalType.THRESHOLD_UPDATE,
            title="Raise the anomaly threshold",
            reason="False positives.",
            affected_component="ml.anomaly_threshold",
            before_state={"threshold": 0.65},
            after_state={"threshold": 0.68},
            evidence={"feedbackIds": [1]},
            proposed_by="analyst@aegisx.dev",
        )
        return proposals.approve(db, proposal.id, approved_by="admin@aegisx.dev", approver_role="admin")

    def test_only_an_approved_proposal_may_be_deployed(self, db) -> None:
        proposal = proposals.create(
            db,
            proposal_type=ProposalType.THRESHOLD_UPDATE,
            title="Pending one",
            reason="r",
            affected_component="ml.anomaly_threshold",
            before_state={"threshold": 0.65},
            after_state={"threshold": 0.70},
            evidence={"x": 1},
            proposed_by="analyst@aegisx.dev",
        )
        with pytest.raises(ValueError, match="approved"):
            proposals.mark_deployed(db, proposal.id, deployed_by="admin@aegisx.dev")

    def test_deployment_records_its_actor_and_rollback_target(self, db) -> None:
        approved = self._approved(db)
        deployed = proposals.mark_deployed(db, approved.id, deployed_by="admin@aegisx.dev")

        assert deployed.status == ProposalStatus.DEPLOYED.value
        assert deployed.deployed_by == "admin@aegisx.dev"
        assert deployed.deployed_at is not None
        # The state to return to is captured before the change, not derived after.
        assert deployed.rollback_state == {"threshold": 0.65}

    def test_a_deployed_proposal_can_be_rolled_back(self, db) -> None:
        approved = self._approved(db)
        proposals.mark_deployed(db, approved.id, deployed_by="admin@aegisx.dev")
        rolled = proposals.mark_rolled_back(
            db, approved.id, rolled_back_by="admin@aegisx.dev", reason="FPR spike."
        )

        assert rolled.status == ProposalStatus.ROLLED_BACK.value
        assert rolled.rollback_reason == "FPR spike."

    def test_an_undeployed_proposal_cannot_be_rolled_back(self, db) -> None:
        approved = self._approved(db)
        with pytest.raises(ValueError, match="deployed"):
            proposals.mark_rolled_back(
                db, approved.id, rolled_back_by="admin@aegisx.dev", reason="x"
            )


VIEWER = {"email": "viewer.prop@aegisx.dev", "password": "ViewerPassw0rd!"}
ANALYST = {"email": "analyst.prop@aegisx.dev", "password": "AnalystPassw0rd!"}


def _headers(client, admin_headers, credentials, role):
    client.post(
        "/api/v1/auth/users",
        json={
            "email": credentials["email"],
            "password": credentials["password"],
            "fullName": role.title(),
            "role": role,
        },
        headers=admin_headers,
    )
    response = client.post("/api/v1/auth/login", json=credentials)
    assert response.status_code == 200, response.text
    return {"Authorization": f"Bearer {response.json()['accessToken']}"}


def _payload(**overrides):
    payload = {
        "proposalType": "threshold_update",
        "title": "Raise the anomaly threshold to 0.68",
        "reason": "False-positive clustering on nightly backup traffic.",
        "affectedComponent": "ml.anomaly_threshold",
        "beforeState": {"threshold": 0.65},
        "afterState": {"threshold": 0.68},
        "evidence": {"feedbackIds": [1, 2, 3]},
        "expectedImpact": {"fprChange": -0.12},
        "riskAssessment": "Recall may fall on low-scoring true positives.",
    }
    payload.update(overrides)
    return payload


class TestProposalAPIPermissions:
    def test_an_analyst_may_propose(self, client, auth_headers) -> None:
        analyst = _headers(client, auth_headers, ANALYST, "analyst")
        response = client.post(
            "/api/v1/adaptation/proposals", json=_payload(), headers=analyst
        )
        assert response.status_code == 201, response.text
        assert response.json()["status"] == "pending"
        assert response.json()["proposedBy"] == ANALYST["email"]

    def test_an_analyst_may_not_approve(self, client, auth_headers) -> None:
        """The separation that makes the workflow meaningful."""
        analyst = _headers(client, auth_headers, ANALYST, "analyst")
        created = client.post(
            "/api/v1/adaptation/proposals", json=_payload(), headers=analyst
        ).json()

        denied = client.post(
            f"/api/v1/adaptation/proposals/{created['id']}/approve", headers=analyst
        )
        assert denied.status_code == 403

    def test_a_viewer_may_read_but_not_propose(self, client, auth_headers) -> None:
        viewer = _headers(client, auth_headers, VIEWER, "viewer")
        assert client.get("/api/v1/adaptation/proposals", headers=viewer).status_code == 200
        denied = client.post(
            "/api/v1/adaptation/proposals", json=_payload(), headers=viewer
        )
        assert denied.status_code == 403

    def test_an_administrator_may_approve(self, client, auth_headers) -> None:
        analyst = _headers(client, auth_headers, ANALYST, "analyst")
        created = client.post(
            "/api/v1/adaptation/proposals", json=_payload(), headers=analyst
        ).json()

        approved = client.post(
            f"/api/v1/adaptation/proposals/{created['id']}/approve", headers=auth_headers
        )
        assert approved.status_code == 200, approved.text
        assert approved.json()["status"] == "approved"
        assert approved.json()["approvedBy"]


class TestProposalAPIWorkflow:
    def test_deploying_an_unapproved_proposal_is_refused(self, client, auth_headers) -> None:
        created = client.post(
            "/api/v1/adaptation/proposals", json=_payload(), headers=auth_headers
        ).json()
        response = client.post(
            f"/api/v1/adaptation/proposals/{created['id']}/deploy", headers=auth_headers
        )
        assert response.status_code == 409

    def test_every_transition_is_audited(self, client, auth_headers) -> None:
        created = client.post(
            "/api/v1/adaptation/proposals", json=_payload(), headers=auth_headers
        ).json()
        client.post(
            f"/api/v1/adaptation/proposals/{created['id']}/approve", headers=auth_headers
        )

        audit = client.get(
            "/api/v1/audit",
            params={"action": "adaptation.proposal_approved"},
            headers=auth_headers,
        )
        assert audit.status_code == 200
        actions = [entry["action"] for entry in audit.json()["items"]]
        assert "adaptation.proposal_approved" in actions
