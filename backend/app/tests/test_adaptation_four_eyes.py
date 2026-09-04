"""Four-eyes approval, enforced rather than recorded (V7).

Through V6 ``proposals.approve`` set ``self_approved`` when the approver was the
proposer and then approved anyway. The V6 handoff stated it plainly: "self_approved
is still recorded, not prevented." These tests are the invariant that replaced it.

The property under test is narrow and worth stating exactly: **no proposal can
reach APPROVED, and therefore no candidate can reach production, on the strength
of one person's decision.** Everything else here supports that or checks the
edges around it.
"""

from __future__ import annotations

import pytest

from app.adaptation.proposals import service as proposals
from app.models.enums import ProposalStatus, ProposalType

ANALYST = "analyst@aegisx.dev"
ADMIN = "admin@aegisx.dev"
OTHER_ADMIN = "second.admin@aegisx.dev"


def _pending(db, **overrides):
    payload = {
        "proposal_type": ProposalType.THRESHOLD_UPDATE,
        "title": "Raise the anomaly threshold to 0.7",
        "reason": "False positive rate is 33% on the current corpus.",
        "affected_component": "ml.anomaly_threshold",
        "before_state": {"threshold": 0.65},
        "after_state": {"threshold": 0.7},
        "evidence": {"feedbackIds": [1]},
        "proposed_by": ANALYST,
        "proposed_by_role": "analyst",
    }
    payload.update(overrides)
    return proposals.create(db, **payload)


class TestAProposerCannotApproveTheirOwnProposal:
    def test_self_approval_is_refused(self, db) -> None:
        """The V6 hole. This used to succeed with self_approved=True."""
        proposal = _pending(db, proposed_by=ADMIN, proposed_by_role="admin")

        with pytest.raises(ValueError, match="cannot also approve"):
            proposals.approve(db, proposal.id, approved_by=ADMIN, approver_role="admin")

    def test_a_refused_self_approval_leaves_the_proposal_pending(self, db) -> None:
        """Fail closed: a refusal must not half-apply the transition."""
        proposal = _pending(db, proposed_by=ADMIN, proposed_by_role="admin")

        with pytest.raises(ValueError):
            proposals.approve(db, proposal.id, approved_by=ADMIN, approver_role="admin")

        assert proposal.status == ProposalStatus.PENDING.value
        assert proposal.approved_by is None
        assert proposal.approved_at is None
        assert proposal.self_approved is False

    def test_case_and_whitespace_do_not_defeat_the_rule(self, db) -> None:
        """Actors are email addresses. A rule that compared them literally could
        be walked around with the shift key."""
        proposal = _pending(db, proposed_by=ADMIN, proposed_by_role="admin")

        with pytest.raises(ValueError, match="cannot also approve"):
            proposals.approve(
                db, proposal.id, approved_by="  Admin@AegisX.dev ", approver_role="admin"
            )

    def test_a_second_authorised_actor_may_approve(self, db) -> None:
        proposal = _pending(db)
        approved = proposals.approve(
            db, proposal.id, approved_by=ADMIN, approver_role="admin"
        )

        assert approved.status == ProposalStatus.APPROVED.value
        assert approved.approved_by == ADMIN
        assert approved.approved_by_role == "admin"
        assert approved.approved_at is not None
        assert approved.self_approved is False


class TestAuthorityIsCheckedNotAssumed:
    def test_a_role_without_the_permission_cannot_approve(self, db) -> None:
        """Checked in the service, not only in the FastAPI dependency: the API
        is one caller, and an experiment harness or CLI is another."""
        proposal = _pending(db)

        for role in ("analyst", "viewer"):
            with pytest.raises(ValueError, match="does not hold adaptation:approve"):
                proposals.approve(
                    db, proposal.id, approved_by=OTHER_ADMIN, approver_role=role
                )

        assert proposal.status == ProposalStatus.PENDING.value

    def test_an_unknown_role_grants_nothing(self, db) -> None:
        proposal = _pending(db)

        with pytest.raises(ValueError, match="does not hold adaptation:approve"):
            proposals.approve(
                db, proposal.id, approved_by=ADMIN, approver_role="superuser"
            )

    def test_an_approval_must_state_its_authority(self, db) -> None:
        proposal = _pending(db)

        with pytest.raises(ValueError, match="must state the role"):
            proposals.approve(db, proposal.id, approved_by=ADMIN, approver_role="")

    def test_a_machine_cannot_approve_whatever_role_it_claims(self, db) -> None:
        """The AI drafts proposals. Letting it approve one would make 'human
        approval' a string the machine can write."""
        proposal = _pending(db)

        with pytest.raises(ValueError, match="not a human actor"):
            proposals.approve(
                db, proposal.id, approved_by="ai:analyst", approver_role="admin"
            )


class TestDuplicateAndInvalidTransitionsFailClosed:
    def test_a_second_approval_is_refused(self, db) -> None:
        proposal = _pending(db)
        proposals.approve(db, proposal.id, approved_by=ADMIN, approver_role="admin")

        with pytest.raises(ValueError, match="not pending"):
            proposals.approve(
                db, proposal.id, approved_by=OTHER_ADMIN, approver_role="admin"
            )

        # The first decision stands; a duplicate does not overwrite the actor.
        assert proposal.approved_by == ADMIN

    def test_a_rejected_proposal_cannot_be_approved(self, db) -> None:
        proposal = _pending(db)
        proposals.reject(
            db,
            proposal.id,
            rejected_by=ADMIN,
            reason="The evidence is one week of one host.",
            rejector_role="admin",
        )

        with pytest.raises(ValueError, match="was rejected"):
            proposals.approve(db, proposal.id, approved_by=ADMIN, approver_role="admin")

    def test_deployment_requires_an_approval_that_happened(self, db) -> None:
        """The link that makes four-eyes reach production: activation is only
        reachable through mark_deployed, which only accepts APPROVED."""
        proposal = _pending(db)

        with pytest.raises(ValueError, match="only an approved"):
            proposals.mark_deployed(db, proposal.id, deployed_by=ADMIN)

    def test_a_failed_gate_still_blocks_approval(self, db) -> None:
        proposal = _pending(
            db, validation={"gates": {"passed": False, "failures": ["recall"]}}
        )

        with pytest.raises(ValueError, match="failed its safety gates"):
            proposals.approve(db, proposal.id, approved_by=ADMIN, approver_role="admin")


class TestRejectionsStayAuditable:
    def test_a_rejection_records_actor_reason_role_and_time(self, db) -> None:
        proposal = _pending(db)
        rejected = proposals.reject(
            db,
            proposal.id,
            rejected_by=ADMIN,
            reason="Threshold change unsupported by the evidence.",
            rejector_role="admin",
        )

        assert rejected.status == ProposalStatus.REJECTED.value
        assert rejected.rejected_by == ADMIN
        assert rejected.rejected_by_role == "admin"
        assert rejected.rejected_at is not None
        assert "unsupported" in rejected.rejection_reason

    def test_a_proposer_may_withdraw_their_own_proposal(self, db) -> None:
        """The asymmetry is deliberate. Four-eyes guards the direction of travel
        that changes what AEGISX detects; refusing your own proposal does not."""
        proposal = _pending(db, proposed_by=ADMIN, proposed_by_role="admin")
        rejected = proposals.reject(
            db,
            proposal.id,
            rejected_by=ADMIN,
            reason="Withdrawing: the measurement was on the wrong split.",
            rejector_role="admin",
        )

        assert rejected.status == ProposalStatus.REJECTED.value


class TestTheApiEnforcesTheSameRule:
    def _raise(self, client, headers) -> int:
        response = client.post(
            "/api/v1/adaptation/proposals",
            headers=headers,
            json={
                "proposalType": "threshold_update",
                "title": "Raise the anomaly threshold to 0.7",
                "reason": "False positive rate is 33% on the current corpus.",
                "affectedComponent": "ml.anomaly_threshold",
                "beforeState": {"threshold": 0.65},
                "afterState": {"threshold": 0.7},
                "evidence": {"feedbackIds": [1]},
            },
        )
        assert response.status_code == 201, response.text
        return response.json()["id"]

    def test_the_proposers_own_approval_is_rejected_over_http(
        self, client, auth_headers
    ) -> None:
        proposal_id = self._raise(client, auth_headers)

        response = client.post(
            f"/api/v1/adaptation/proposals/{proposal_id}/approve", headers=auth_headers
        )

        assert response.status_code == 409, response.text
        assert "cannot also approve" in response.json()["detail"]

        # And the proposal is still pending, not half-transitioned.
        state = client.get(
            f"/api/v1/adaptation/proposals/{proposal_id}", headers=auth_headers
        )
        assert state.json()["status"] == "pending"

    def test_the_acting_role_is_recorded_on_the_row(self, client, auth_headers) -> None:
        proposal_id = self._raise(client, auth_headers)

        body = client.get(
            f"/api/v1/adaptation/proposals/{proposal_id}", headers=auth_headers
        ).json()

        assert body["proposedByRole"] in {"admin", "analyst"}
        assert body["selfApproved"] is False
