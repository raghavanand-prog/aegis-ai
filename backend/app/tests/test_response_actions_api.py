"""Response-action approval through the service and the API.

`test_response_approval.py` proves the rules. This proves they are reached, that
an approval is bound to the evidence the approver was shown, and that none of it
executes anything.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.tests.test_events import ingest

ANALYST = {"email": "analyst.response@aegisx.dev", "password": "AnalystPassw0rd!"}
OTHER_ADMIN = {"email": "admin2.response@aegisx.dev", "password": "AdminPassw0rd!"}
VIEWER = {"email": "viewer.response@aegisx.dev", "password": "ViewerPassw0rd!"}


def _ensure_user(client: TestClient, admin_headers: dict, credentials: dict, role: str) -> None:
    response = client.post(
        "/api/v1/auth/users",
        json={
            "email": credentials["email"],
            "password": credentials["password"],
            "fullName": f"Response {role.title()}",
            "role": role,
        },
        headers=admin_headers,
    )
    assert response.status_code in (201, 409), response.text


def _login(client: TestClient, credentials: dict) -> dict:
    response = client.post("/api/v1/auth/login", json=credentials)
    assert response.status_code == 200, response.text
    return {"Authorization": f"Bearer {response.json()['accessToken']}"}


@pytest.fixture()
def analyst_headers(client: TestClient, auth_headers: dict) -> dict:
    _ensure_user(client, auth_headers, ANALYST, "analyst")
    return _login(client, ANALYST)


@pytest.fixture()
def other_admin_headers(client: TestClient, auth_headers: dict) -> dict:
    _ensure_user(client, auth_headers, OTHER_ADMIN, "admin")
    return _login(client, OTHER_ADMIN)


@pytest.fixture()
def viewer_headers(client: TestClient, auth_headers: dict) -> dict:
    _ensure_user(client, auth_headers, VIEWER, "viewer")
    return _login(client, VIEWER)


def _incident(client: TestClient, headers: dict) -> dict:
    event = ingest(client, headers)
    response = client.post(f"/api/v1/events/{event['id']}/promote", headers=headers)
    assert response.status_code == 201, response.text
    return response.json()


def _manifest(client: TestClient, headers: dict, incident_id: str) -> str:
    return client.get(
        f"/api/v1/incidents/{incident_id}/evidence", headers=headers
    ).json()["manifestDigest"]


def _request(client: TestClient, headers: dict, incident_id: str, **overrides):
    body = {
        "actionType": "isolate_endpoint",
        "parameters": {"hostname": "SYN-WIN-001", "durationMinutes": 60},
        "justification": "confirmed encoded PowerShell from Word",
    }
    body.update(overrides)
    return client.post(
        f"/api/v1/incidents/{incident_id}/response-actions", json=body, headers=headers
    )


def _approve(client: TestClient, headers: dict, incident_id: str, ref: str, **body):
    return client.post(
        f"/api/v1/incidents/{incident_id}/response-actions/{ref}/approve",
        json=body,
        headers=headers,
    )


def _reject(client: TestClient, headers: dict, incident_id: str, ref: str, **body):
    return client.post(
        f"/api/v1/incidents/{incident_id}/response-actions/{ref}/reject",
        json=body,
        headers=headers,
    )


def _get_one(client: TestClient, headers: dict, incident_id: str, ref: str):
    return client.get(
        f"/api/v1/incidents/{incident_id}/response-actions/{ref}", headers=headers
    )


def _withdraw(client: TestClient, headers: dict, incident_id: str, ref: str, **body):
    return client.post(
        f"/api/v1/incidents/{incident_id}/response-actions/{ref}/withdraw",
        json=body,
        headers=headers,
    )


def _decisions(client: TestClient, headers: dict, incident_id: str):
    return client.get(f"/api/v1/incidents/{incident_id}/decisions", headers=headers).json()


# --- Requesting -----------------------------------------------------------


class TestRequesting:
    def test_an_analyst_may_request_containment(
        self, client: TestClient, auth_headers: dict, analyst_headers: dict
    ) -> None:
        incident = _incident(client, auth_headers)
        response = _request(client, analyst_headers, incident["id"])

        assert response.status_code == 201, response.text
        body = response.json()
        assert body["status"] == "requested"
        assert body["requestRef"].startswith("RAR-")
        assert body["actionType"] == "isolate_endpoint"
        assert len(body["parametersDigest"]) == 64
        assert body["decisionRef"] is None

    def test_a_request_does_nothing(
        self, client: TestClient, auth_headers: dict, analyst_headers: dict
    ) -> None:
        """It must not move the incident, and must not claim execution.

        Containment remains a lifecycle transition; a request is somebody
        asking, and asking changes nothing.
        """
        incident = _incident(client, auth_headers)
        before = client.get(
            f"/api/v1/incidents/{incident['id']}", headers=auth_headers
        ).json()["status"]

        body = _request(client, analyst_headers, incident["id"]).json()

        after = client.get(
            f"/api/v1/incidents/{incident['id']}", headers=auth_headers
        ).json()["status"]
        assert after == before
        assert body["executed"] is False
        assert "no response action is executed" in body["executionNote"].lower()

    def test_a_request_needs_a_justification(
        self, client: TestClient, auth_headers: dict, analyst_headers: dict
    ) -> None:
        incident = _incident(client, auth_headers)
        assert (
            _request(client, analyst_headers, incident["id"], justification="  ").status_code
            == 422
        )

    def test_an_unknown_action_type_is_refused(
        self, client: TestClient, auth_headers: dict, analyst_headers: dict
    ) -> None:
        incident = _incident(client, auth_headers)
        assert (
            _request(client, analyst_headers, incident["id"], actionType="nuke").status_code
            == 422
        )

    def test_a_viewer_may_not_request(
        self, client: TestClient, auth_headers: dict, viewer_headers: dict
    ) -> None:
        incident = _incident(client, auth_headers)
        assert _request(client, viewer_headers, incident["id"]).status_code == 403

    def test_requesting_is_audited(
        self, client: TestClient, auth_headers: dict, analyst_headers: dict
    ) -> None:
        incident = _incident(client, auth_headers)
        ref = _request(client, analyst_headers, incident["id"]).json()["requestRef"]

        audit = client.get(
            f"/api/v1/audit?action=response_action.requested&targetId={ref}",
            headers=auth_headers,
        ).json()
        assert audit["total"] == 1, audit


# --- Approving ------------------------------------------------------------


class TestApproving:
    def test_a_second_administrator_may_approve(
        self, client: TestClient, auth_headers: dict, analyst_headers: dict
    ) -> None:
        incident = _incident(client, auth_headers)
        ref = _request(client, analyst_headers, incident["id"]).json()["requestRef"]
        digest = _manifest(client, auth_headers, incident["id"])

        response = _approve(
            client, auth_headers, incident["id"], ref, expectedEvidenceDigest=digest
        )
        assert response.status_code == 200, response.text
        body = response.json()
        assert body["status"] == "approved"
        assert body["decidedByRole"] == "admin"
        assert body["decisionRef"], "the approval must be bound to evidence"
        assert body["executed"] is False

    def test_the_approval_is_bound_to_the_evidence_shown(
        self, client: TestClient, auth_headers: dict, analyst_headers: dict
    ) -> None:
        """One mechanism, not two: the binding is the same record a lifecycle
        decision produces, in the same table, on the same endpoint."""
        incident = _incident(client, auth_headers)
        ref = _request(client, analyst_headers, incident["id"]).json()["requestRef"]
        digest = _manifest(client, auth_headers, incident["id"])
        _approve(client, auth_headers, incident["id"], ref, expectedEvidenceDigest=digest)

        decisions = _decisions(client, auth_headers, incident["id"])
        approvals = [
            item
            for item in decisions["items"]
            if item["decisionType"] == "response_action.approval"
        ]
        assert len(approvals) == 1, decisions
        assert approvals[0]["manifestDigest"] == digest
        assert approvals[0]["drift"]["verdict"] == "unchanged"

    def test_an_analyst_may_not_approve(
        self, client: TestClient, auth_headers: dict, analyst_headers: dict
    ) -> None:
        """Requesting and signing off are separate authorities."""
        incident = _incident(client, auth_headers)
        ref = _request(client, analyst_headers, incident["id"]).json()["requestRef"]
        digest = _manifest(client, analyst_headers, incident["id"])

        response = _approve(
            client, analyst_headers, incident["id"], ref, expectedEvidenceDigest=digest
        )
        assert response.status_code == 403, response.text

    def test_the_requester_may_not_approve_their_own_request(
        self, client: TestClient, auth_headers: dict, other_admin_headers: dict
    ) -> None:
        """Four-eyes, enforced even when the requester is an administrator who
        holds the approval permission."""
        incident = _incident(client, auth_headers)
        ref = _request(client, other_admin_headers, incident["id"]).json()["requestRef"]
        digest = _manifest(client, other_admin_headers, incident["id"])

        response = _approve(
            client, other_admin_headers, incident["id"], ref, expectedEvidenceDigest=digest
        )
        assert response.status_code == 403, response.text
        assert "cannot also approve" in response.json()["detail"]

    def test_a_decided_request_cannot_be_decided_again(
        self, client: TestClient, auth_headers: dict, analyst_headers: dict
    ) -> None:
        incident = _incident(client, auth_headers)
        ref = _request(client, analyst_headers, incident["id"]).json()["requestRef"]
        digest = _manifest(client, auth_headers, incident["id"])
        _approve(client, auth_headers, incident["id"], ref, expectedEvidenceDigest=digest)

        again = _approve(
            client, auth_headers, incident["id"], ref, expectedEvidenceDigest=digest
        )
        assert again.status_code == 409, again.text
        assert _reject(
            client, auth_headers, incident["id"], ref, reason="changed my mind"
        ).status_code == 409

    def test_approving_is_audited_and_says_it_did_not_execute(
        self, client: TestClient, auth_headers: dict, analyst_headers: dict
    ) -> None:
        incident = _incident(client, auth_headers)
        ref = _request(client, analyst_headers, incident["id"]).json()["requestRef"]
        digest = _manifest(client, auth_headers, incident["id"])
        _approve(client, auth_headers, incident["id"], ref, expectedEvidenceDigest=digest)

        audit = client.get(
            f"/api/v1/audit?action=response_action.approved&targetId={ref}",
            headers=auth_headers,
        ).json()
        assert audit["total"] == 1, audit
        assert audit["items"][0]["details"]["executed"] is False
        assert audit["items"][0]["details"]["decisionRef"]


# --- Freshness ------------------------------------------------------------


class TestFreshnessIsMandatory:
    def test_an_approval_without_a_digest_is_refused(
        self, client: TestClient, auth_headers: dict, analyst_headers: dict
    ) -> None:
        incident = _incident(client, auth_headers)
        ref = _request(client, analyst_headers, incident["id"]).json()["requestRef"]

        assert _approve(client, auth_headers, incident["id"], ref).status_code == 422

    def test_a_stale_digest_is_refused_and_nothing_changes(
        self, client: TestClient, auth_headers: dict, analyst_headers: dict, db
    ) -> None:
        from app.services import incident_service

        incident = _incident(client, auth_headers)
        ref = _request(client, analyst_headers, incident["id"]).json()["requestRef"]
        reviewed = _manifest(client, auth_headers, incident["id"])

        stored = incident_service.get_incident(db, incident["id"])
        stored.events[0].hostname = "MOVED-AFTER-REVIEW"
        db.commit()

        response = _approve(
            client, auth_headers, incident["id"], ref, expectedEvidenceDigest=reviewed
        )
        assert response.status_code == 409, response.text

        listed = client.get(
            f"/api/v1/incidents/{incident['id']}/response-actions", headers=auth_headers
        ).json()
        assert listed["items"][0]["status"] == "requested"
        assert listed["items"][0]["decisionRef"] is None
        assert not [
            item
            for item in _decisions(client, auth_headers, incident["id"])["items"]
            if item["decisionType"].startswith("response_action")
        ]

    def test_a_forged_digest_fails_closed(
        self, client: TestClient, auth_headers: dict, analyst_headers: dict
    ) -> None:
        incident = _incident(client, auth_headers)
        ref = _request(client, analyst_headers, incident["id"]).json()["requestRef"]

        response = _approve(
            client, auth_headers, incident["id"], ref, expectedEvidenceDigest="0" * 64
        )
        assert response.status_code == 409, response.text

    def test_a_refused_approval_is_audited(
        self, client: TestClient, auth_headers: dict, analyst_headers: dict
    ) -> None:
        incident = _incident(client, auth_headers)
        ref = _request(client, analyst_headers, incident["id"]).json()["requestRef"]
        _approve(client, auth_headers, incident["id"], ref, expectedEvidenceDigest="0" * 64)

        audit = client.get(
            f"/api/v1/audit?action=response_action.refused&targetId={ref}",
            headers=auth_headers,
        ).json()
        assert audit["total"] >= 1, audit


class TestTheAuditRecordsBothSidesOfTheComparison:
    """An audit that records only what the approver *claimed* is half a record.

    "The approver said they had reviewed digest X" is not checkable on its own.
    "The approver said X, the server held Y" is, and Y is the half a reviewer
    cannot reconstruct later - the evidence has moved on by the time anybody
    reads the audit.
    """

    def test_a_stale_approval_records_the_reviewed_and_the_current_digest(
        self, client: TestClient, auth_headers: dict, analyst_headers: dict, db
    ) -> None:
        from app.services import incident_service

        incident = _incident(client, auth_headers)
        ref = _request(client, analyst_headers, incident["id"]).json()["requestRef"]
        reviewed = _manifest(client, auth_headers, incident["id"])

        stored = incident_service.get_incident(db, incident["id"])
        stored.events[0].hostname = "MOVED-AFTER-REVIEW"
        db.commit()

        assert (
            _approve(
                client, auth_headers, incident["id"], ref, expectedEvidenceDigest=reviewed
            ).status_code
            == 409
        )

        audit = client.get(
            f"/api/v1/audit?action=response_action.refused&targetId={ref}",
            headers=auth_headers,
        ).json()
        details = audit["items"][0]["details"]
        assert details["reviewedDigest"] == reviewed
        assert details["currentDigest"], details
        assert details["currentDigest"] != reviewed
        assert details["currentDigest"] == _manifest(client, auth_headers, incident["id"])

    def test_a_refusal_that_was_not_about_evidence_records_no_current_digest(
        self, client: TestClient, auth_headers: dict
    ) -> None:
        """A stated limit, not an omission.

        The requester approving their own request is refused before the
        evidence is ever weighed. Recording a current digest there would imply
        the evidence was part of the reason, and it was not.
        """
        incident = _incident(client, auth_headers)
        ref = _request(client, auth_headers, incident["id"]).json()["requestRef"]
        reviewed = _manifest(client, auth_headers, incident["id"])

        assert (
            _approve(
                client, auth_headers, incident["id"], ref, expectedEvidenceDigest=reviewed
            ).status_code
            == 403
        )

        audit = client.get(
            f"/api/v1/audit?action=response_action.refused&targetId={ref}",
            headers=auth_headers,
        ).json()
        details = audit["items"][0]["details"]
        assert details["refusal"] == "SelfApprovalRefused"
        assert details["currentDigest"] is None

    def test_an_approval_records_the_digest_it_was_bound_to(
        self, client: TestClient, auth_headers: dict, analyst_headers: dict
    ) -> None:
        """The success case needs it too. Reaching the digest through the
        binding row is a join a reader should not have to know to make."""
        incident = _incident(client, auth_headers)
        ref = _request(client, analyst_headers, incident["id"]).json()["requestRef"]
        digest = _manifest(client, auth_headers, incident["id"])
        assert (
            _approve(
                client, auth_headers, incident["id"], ref, expectedEvidenceDigest=digest
            ).status_code
            == 200
        )

        audit = client.get(
            f"/api/v1/audit?action=response_action.approved&targetId={ref}",
            headers=auth_headers,
        ).json()
        assert audit["items"][0]["details"]["evidenceDigest"] == digest

    def test_no_audit_detail_carries_anything_but_digests_and_references(
        self, client: TestClient, auth_headers: dict, analyst_headers: dict
    ) -> None:
        """Audit records must not become a second copy of the evidence.

        A digest is a reference; the content behind it is not repeated here,
        so an audit reader cannot be shown something the evidence endpoint
        would have refused them.
        """
        incident = _incident(client, auth_headers)
        ref = _request(client, analyst_headers, incident["id"]).json()["requestRef"]
        digest = _manifest(client, auth_headers, incident["id"])
        _approve(client, auth_headers, incident["id"], ref, expectedEvidenceDigest=digest)

        audit = client.get(f"/api/v1/audit?targetId={ref}", headers=auth_headers).json()
        for entry in audit["items"]:
            for key, value in entry["details"].items():
                assert not isinstance(value, (dict, list)), (key, value)


class TestParameterTampering:
    def test_parameters_edited_after_the_request_refuse_the_approval(
        self, client: TestClient, auth_headers: dict, analyst_headers: dict, db
    ) -> None:
        """The approver signs off isolating one host; the stored row must not
        be able to name another by the time it is approved."""
        from app.models.response_action import ResponseActionRequest

        incident = _incident(client, auth_headers)
        ref = _request(client, analyst_headers, incident["id"]).json()["requestRef"]

        record = (
            db.query(ResponseActionRequest).filter_by(request_ref=ref).one()
        )
        record.parameters = {"hostname": "A-DIFFERENT-HOST", "durationMinutes": 60}
        db.commit()

        digest = _manifest(client, auth_headers, incident["id"])
        response = _approve(
            client, auth_headers, incident["id"], ref, expectedEvidenceDigest=digest
        )
        assert response.status_code == 409, response.text
        assert "parameters have changed" in response.json()["detail"]


# --- Rejecting ------------------------------------------------------------


class TestRejecting:
    def test_an_administrator_may_reject_with_a_reason(
        self, client: TestClient, auth_headers: dict, analyst_headers: dict
    ) -> None:
        incident = _incident(client, auth_headers)
        ref = _request(client, analyst_headers, incident["id"]).json()["requestRef"]

        response = _reject(
            client, auth_headers, incident["id"], ref, reason="host is a domain controller"
        )
        assert response.status_code == 200, response.text
        assert response.json()["status"] == "rejected"
        assert response.json()["decisionRef"], "a refusal is a result and is recorded"

    def test_rejection_needs_no_evidence_digest(
        self, client: TestClient, auth_headers: dict, analyst_headers: dict, db
    ) -> None:
        """Blocking a rejection because the evidence moved would trap the
        request as pending forever. Refusing is the fail-safe direction."""
        from app.services import incident_service

        incident = _incident(client, auth_headers)
        ref = _request(client, analyst_headers, incident["id"]).json()["requestRef"]

        stored = incident_service.get_incident(db, incident["id"])
        stored.events[0].hostname = "MOVED"
        db.commit()

        assert _reject(
            client, auth_headers, incident["id"], ref, reason="not warranted"
        ).status_code == 200

    def test_rejection_needs_a_reason(
        self, client: TestClient, auth_headers: dict, analyst_headers: dict
    ) -> None:
        incident = _incident(client, auth_headers)
        ref = _request(client, analyst_headers, incident["id"]).json()["requestRef"]
        assert _reject(client, auth_headers, incident["id"], ref, reason="  ").status_code == 422

    def test_an_analyst_may_not_reject(
        self, client: TestClient, auth_headers: dict, analyst_headers: dict
    ) -> None:
        incident = _incident(client, auth_headers)
        ref = _request(client, analyst_headers, incident["id"]).json()["requestRef"]
        assert _reject(
            client, analyst_headers, incident["id"], ref, reason="mine"
        ).status_code == 403


# --- Adversarial ----------------------------------------------------------


class TestNothingExecutes:
    def test_there_is_no_execute_route(
        self, client: TestClient, auth_headers: dict, analyst_headers: dict
    ) -> None:
        incident = _incident(client, auth_headers)
        ref = _request(client, analyst_headers, incident["id"]).json()["requestRef"]
        base = f"/api/v1/incidents/{incident['id']}/response-actions/{ref}"

        for path in ("/execute", "/run", "/perform", ""):
            response = client.post(f"{base}{path}", json={}, headers=auth_headers)
            assert response.status_code in (404, 405, 422), f"{path}: {response.status_code}"

    def test_the_openapi_surface_offers_no_execution(self) -> None:
        from app.main import app

        paths = app.openapi()["paths"]
        offending = [
            path
            for path in paths
            if "response-action" in path
            and any(word in path for word in ("execute", "run", "perform"))
        ]
        assert not offending, offending

    def test_a_request_cannot_be_deleted_or_edited(
        self, client: TestClient, auth_headers: dict, analyst_headers: dict
    ) -> None:
        """Append-only: a decision is not revised, and a record is not removed."""
        incident = _incident(client, auth_headers)
        ref = _request(client, analyst_headers, incident["id"]).json()["requestRef"]
        base = f"/api/v1/incidents/{incident['id']}/response-actions/{ref}"

        for request in (client.patch, client.put, client.delete):
            assert request(base, headers=auth_headers).status_code in (404, 405)


class TestWithdrawing:
    """Retraction by the requester.

    The status existed in the enum and the CHECK constraint from V9 and
    nothing could produce it - a schema-valid state no code path reached.
    """

    def test_the_requester_may_withdraw_their_own_request(
        self, client: TestClient, auth_headers: dict, analyst_headers: dict
    ) -> None:
        incident = _incident(client, auth_headers)
        ref = _request(client, analyst_headers, incident["id"]).json()["requestRef"]

        response = _withdraw(
            client, analyst_headers, incident["id"], ref, reason="contained by hand"
        )
        assert response.status_code == 200, response.text
        body = response.json()
        assert body["status"] == "withdrawn"
        assert body["decidedBy"] == ANALYST["email"]
        assert body["decisionReason"] == "contained by hand"

    def test_an_administrator_may_not_withdraw_somebody_elses_request(
        self, client: TestClient, auth_headers: dict, analyst_headers: dict
    ) -> None:
        """They reject it instead, under their own name. Checked here as well
        as in the pure tests because this is the one authority an
        administrator does *not* hold on this object."""
        incident = _incident(client, auth_headers)
        ref = _request(client, analyst_headers, incident["id"]).json()["requestRef"]

        response = _withdraw(
            client, auth_headers, incident["id"], ref, reason="I disagree"
        )
        assert response.status_code == 403, response.text

        listed = client.get(
            f"/api/v1/incidents/{incident['id']}/response-actions", headers=auth_headers
        ).json()
        assert listed["items"][0]["status"] == "requested"

    def test_a_viewer_may_not_withdraw(
        self, client: TestClient, auth_headers: dict, viewer_headers: dict
    ) -> None:
        incident = _incident(client, auth_headers)
        ref = _request(client, auth_headers, incident["id"]).json()["requestRef"]
        assert (
            _withdraw(
                client, viewer_headers, incident["id"], ref, reason="no"
            ).status_code
            == 403
        )

    def test_withdrawal_needs_a_reason(
        self, client: TestClient, auth_headers: dict, analyst_headers: dict
    ) -> None:
        incident = _incident(client, auth_headers)
        ref = _request(client, analyst_headers, incident["id"]).json()["requestRef"]
        assert _withdraw(client, analyst_headers, incident["id"], ref).status_code == 422

    def test_withdrawal_is_bound_to_the_evidence_of_the_moment(
        self, client: TestClient, auth_headers: dict, analyst_headers: dict
    ) -> None:
        """What was known when containment was called off is worth answering
        later, exactly as for a rejection."""
        incident = _incident(client, auth_headers)
        ref = _request(client, analyst_headers, incident["id"]).json()["requestRef"]

        body = _withdraw(
            client, analyst_headers, incident["id"], ref, reason="handled offline"
        ).json()
        assert body["decisionRef"] is not None

        decisions = _decisions(client, auth_headers, incident["id"])["items"]
        withdrawal = [
            item
            for item in decisions
            if item["decisionType"] == "response_action.withdrawal"
        ]
        assert len(withdrawal) == 1, decisions
        assert withdrawal[0]["decisionRef"] == body["decisionRef"]

    def test_withdrawal_is_not_blocked_by_evidence_that_moved(
        self, client: TestClient, auth_headers: dict, analyst_headers: dict, db
    ) -> None:
        """The fail-safe direction. If drift could block a withdrawal, a
        request whose evidence changed would be trapped pending forever."""
        from app.services import incident_service

        incident = _incident(client, auth_headers)
        ref = _request(client, analyst_headers, incident["id"]).json()["requestRef"]

        stored = incident_service.get_incident(db, incident["id"])
        stored.events[0].hostname = "MOVED-AFTER-REQUEST"
        db.commit()

        response = _withdraw(
            client, analyst_headers, incident["id"], ref, reason="no longer needed"
        )
        assert response.status_code == 200, response.text

    def test_a_withdrawn_request_cannot_then_be_approved(
        self, client: TestClient, auth_headers: dict, analyst_headers: dict
    ) -> None:
        """The adversarial one. Withdrawal must not become a way to move a
        request into a state a second person never signed off."""
        incident = _incident(client, auth_headers)
        ref = _request(client, analyst_headers, incident["id"]).json()["requestRef"]
        reviewed = _manifest(client, auth_headers, incident["id"])

        assert (
            _withdraw(
                client, analyst_headers, incident["id"], ref, reason="stand down"
            ).status_code
            == 200
        )

        response = _approve(
            client, auth_headers, incident["id"], ref, expectedEvidenceDigest=reviewed
        )
        assert response.status_code == 409, response.text

        listed = client.get(
            f"/api/v1/incidents/{incident['id']}/response-actions", headers=auth_headers
        ).json()
        assert listed["items"][0]["status"] == "withdrawn"

    def test_a_withdrawn_request_cannot_be_withdrawn_again(
        self, client: TestClient, auth_headers: dict, analyst_headers: dict
    ) -> None:
        incident = _incident(client, auth_headers)
        ref = _request(client, analyst_headers, incident["id"]).json()["requestRef"]
        _withdraw(client, analyst_headers, incident["id"], ref, reason="stand down")

        assert (
            _withdraw(
                client, analyst_headers, incident["id"], ref, reason="again"
            ).status_code
            == 409
        )

    def test_an_approved_request_cannot_be_withdrawn(
        self, client: TestClient, auth_headers: dict, analyst_headers: dict
    ) -> None:
        """No undo. An approved containment action is a decision a second
        person took; the requester cannot unmake it."""
        incident = _incident(client, auth_headers)
        ref = _request(client, analyst_headers, incident["id"]).json()["requestRef"]
        reviewed = _manifest(client, auth_headers, incident["id"])
        assert (
            _approve(
                client, auth_headers, incident["id"], ref, expectedEvidenceDigest=reviewed
            ).status_code
            == 200
        )

        assert (
            _withdraw(
                client, analyst_headers, incident["id"], ref, reason="changed my mind"
            ).status_code
            == 409
        )

    def test_withdrawing_is_audited(
        self, client: TestClient, auth_headers: dict, analyst_headers: dict
    ) -> None:
        incident = _incident(client, auth_headers)
        ref = _request(client, analyst_headers, incident["id"]).json()["requestRef"]
        _withdraw(client, analyst_headers, incident["id"], ref, reason="handled offline")

        audit = client.get(
            f"/api/v1/audit?action=response_action.withdrawn&targetId={ref}",
            headers=auth_headers,
        ).json()
        assert audit["total"] >= 1, audit

    def test_the_service_refuses_without_the_router(
        self, client: TestClient, auth_headers: dict, analyst_headers: dict, db
    ) -> None:
        """The API is one caller. A wrong actor reaching the service directly
        gets the same refusal and mutates nothing, without a rollback."""
        from app.response import approval
        from app.services import incident_service, response_action_service

        incident = _incident(client, auth_headers)
        ref = _request(client, analyst_headers, incident["id"]).json()["requestRef"]

        stored = incident_service.get_incident(db, incident["id"])
        record = response_action_service.get_for_incident(db, stored, ref)

        with pytest.raises(approval.NotTheRequester):
            response_action_service.withdraw_action(
                db,
                stored,
                record,
                actor="somebody.else@aegisx.dev",
                actor_role="admin",
                reason="not mine to retract",
            )
        assert record.status == "requested"
        assert record.decided_by is None
        assert record.evidence_binding_id is None


class TestReadingOne:
    """One request by reference.

    The list endpoint could already answer this by being filtered client-side,
    which is exactly the arrangement that puts an authorization decision in the
    browser. A caller that wants one request asks for one.
    """

    def test_a_request_can_be_read_by_reference(
        self, client: TestClient, auth_headers: dict, analyst_headers: dict
    ) -> None:
        incident = _incident(client, auth_headers)
        created = _request(client, analyst_headers, incident["id"]).json()

        response = _get_one(client, auth_headers, incident["id"], created["requestRef"])
        assert response.status_code == 200, response.text
        assert response.json() == created

    def test_it_renders_exactly_what_the_list_renders(
        self, client: TestClient, auth_headers: dict, analyst_headers: dict
    ) -> None:
        """Two surfaces onto one row must not be able to disagree - a field
        that appears in one and not the other is how a reviewer ends up
        believing the wrong thing about a pending containment action."""
        incident = _incident(client, auth_headers)
        ref = _request(client, analyst_headers, incident["id"]).json()["requestRef"]
        digest = _manifest(client, auth_headers, incident["id"])
        _approve(client, auth_headers, incident["id"], ref, expectedEvidenceDigest=digest)

        listed = client.get(
            f"/api/v1/incidents/{incident['id']}/response-actions", headers=auth_headers
        ).json()["items"][0]
        assert _get_one(client, auth_headers, incident["id"], ref).json() == listed

    def test_a_viewer_may_read_one(
        self, client: TestClient, auth_headers: dict, analyst_headers: dict, viewer_headers: dict
    ) -> None:
        """Reading what the SOC is deciding is not a privilege; deciding it
        is. Same split the list endpoint already makes."""
        incident = _incident(client, auth_headers)
        ref = _request(client, analyst_headers, incident["id"]).json()["requestRef"]
        assert _get_one(client, viewer_headers, incident["id"], ref).status_code == 200

    def test_it_requires_a_session(
        self, client: TestClient, auth_headers: dict, analyst_headers: dict
    ) -> None:
        incident = _incident(client, auth_headers)
        ref = _request(client, analyst_headers, incident["id"]).json()["requestRef"]
        assert _get_one(client, {}, incident["id"], ref).status_code == 401

    def test_an_unknown_reference_is_a_404(
        self, client: TestClient, auth_headers: dict
    ) -> None:
        incident = _incident(client, auth_headers)
        assert _get_one(client, auth_headers, incident["id"], "RAR-NOPE-0001").status_code == 404

    def test_an_unknown_incident_is_a_404(
        self, client: TestClient, auth_headers: dict
    ) -> None:
        assert _get_one(client, auth_headers, "INC-999999", "RAR-NOPE-0001").status_code == 404

    def test_a_request_from_another_incident_is_not_reachable(
        self, client: TestClient, auth_headers: dict, analyst_headers: dict
    ) -> None:
        """The security-relevant one. A reference is scoped to its incident,
        so guessing a neighbouring reference resolves to nothing rather than
        to somebody else's pending containment action."""
        first = _incident(client, auth_headers)
        second = _incident(client, auth_headers)
        ref = _request(client, analyst_headers, first["id"]).json()["requestRef"]

        assert _get_one(client, auth_headers, second["id"], ref).status_code == 404
        assert _get_one(client, auth_headers, first["id"], ref).status_code == 200


class TestCrossIncidentAccess:
    def test_a_request_from_another_incident_is_not_reachable(
        self, client: TestClient, auth_headers: dict, analyst_headers: dict
    ) -> None:
        first = _incident(client, auth_headers)
        second = _incident(client, auth_headers)
        foreign = _request(client, analyst_headers, second["id"]).json()["requestRef"]
        digest = _manifest(client, auth_headers, first["id"])

        assert _approve(
            client, auth_headers, first["id"], foreign, expectedEvidenceDigest=digest
        ).status_code == 404
        assert _reject(
            client, auth_headers, first["id"], foreign, reason="x"
        ).status_code == 404

    def test_an_incidents_requests_never_contain_anothers(
        self, client: TestClient, auth_headers: dict, analyst_headers: dict
    ) -> None:
        first = _incident(client, auth_headers)
        second = _incident(client, auth_headers)
        _request(client, analyst_headers, first["id"])
        _request(client, analyst_headers, second["id"])

        first_refs = {
            item["requestRef"]
            for item in client.get(
                f"/api/v1/incidents/{first['id']}/response-actions", headers=auth_headers
            ).json()["items"]
        }
        second_refs = {
            item["requestRef"]
            for item in client.get(
                f"/api/v1/incidents/{second['id']}/response-actions", headers=auth_headers
            ).json()["items"]
        }
        assert first_refs and second_refs
        assert not (first_refs & second_refs)

    def test_an_unknown_incident_is_a_404(
        self, client: TestClient, auth_headers: dict
    ) -> None:
        assert client.get(
            "/api/v1/incidents/INC-NOPE/response-actions", headers=auth_headers
        ).status_code == 404


class TestServiceLayerIsSafeWithoutTheRouter:
    def test_an_unauthorized_approval_mutates_nothing_without_a_rollback(
        self, client: TestClient, auth_headers: dict, analyst_headers: dict, db
    ) -> None:
        """Called directly, with no router to clean up after it."""
        from app.models.response_action import ResponseActionRequest
        from app.response import approval
        from app.services import incident_service, response_action_service

        incident = _incident(client, auth_headers)
        ref = _request(client, analyst_headers, incident["id"]).json()["requestRef"]

        stored_incident = incident_service.get_incident(db, incident["id"])
        record = db.query(ResponseActionRequest).filter_by(request_ref=ref).one()

        with pytest.raises(approval.UnauthorizedApproval):
            response_action_service.approve_action(
                db,
                stored_incident,
                record,
                approver="viewer@aegisx.dev",
                approver_role="viewer",
                expected_evidence_digest="a" * 64,
            )

        assert record.status == "requested"
        assert record.evidence_binding_id is None

    def test_a_machine_cannot_approve_through_the_service(
        self, client: TestClient, auth_headers: dict, analyst_headers: dict, db
    ) -> None:
        from app.models.response_action import ResponseActionRequest
        from app.response import approval
        from app.services import incident_service, response_action_service

        incident = _incident(client, auth_headers)
        ref = _request(client, analyst_headers, incident["id"]).json()["requestRef"]
        stored_incident = incident_service.get_incident(db, incident["id"])
        record = db.query(ResponseActionRequest).filter_by(request_ref=ref).one()

        for machine in ("ai:analyst", "AI:Analyst", "automation:soar"):
            with pytest.raises(approval.UnauthorizedApproval):
                response_action_service.approve_action(
                    db,
                    stored_incident,
                    record,
                    approver=machine,
                    approver_role="admin",
                    expected_evidence_digest="a" * 64,
                )
        assert record.status == "requested"


class TestTheOldPlaceholderIsUntouched:
    def test_the_v1_response_note_still_behaves_exactly_as_before(
        self, client: TestClient, auth_headers: dict
    ) -> None:
        """Phase E deliberately did not bind evidence to it.

        It records a free-text note by one person and executes nothing, with no
        approval in it. Wrapping that in decision-integrity machinery would have
        made a single-party note look like a governed approval.
        """
        incident = _incident(client, auth_headers)
        response = client.post(
            f"/api/v1/incidents/{incident['id']}/response",
            json={"action": "Isolated host"},
            headers=auth_headers,
        )
        assert response.status_code == 200, response.text
        assert any(
            entry["action"] == "response_action"
            for entry in response.json()["timeline"]
        )

        # And it creates no decision binding - it is not an approval.
        assert not [
            item
            for item in _decisions(client, auth_headers, incident["id"])["items"]
            if item["decisionType"].startswith("response_action")
        ]
