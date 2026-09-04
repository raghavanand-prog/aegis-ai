"""Lifecycle enforcement through the service and the API.

``test_incident_lifecycle.py`` proves the rules. This file proves they are
actually reached - that the only way an incident's status changes is through
them, that the refusals arrive as the right HTTP status, and that what gets
written down afterwards is enough to reconstruct who did what and why.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.incidents import lifecycle
from app.models.incident import Incident
from app.schemas.incident import IncidentUpdate
from app.services import incident_service
from app.tests.test_events import ingest

ANALYST_CREDENTIALS = {"email": "analyst.lifecycle@aegisx.dev", "password": "AnalystPassw0rd!"}
VIEWER_CREDENTIALS = {"email": "viewer.lifecycle@aegisx.dev", "password": "ViewerPassw0rd!"}


def _ensure_user(client: TestClient, admin_headers: dict, credentials: dict, role: str) -> None:
    response = client.post(
        "/api/v1/auth/users",
        json={
            "email": credentials["email"],
            "password": credentials["password"],
            "fullName": f"Lifecycle {role.title()}",
            "role": role,
        },
        headers=admin_headers,
    )
    assert response.status_code in (201, 409), response.text


def _headers_for(client: TestClient, credentials: dict) -> dict:
    response = client.post("/api/v1/auth/login", json=credentials)
    assert response.status_code == 200, response.text
    return {"Authorization": f"Bearer {response.json()['accessToken']}"}


@pytest.fixture()
def analyst_headers(client: TestClient, auth_headers: dict) -> dict:
    _ensure_user(client, auth_headers, ANALYST_CREDENTIALS, "analyst")
    return _headers_for(client, ANALYST_CREDENTIALS)


@pytest.fixture()
def viewer_headers(client: TestClient, auth_headers: dict) -> dict:
    _ensure_user(client, auth_headers, VIEWER_CREDENTIALS, "viewer")
    return _headers_for(client, VIEWER_CREDENTIALS)


def _new_incident(client: TestClient, headers: dict) -> dict:
    """An incident in its entry state, created the way the platform creates one."""
    event = ingest(client, headers)
    response = client.post(f"/api/v1/events/{event['id']}/promote", headers=headers)
    assert response.status_code == 201, response.text
    return response.json()


def _patch(client: TestClient, headers: dict, incident_id: str, **body):
    return client.patch(f"/api/v1/incidents/{incident_id}", json=body, headers=headers)


def _drive_to(client: TestClient, headers: dict, incident_id: str, *statuses: str) -> dict:
    """Walk an incident along a legal path, asserting each step."""
    payload: dict = {}
    for status in statuses:
        response = _patch(
            client, headers, incident_id, status=status, statusReason="driving to state"
        )
        assert response.status_code == 200, f"{status}: {response.text}"
        payload = response.json()
    return payload


# --- The happy path -------------------------------------------------------


class TestLegalTransitions:
    def test_the_forward_path_can_be_walked_end_to_end(
        self, client: TestClient, auth_headers: dict
    ) -> None:
        incident = _new_incident(client, auth_headers)
        assert incident["status"] == "Open"

        final = _drive_to(
            client,
            auth_headers,
            incident["id"],
            "Triaged",
            "Investigating",
            "Containment Pending",
            "Contained",
            "Resolved",
            "Closed",
        )
        assert final["status"] == "Closed"

    def test_an_unchanged_status_is_a_no_op_not_a_refusal(
        self, client: TestClient, auth_headers: dict
    ) -> None:
        """The UI sends the whole object back. Re-sending the current status
        alongside an edited title must not be rejected as a self-transition."""
        incident = _new_incident(client, auth_headers)

        response = _patch(
            client, auth_headers, incident["id"], status="Open", title="Renamed"
        )
        assert response.status_code == 200, response.text
        assert response.json()["status"] == "Open"
        assert response.json()["title"] == "Renamed"

    def test_a_patch_that_does_not_mention_status_is_untouched_by_the_lifecycle(
        self, client: TestClient, auth_headers: dict
    ) -> None:
        incident = _new_incident(client, auth_headers)
        response = _patch(client, auth_headers, incident["id"], description="More detail")
        assert response.status_code == 200, response.text
        assert response.json()["status"] == "Open"


# --- Refusals -------------------------------------------------------------


class TestIllegalTransitions:
    def test_an_illegal_edge_is_refused_with_conflict(
        self, client: TestClient, auth_headers: dict
    ) -> None:
        incident = _new_incident(client, auth_headers)
        response = _patch(client, auth_headers, incident["id"], status="Contained")
        assert response.status_code == 409, response.text
        assert "Contained" in response.json()["detail"]

    def test_a_resolved_incident_cannot_be_reopened_to_open(
        self, client: TestClient, auth_headers: dict
    ) -> None:
        incident = _new_incident(client, auth_headers)
        _drive_to(client, auth_headers, incident["id"], "Investigating", "Resolved")

        response = _patch(client, auth_headers, incident["id"], status="Open")
        assert response.status_code == 409, response.text

    def test_nothing_escapes_a_closed_incident(
        self, client: TestClient, auth_headers: dict
    ) -> None:
        incident = _new_incident(client, auth_headers)
        _drive_to(client, auth_headers, incident["id"], "Investigating", "Resolved", "Closed")

        for target in ("Open", "Triaged", "Investigating", "Contained", "Resolved"):
            response = _patch(
                client, auth_headers, incident["id"], status=target, statusReason="let me in"
            )
            assert response.status_code == 409, f"{target}: {response.text}"

        assert (
            client.get(f"/api/v1/incidents/{incident['id']}", headers=auth_headers).json()[
                "status"
            ]
            == "Closed"
        )

    def test_an_unknown_status_is_refused_by_validation(
        self, client: TestClient, auth_headers: dict
    ) -> None:
        incident = _new_incident(client, auth_headers)
        response = _patch(client, auth_headers, incident["id"], status="Quarantined")
        assert response.status_code == 422, response.text

    def test_a_refused_transition_changes_nothing(
        self, client: TestClient, auth_headers: dict
    ) -> None:
        """A refusal must not leave the title edited and the status not.

        The two changes arrive in one request; a partial application would be a
        silent, invisible half-write."""
        incident = _new_incident(client, auth_headers)

        response = _patch(
            client, auth_headers, incident["id"], status="Contained", title="Should not stick"
        )
        assert response.status_code == 409, response.text

        after = client.get(
            f"/api/v1/incidents/{incident['id']}", headers=auth_headers
        ).json()
        assert after["status"] == "Open"
        assert after["title"] != "Should not stick"


# --- Authority ------------------------------------------------------------


class TestAuthority:
    def test_an_analyst_may_contain_but_not_close(
        self, client: TestClient, auth_headers: dict, analyst_headers: dict
    ) -> None:
        incident = _new_incident(client, auth_headers)
        _drive_to(client, analyst_headers, incident["id"], "Investigating", "Contained")

        resolved = _patch(
            client, analyst_headers, incident["id"], status="Resolved", statusReason="cleaned up"
        )
        assert resolved.status_code == 200, resolved.text

        refused = _patch(
            client, analyst_headers, incident["id"], status="Closed", statusReason="done"
        )
        assert refused.status_code == 403, refused.text
        assert "incidents:close" in refused.json()["detail"]

    def test_an_administrator_may_close(
        self, client: TestClient, auth_headers: dict
    ) -> None:
        incident = _new_incident(client, auth_headers)
        _drive_to(client, auth_headers, incident["id"], "Investigating", "Resolved")

        response = _patch(
            client, auth_headers, incident["id"], status="Closed", statusReason="signed off"
        )
        assert response.status_code == 200, response.text
        assert response.json()["status"] == "Closed"

    def test_a_viewer_may_not_transition_anything(
        self, client: TestClient, auth_headers: dict, viewer_headers: dict
    ) -> None:
        incident = _new_incident(client, auth_headers)
        response = _patch(client, viewer_headers, incident["id"], status="Triaged")
        assert response.status_code == 403, response.text

    def test_the_close_permission_is_administrator_only(
        self, client: TestClient, auth_headers: dict
    ) -> None:
        matrix = client.get("/api/v1/auth/permissions", headers=auth_headers).json()
        assert "incidents:close" in matrix["admin"]
        assert "incidents:close" not in matrix["analyst"]
        assert "incidents:close" not in matrix["viewer"]


# --- Reasons --------------------------------------------------------------


class TestReasons:
    def test_resolving_without_a_reason_is_refused(
        self, client: TestClient, auth_headers: dict
    ) -> None:
        incident = _new_incident(client, auth_headers)
        _drive_to(client, auth_headers, incident["id"], "Investigating")

        response = _patch(client, auth_headers, incident["id"], status="Resolved")
        assert response.status_code == 400, response.text
        assert "reason" in response.json()["detail"].lower()

    def test_a_blank_reason_is_refused(
        self, client: TestClient, auth_headers: dict
    ) -> None:
        incident = _new_incident(client, auth_headers)
        _drive_to(client, auth_headers, incident["id"], "Investigating")

        response = _patch(
            client, auth_headers, incident["id"], status="Resolved", statusReason="   "
        )
        assert response.status_code == 400, response.text

    def test_reopening_requires_a_reason(
        self, client: TestClient, auth_headers: dict
    ) -> None:
        incident = _new_incident(client, auth_headers)
        _drive_to(client, auth_headers, incident["id"], "Investigating", "Resolved")

        assert (
            _patch(client, auth_headers, incident["id"], status="Investigating").status_code
            == 400
        )
        assert (
            _patch(
                client,
                auth_headers,
                incident["id"],
                status="Investigating",
                statusReason="new evidence on the same host",
            ).status_code
            == 200
        )

    def test_forward_progress_needs_no_reason(
        self, client: TestClient, auth_headers: dict
    ) -> None:
        incident = _new_incident(client, auth_headers)
        assert _patch(client, auth_headers, incident["id"], status="Triaged").status_code == 200


# --- What gets written down -----------------------------------------------


class TestRecordKeeping:
    def test_a_transition_is_audited_with_both_ends_and_the_reason(
        self, client: TestClient, auth_headers: dict
    ) -> None:
        incident = _new_incident(client, auth_headers)
        _patch(
            client,
            auth_headers,
            incident["id"],
            status="Investigating",
            statusReason="picked up",
        )

        audit = client.get(
            "/api/v1/audit?action=incident.status_changed"
            f"&targetId={incident['id']}",
            headers=auth_headers,
        ).json()
        assert audit["total"] == 1, audit
        details = audit["items"][0]["details"]
        assert details["from"] == "Open"
        assert details["to"] == "Investigating"
        assert audit["items"][0]["username"]

    def test_the_reason_reaches_the_audit_row(
        self, client: TestClient, auth_headers: dict
    ) -> None:
        incident = _new_incident(client, auth_headers)
        _drive_to(client, auth_headers, incident["id"], "Investigating")
        _patch(
            client,
            auth_headers,
            incident["id"],
            status="Resolved",
            statusReason="confirmed benign scanner",
        )

        audit = client.get(
            "/api/v1/audit?action=incident.status_changed"
            f"&targetId={incident['id']}",
            headers=auth_headers,
        ).json()
        reasons = [item["details"].get("reason") for item in audit["items"]]
        assert "confirmed benign scanner" in reasons

    def test_the_timeline_records_the_actor_and_the_reason(
        self, client: TestClient, auth_headers: dict
    ) -> None:
        incident = _new_incident(client, auth_headers)
        updated = _patch(
            client,
            auth_headers,
            incident["id"],
            status="Investigating",
            statusReason="assigned to me",
        ).json()

        entries = [e for e in updated["timeline"] if e["action"] == "status_changed"]
        assert entries, updated["timeline"]
        entry = entries[-1]
        assert entry["actor"]
        assert entry["timestamp"]
        assert "Open" in entry["detail"] and "Investigating" in entry["detail"]
        assert "assigned to me" in entry["detail"]


class TestResolvedAt:
    def test_resolving_stamps_resolved_at(
        self, client: TestClient, auth_headers: dict
    ) -> None:
        incident = _new_incident(client, auth_headers)
        _drive_to(client, auth_headers, incident["id"], "Investigating")
        resolved = _patch(
            client, auth_headers, incident["id"], status="Resolved", statusReason="fixed"
        ).json()
        assert resolved["resolvedAt"] is not None

    def test_closing_preserves_resolved_at(
        self, client: TestClient, auth_headers: dict
    ) -> None:
        """The V1 bug: any transition off ``Resolved`` set ``resolved_at`` back
        to NULL, so closing an incident erased when it had been resolved."""
        incident = _new_incident(client, auth_headers)
        _drive_to(client, auth_headers, incident["id"], "Investigating")
        resolved = _patch(
            client, auth_headers, incident["id"], status="Resolved", statusReason="fixed"
        ).json()

        closed = _patch(
            client, auth_headers, incident["id"], status="Closed", statusReason="signed off"
        ).json()
        assert closed["resolvedAt"] == resolved["resolvedAt"]

    def test_reopening_clears_resolved_at(
        self, client: TestClient, auth_headers: dict
    ) -> None:
        """Correct in the other direction: an incident being worked again is
        not resolved, and leaving the stamp would say it was."""
        incident = _new_incident(client, auth_headers)
        _drive_to(client, auth_headers, incident["id"], "Investigating")
        _patch(client, auth_headers, incident["id"], status="Resolved", statusReason="fixed")

        reopened = _patch(
            client,
            auth_headers,
            incident["id"],
            status="Investigating",
            statusReason="it came back",
        ).json()
        assert reopened["resolvedAt"] is None


# --- Backwards compatibility ----------------------------------------------


class TestBackwardsCompatibility:
    def test_an_incident_stored_before_the_lifecycle_can_still_be_worked(
        self, client: TestClient, auth_headers: dict, db
    ) -> None:
        """Simulates a row written by V1-V8, which had no transition rules.

        Inserted directly, because that is what those rows are: statuses that
        arrived without passing through any gate. Each must still have a legal
        way forward, or the migration would strand it.
        """
        for index, legacy_status in enumerate(
            ["Open", "Investigating", "Contained", "Resolved"]
        ):
            incident = Incident(
                incident_id=f"INC-LEGACY-{index}",
                title=f"Legacy {legacy_status}",
                severity="Medium",
                status=legacy_status,
                analyst="Unassigned",
            )
            db.add(incident)
            db.commit()

            listed = client.get(
                f"/api/v1/incidents/INC-LEGACY-{index}", headers=auth_headers
            )
            assert listed.status_code == 200, listed.text
            assert listed.json()["status"] == legacy_status

            response = _patch(
                client,
                auth_headers,
                f"INC-LEGACY-{index}",
                status="Investigating" if legacy_status != "Investigating" else "Resolved",
                statusReason="worked after the migration",
            )
            assert response.status_code == 200, f"{legacy_status}: {response.text}"

    def test_the_new_statuses_survive_a_round_trip_through_the_list_filter(
        self, client: TestClient, auth_headers: dict
    ) -> None:
        incident = _new_incident(client, auth_headers)
        _drive_to(client, auth_headers, incident["id"], "Triaged")

        listed = client.get("/api/v1/incidents?status=Triaged", headers=auth_headers)
        assert listed.status_code == 200, listed.text
        assert incident["id"] in [item["id"] for item in listed.json()["items"]]

    def test_containment_pending_survives_the_list_filter(
        self, client: TestClient, auth_headers: dict
    ) -> None:
        """The one status whose value contains a space, so the one whose query
        string encoding could quietly break."""
        incident = _new_incident(client, auth_headers)
        _drive_to(client, auth_headers, incident["id"], "Investigating", "Containment Pending")

        listed = client.get(
            "/api/v1/incidents", params={"status": "Containment Pending"}, headers=auth_headers
        )
        assert listed.status_code == 200, listed.text
        assert incident["id"] in [item["id"] for item in listed.json()["items"]]


class TestServiceLayerIsSafeWithoutTheRouter:
    """The service is the boundary, not the router.

    Both of these were real defects in the first cut of this phase, found by
    re-reading the diff rather than by a failing test.
    """

    def test_an_anonymous_internal_caller_cannot_close_an_incident(
        self, client: TestClient, auth_headers: dict, db
    ) -> None:
        """``user=None`` used to resolve to the actor string ``"system"``.

        That does not match the ``system:`` prefix, so it read as a human, and
        an unauthenticated internal call inherited the administrator role by
        default - closing an incident with nobody accountable for it.
        """
        incident = _new_incident(client, auth_headers)
        _drive_to(client, auth_headers, incident["id"], "Investigating", "Resolved")

        stored = incident_service.get_incident(db, incident["id"])
        with pytest.raises(lifecycle.UnauthorizedTransition):
            incident_service.update_incident(
                db,
                stored,
                IncidentUpdate(status="Closed", statusReason="by a machine"),
                user=None,
                broadcast=False,
            )

    def test_a_refused_transition_leaves_the_other_fields_alone_without_a_rollback(
        self, client: TestClient, auth_headers: dict, db
    ) -> None:
        """Called directly, with no router to roll back for it.

        The first cut mutated the title, then validated the status, and relied
        on the caller to undo the half-write."""
        incident = _new_incident(client, auth_headers)
        stored = incident_service.get_incident(db, incident["id"])
        original_title = stored.title

        with pytest.raises(lifecycle.InvalidTransition):
            incident_service.update_incident(
                db,
                stored,
                IncidentUpdate(title="Should not stick", status="Contained"),
                user=None,
                broadcast=False,
            )

        assert stored.title == original_title
        assert stored.status == "Open"


class TestCreation:
    def test_an_incident_may_not_be_created_in_a_privileged_state(
        self, client: TestClient, auth_headers: dict
    ) -> None:
        """Otherwise creation is a way around the transition rules: an actor
        without ``incidents:close`` could produce a sealed incident, and one
        without ``incidents:respond`` could assert containment."""
        for status in ("Contained", "Containment Pending", "Resolved", "Closed"):
            response = client.post(
                "/api/v1/incidents",
                json={"title": f"Created as {status}", "status": status, "eventIds": []},
                headers=auth_headers,
            )
            assert response.status_code == 400, f"{status}: {response.text}"

    def test_an_incident_may_be_created_in_a_working_state(
        self, client: TestClient, auth_headers: dict
    ) -> None:
        for status in ("Open", "Triaged", "Investigating"):
            response = client.post(
                "/api/v1/incidents",
                json={"title": f"Created as {status}", "status": status, "eventIds": []},
                headers=auth_headers,
            )
            assert response.status_code == 201, f"{status}: {response.text}"
            assert response.json()["status"] == status
