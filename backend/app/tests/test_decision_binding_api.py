"""Decision-bound evidence integrity through the service and the API.

`test_decision_binding.py` proves the classification. This proves it is
actually reached: that a consequential decision records what it rested on, that
a stale decision is refused before it is taken, and that a change afterwards is
reported for what it is.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.tests.test_events import ingest

VIEWER_CREDENTIALS = {"email": "viewer.decision@aegisx.dev", "password": "ViewerPassw0rd!"}


def _ensure_user(client: TestClient, admin_headers: dict, credentials: dict, role: str) -> None:
    response = client.post(
        "/api/v1/auth/users",
        json={
            "email": credentials["email"],
            "password": credentials["password"],
            "fullName": f"Decision {role.title()}",
            "role": role,
        },
        headers=admin_headers,
    )
    assert response.status_code in (201, 409), response.text


@pytest.fixture()
def viewer_headers(client: TestClient, auth_headers: dict) -> dict:
    _ensure_user(client, auth_headers, VIEWER_CREDENTIALS, "viewer")
    response = client.post("/api/v1/auth/login", json=VIEWER_CREDENTIALS)
    assert response.status_code == 200, response.text
    return {"Authorization": f"Bearer {response.json()['accessToken']}"}


def _incident(client: TestClient, headers: dict, **event_overrides) -> dict:
    event = ingest(client, headers, **event_overrides)
    response = client.post(f"/api/v1/events/{event['id']}/promote", headers=headers)
    assert response.status_code == 201, response.text
    return response.json()


def _patch(client: TestClient, headers: dict, incident_id: str, **body):
    return client.patch(f"/api/v1/incidents/{incident_id}", json=body, headers=headers)


def _decisions(client: TestClient, headers: dict, incident_id: str):
    return client.get(f"/api/v1/incidents/{incident_id}/decisions", headers=headers)


def _manifest(client: TestClient, headers: dict, incident_id: str) -> str:
    response = client.get(f"/api/v1/incidents/{incident_id}/evidence", headers=headers)
    assert response.status_code == 200, response.text
    return response.json()["manifestDigest"]


def _contain(client: TestClient, headers: dict, incident_id: str, **extra):
    """Drive an incident to a consequential decision through legal states."""
    assert _patch(client, headers, incident_id, status="Investigating").status_code == 200
    return _patch(
        client,
        headers,
        incident_id,
        status="Contained",
        statusReason="isolated the host",
        **extra,
    )


# --- What gets bound ------------------------------------------------------


class TestBindingIsRecorded:
    def test_a_consequential_decision_records_its_evidence(
        self, client: TestClient, auth_headers: dict
    ) -> None:
        incident = _incident(client, auth_headers)
        assert _contain(client, auth_headers, incident["id"]).status_code == 200

        body = _decisions(client, auth_headers, incident["id"]).json()
        assert body["total"] == 1
        binding = body["items"][0]
        assert binding["toState"] == "Contained"
        assert binding["fromState"] == "Investigating"
        assert binding["reason"] == "isolated the host"
        assert binding["decidedBy"]
        assert binding["decidedByRole"] == "admin"
        assert len(binding["manifestDigest"]) == 64
        assert binding["evidenceCount"] >= 1
        assert binding["decisionRef"].startswith("DEC-")

    def test_the_recorded_manifest_is_the_evidence_that_was_there(
        self, client: TestClient, auth_headers: dict
    ) -> None:
        incident = _incident(client, auth_headers)
        _patch(client, auth_headers, incident["id"], status="Investigating")
        expected = _manifest(client, auth_headers, incident["id"])

        _patch(
            client,
            auth_headers,
            incident["id"],
            status="Contained",
            statusReason="isolated",
        )

        binding = _decisions(client, auth_headers, incident["id"]).json()["items"][0]
        assert binding["manifestDigest"] == expected

    def test_routine_progress_is_deliberately_not_bound(
        self, client: TestClient, auth_headers: dict
    ) -> None:
        """`Open -> Triaged` concludes nothing. Binding it would put a
        seven-provider collection on every ordinary PATCH for no return."""
        incident = _incident(client, auth_headers)
        assert _patch(client, auth_headers, incident["id"], status="Triaged").status_code == 200

        assert _decisions(client, auth_headers, incident["id"]).json()["total"] == 0

    @pytest.mark.parametrize(
        ("path", "final", "reason"),
        [
            (["Investigating"], "Containment Pending", None),
            (["Investigating"], "Resolved", "false positive"),
            (["Investigating", "Resolved"], "Closed", "signed off"),
        ],
    )
    def test_every_consequential_transition_is_bound(
        self, client: TestClient, auth_headers: dict, path, final, reason
    ) -> None:
        incident = _incident(client, auth_headers)
        for step in path:
            body = {"status": step}
            if step in ("Resolved", "Closed"):
                body["statusReason"] = "stepping"
            assert _patch(client, auth_headers, incident["id"], **body).status_code == 200

        before = _decisions(client, auth_headers, incident["id"]).json()["total"]
        body = {"status": final}
        if reason:
            body["statusReason"] = reason
        assert _patch(client, auth_headers, incident["id"], **body).status_code == 200

        after = _decisions(client, auth_headers, incident["id"]).json()["total"]
        assert after == before + 1

    def test_a_decision_taken_while_a_provider_was_down_records_that(
        self, client: TestClient, auth_headers: dict, monkeypatch
    ) -> None:
        """Deciding on partial evidence is as important to record as evidence
        moving afterwards, and nothing captured it before."""
        from app.evidence.collectors import MLEvidenceProvider

        incident = _incident(client, auth_headers)
        _patch(client, auth_headers, incident["id"], status="Investigating")

        def explode(self, db, incident):  # noqa: ANN001, ARG001
            raise RuntimeError("provider down")

        monkeypatch.setattr(MLEvidenceProvider, "collect", explode)
        _patch(
            client,
            auth_headers,
            incident["id"],
            status="Contained",
            statusReason="decided anyway",
        )
        monkeypatch.undo()

        binding = _decisions(client, auth_headers, incident["id"]).json()["items"][0]
        degraded = binding["drift"]["degradedAtDecision"]
        assert any(entry["provider"] == "aegisx.ml" for entry in degraded), binding

    def test_the_binding_is_reachable_from_the_audit_trail(
        self, client: TestClient, auth_headers: dict
    ) -> None:
        incident = _incident(client, auth_headers)
        _contain(client, auth_headers, incident["id"])

        audit = client.get(
            "/api/v1/audit?action=decision.evidence_bound", headers=auth_headers
        ).json()
        assert audit["total"] >= 1
        details = audit["items"][0]["details"]
        assert details["manifestDigest"]
        assert details["incidentId"]

        status_audit = client.get(
            "/api/v1/audit?action=incident.status_changed"
            f"&targetId={incident['id']}",
            headers=auth_headers,
        ).json()
        bound = [
            item for item in status_audit["items"] if item["details"].get("decisionRef")
        ]
        assert bound, status_audit


# --- Refusing a decision taken on evidence that moved ---------------------


class TestExpectedDigest:
    def test_a_matching_digest_is_accepted(
        self, client: TestClient, auth_headers: dict
    ) -> None:
        incident = _incident(client, auth_headers)
        _patch(client, auth_headers, incident["id"], status="Investigating")
        digest = _manifest(client, auth_headers, incident["id"])

        response = _patch(
            client,
            auth_headers,
            incident["id"],
            status="Contained",
            statusReason="reviewed",
            expectedEvidenceDigest=digest,
        )
        assert response.status_code == 200, response.text

    def test_a_stale_digest_refuses_the_decision(
        self, client: TestClient, auth_headers: dict, db
    ) -> None:
        """The window this closes: an approver renders the evidence, thinks,
        and clicks - and the evidence changed in between."""
        from app.services import incident_service

        incident = _incident(client, auth_headers)
        _patch(client, auth_headers, incident["id"], status="Investigating")
        reviewed = _manifest(client, auth_headers, incident["id"])

        stored = incident_service.get_incident(db, incident["id"])
        stored.events[0].hostname = "CHANGED-AFTER-REVIEW"
        db.commit()

        response = _patch(
            client,
            auth_headers,
            incident["id"],
            status="Contained",
            statusReason="acting on what I read",
            expectedEvidenceDigest=reviewed,
        )
        assert response.status_code == 409, response.text
        assert "changed since" in response.json()["detail"]

    def test_a_refused_decision_changes_nothing(
        self, client: TestClient, auth_headers: dict, db
    ) -> None:
        from app.services import incident_service

        incident = _incident(client, auth_headers)
        _patch(client, auth_headers, incident["id"], status="Investigating")
        reviewed = _manifest(client, auth_headers, incident["id"])

        stored = incident_service.get_incident(db, incident["id"])
        stored.events[0].hostname = "MOVED"
        db.commit()

        _patch(
            client,
            auth_headers,
            incident["id"],
            status="Contained",
            statusReason="x",
            expectedEvidenceDigest=reviewed,
        )

        after = client.get(
            f"/api/v1/incidents/{incident['id']}", headers=auth_headers
        ).json()
        assert after["status"] == "Investigating"
        assert _decisions(client, auth_headers, incident["id"]).json()["total"] == 0

    def test_a_forged_digest_refuses_rather_than_passes(
        self, client: TestClient, auth_headers: dict
    ) -> None:
        """Fail closed. A digest the server never issued must not be treated as
        agreement."""
        incident = _incident(client, auth_headers)
        _patch(client, auth_headers, incident["id"], status="Investigating")

        response = _patch(
            client,
            auth_headers,
            incident["id"],
            status="Contained",
            statusReason="x",
            expectedEvidenceDigest="0" * 64,
        )
        assert response.status_code == 409, response.text

    def test_the_refusal_is_audited(
        self, client: TestClient, auth_headers: dict
    ) -> None:
        incident = _incident(client, auth_headers)
        _patch(client, auth_headers, incident["id"], status="Investigating")
        _patch(
            client,
            auth_headers,
            incident["id"],
            status="Contained",
            statusReason="x",
            expectedEvidenceDigest="0" * 64,
        )

        audit = client.get(
            "/api/v1/audit?action=decision.evidence_stale"
            f"&targetId={incident['id']}",
            headers=auth_headers,
        ).json()
        assert audit["total"] >= 1, audit

    def test_omitting_the_digest_keeps_the_old_behaviour(
        self, client: TestClient, auth_headers: dict, db
    ) -> None:
        """Opt-in, and the cost of that is stated rather than hidden: a client
        that sends nothing gets no protection."""
        from app.services import incident_service

        incident = _incident(client, auth_headers)
        _patch(client, auth_headers, incident["id"], status="Investigating")

        stored = incident_service.get_incident(db, incident["id"])
        stored.events[0].hostname = "MOVED-BUT-NOBODY-CHECKED"
        db.commit()

        response = _patch(
            client,
            auth_headers,
            incident["id"],
            status="Contained",
            statusReason="no digest supplied",
        )
        assert response.status_code == 200, response.text

    def test_the_digest_is_ignored_on_a_non_consequential_transition(
        self, client: TestClient, auth_headers: dict
    ) -> None:
        """Nothing is bound, so there is nothing to be stale against."""
        incident = _incident(client, auth_headers)
        response = _patch(
            client,
            auth_headers,
            incident["id"],
            status="Triaged",
            expectedEvidenceDigest="0" * 64,
        )
        assert response.status_code == 200, response.text


# --- Drift after the decision ---------------------------------------------


class TestDriftAfterTheDecision:
    def test_untouched_evidence_reports_unchanged(
        self, client: TestClient, auth_headers: dict
    ) -> None:
        incident = _incident(client, auth_headers)
        _contain(client, auth_headers, incident["id"])

        body = _decisions(client, auth_headers, incident["id"]).json()
        assert body["items"][0]["drift"]["verdict"] == "unchanged"
        assert body["worstVerdict"] == "unchanged"
        assert body["items"][0]["drift"]["underminesDecision"] is False

    def test_an_edited_immutable_record_reports_tampering(
        self, client: TestClient, auth_headers: dict, db
    ) -> None:
        """An event is written once at ingestion. If its projection changed,
        something outside the application changed it."""
        from app.services import incident_service

        incident = _incident(client, auth_headers)
        _contain(client, auth_headers, incident["id"])

        stored = incident_service.get_incident(db, incident["id"])
        stored.events[0].hostname = "TAMPERED-HOST"
        db.commit()

        drift = _decisions(client, auth_headers, incident["id"]).json()["items"][0]["drift"]
        assert drift["verdict"] == "tampered"
        assert drift["underminesDecision"] is True
        assert drift["changed"][0]["integrity"] == "write_once"
        assert drift["changed"][0]["digestAtDecision"] != drift["changed"][0]["digestNow"]

    def test_new_evidence_reports_extended_not_tampering(
        self, client: TestClient, auth_headers: dict, db
    ) -> None:
        """Evidence arriving after a decision does not undermine what the
        decision rested on, and calling it tampering would train people to
        ignore the alarm."""
        from app.services import incident_service

        incident = _incident(client, auth_headers)
        _contain(client, auth_headers, incident["id"])

        extra = ingest(client, auth_headers)
        stored = incident_service.get_incident(db, incident["id"])
        stored_event = incident_service.event_repository.get_by_event_id(db, extra["id"])
        stored_event.incident_id = stored.id
        db.commit()

        drift = _decisions(client, auth_headers, incident["id"]).json()["items"][0]["drift"]
        assert drift["verdict"] == "extended", drift
        assert drift["added"]
        assert not drift["removed"]
        assert drift["underminesDecision"] is False

    def test_a_refreshed_vendor_verdict_is_material_not_benign(
        self, client: TestClient, auth_headers: dict, db
    ) -> None:
        """The case the whole taxonomy exists for.

        A threat-intelligence row is rewritten in place on re-lookup, so this
        happens routinely. It must not read as tampering - and it must not read
        as fine either, because the verdict behind the decision may have
        inverted.
        """
        from app.models.ioc import IOC
        from app.models.threat_intel import ThreatIntelResult
        from app.services import incident_service

        incident = _incident(client, auth_headers)
        stored = incident_service.get_incident(db, incident["id"])

        indicator = IOC(type="ip", value="203.0.113.77", severity="High", confidence=80)
        db.add(indicator)
        db.flush()
        verdict = ThreatIntelResult(
            ioc_id=indicator.id,
            ioc_type="ip",
            ioc_value="203.0.113.77",
            provider="virustotal",
            status="ok",
            reputation="malicious",
            confidence=90,
            malicious_count=9,
        )
        db.add(verdict)
        stored.iocs.append(indicator)
        db.commit()

        _contain(client, auth_headers, incident["id"])

        # The cache refreshes and the vendor now says the opposite.
        verdict.reputation = "harmless"
        verdict.malicious_count = 0
        verdict.harmless_count = 9
        db.commit()

        drift = _decisions(client, auth_headers, incident["id"]).json()["items"][0]["drift"]
        assert drift["verdict"] == "refreshed", drift
        assert drift["changed"][0]["integrity"] == "mutable"
        # Routine cause, serious consequence.
        assert drift["underminesDecision"] is True

    def test_removed_evidence_reports_tampering(
        self, client: TestClient, auth_headers: dict, db
    ) -> None:
        from app.services import incident_service

        incident = _incident(client, auth_headers)
        _contain(client, auth_headers, incident["id"])

        stored = incident_service.get_incident(db, incident["id"])
        stored.events[0].incident_id = None
        db.commit()

        drift = _decisions(client, auth_headers, incident["id"]).json()["items"][0]["drift"]
        assert drift["verdict"] == "tampered"
        assert drift["removed"]

    def test_the_worst_verdict_is_reported_for_the_incident(
        self, client: TestClient, auth_headers: dict, db
    ) -> None:
        from app.services import incident_service

        incident = _incident(client, auth_headers)
        _contain(client, auth_headers, incident["id"])
        _patch(
            client, auth_headers, incident["id"], status="Resolved", statusReason="done"
        )

        stored = incident_service.get_incident(db, incident["id"])
        stored.events[0].hostname = "TAMPERED"
        db.commit()

        body = _decisions(client, auth_headers, incident["id"]).json()
        assert body["total"] == 2
        assert body["worstVerdict"] == "tampered"


# --- Adversarial ----------------------------------------------------------


class TestBindingsAreAppendOnly:
    def test_there_is_no_write_route_for_any_role(
        self, client: TestClient, auth_headers: dict
    ) -> None:
        incident = _incident(client, auth_headers)
        _contain(client, auth_headers, incident["id"])
        ref = _decisions(client, auth_headers, incident["id"]).json()["items"][0][
            "decisionRef"
        ]
        base = f"/api/v1/incidents/{incident['id']}/decisions"

        for request, url in (
            (client.post, base),
            (client.post, f"{base}/{ref}"),
            (client.patch, f"{base}/{ref}"),
            (client.put, f"{base}/{ref}"),
            (client.delete, f"{base}/{ref}"),
        ):
            response = request(url, headers=auth_headers)
            assert response.status_code in (404, 405), f"{url}: {response.status_code}"

    def test_a_later_decision_does_not_rewrite_an_earlier_one(
        self, client: TestClient, auth_headers: dict
    ) -> None:
        incident = _incident(client, auth_headers)
        _contain(client, auth_headers, incident["id"])
        first = _decisions(client, auth_headers, incident["id"]).json()["items"][0]

        _patch(
            client, auth_headers, incident["id"], status="Resolved", statusReason="done"
        )
        body = _decisions(client, auth_headers, incident["id"]).json()

        kept = [i for i in body["items"] if i["decisionRef"] == first["decisionRef"]]
        assert len(kept) == 1
        assert kept[0]["manifestDigest"] == first["manifestDigest"]
        assert kept[0]["toState"] == "Contained"


class TestCrossIncidentAccess:
    def test_a_decision_from_another_incident_is_not_reachable(
        self, client: TestClient, auth_headers: dict
    ) -> None:
        first = _incident(client, auth_headers)
        second = _incident(client, auth_headers)
        _contain(client, auth_headers, second["id"])

        foreign = _decisions(client, auth_headers, second["id"]).json()["items"][0][
            "decisionRef"
        ]
        response = client.get(
            f"/api/v1/incidents/{first['id']}/decisions/{foreign}", headers=auth_headers
        )
        assert response.status_code == 404, response.text

    def test_an_incidents_decisions_never_contain_anothers(
        self, client: TestClient, auth_headers: dict
    ) -> None:
        first = _incident(client, auth_headers)
        second = _incident(client, auth_headers)
        _contain(client, auth_headers, first["id"])
        _contain(client, auth_headers, second["id"])

        first_refs = {
            i["decisionRef"] for i in _decisions(client, auth_headers, first["id"]).json()["items"]
        }
        second_refs = {
            i["decisionRef"] for i in _decisions(client, auth_headers, second["id"]).json()["items"]
        }
        assert first_refs and second_refs
        assert not (first_refs & second_refs)

    def test_an_unknown_incident_is_a_404(
        self, client: TestClient, auth_headers: dict
    ) -> None:
        assert _decisions(client, auth_headers, "INC-NOPE").status_code == 404


class TestForgedInput:
    def test_the_verdict_cannot_be_influenced_by_a_request_parameter(
        self, client: TestClient, auth_headers: dict, db
    ) -> None:
        from app.services import incident_service

        incident = _incident(client, auth_headers)
        _contain(client, auth_headers, incident["id"])

        stored = incident_service.get_incident(db, incident["id"])
        stored.events[0].hostname = "TAMPERED"
        db.commit()

        response = client.get(
            f"/api/v1/incidents/{incident['id']}/decisions",
            params={"verdict": "unchanged", "underminesDecision": "false"},
            headers=auth_headers,
        )
        assert response.json()["items"][0]["drift"]["verdict"] == "tampered"

    def test_the_snapshot_is_server_side_only(
        self, client: TestClient, auth_headers: dict
    ) -> None:
        """A caller cannot dictate what a decision claims it rested on."""
        incident = _incident(client, auth_headers)
        _patch(client, auth_headers, incident["id"], status="Investigating")
        real = _manifest(client, auth_headers, incident["id"])

        _patch(
            client,
            auth_headers,
            incident["id"],
            status="Contained",
            statusReason="x",
            manifestDigest="f" * 64,
            evidenceSnapshot={"entries": []},
        )
        binding = _decisions(client, auth_headers, incident["id"]).json()["items"][0]
        assert binding["manifestDigest"] == real
        assert binding["evidenceCount"] >= 1


class TestAuthorization:
    def test_reading_decisions_requires_a_session(
        self, client: TestClient, auth_headers: dict
    ) -> None:
        incident = _incident(client, auth_headers)
        assert client.get(f"/api/v1/incidents/{incident['id']}/decisions").status_code == 401

    def test_a_viewer_may_read_decisions(
        self, client: TestClient, auth_headers: dict, viewer_headers: dict
    ) -> None:
        """A viewer already sees the incident and its evidence. Showing the
        conclusion while hiding whether its basis still holds would be worse
        than showing neither."""
        incident = _incident(client, auth_headers)
        _contain(client, auth_headers, incident["id"])
        assert _decisions(client, viewer_headers, incident["id"]).status_code == 200
