"""Cloud posture through the API, and the ways it could mislead.

Three things are being defended here, in descending order of how much damage
getting them wrong would do:

1. **Nothing may imply a real cloud integration exists.** There is no SDK, no
   credential and no network call on this path. Every response says so.
2. **A resource named inside an event cannot pull in another account's
   posture.** Request parameters are attacker-influenced; the account check is
   what stops that becoming a cross-account disclosure.
3. **An empty result is not a clean bill of health.** A provider that has
   scanned nothing must not render the same as an account with no problems.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.tests.test_events import ingest

ACCOUNT = "111111111111"
OTHER_ACCOUNT = "222222222222"

ANALYST_CREDENTIALS = {"email": "analyst.cloud@aegisx.dev", "password": "AnalystPassw0rd!"}
VIEWER_CREDENTIALS = {"email": "viewer.cloud@aegisx.dev", "password": "ViewerPassw0rd!"}

DEPLOY_ROLE = f"arn:aws:iam::{ACCOUNT}:role/aegisx-deploy"
PAYROLL_BUCKET = "arn:aws:s3:::aegisx-payroll-exports"


def _ensure_user(client: TestClient, admin_headers: dict, credentials: dict, role: str) -> None:
    response = client.post(
        "/api/v1/auth/users",
        json={
            "email": credentials["email"],
            "password": credentials["password"],
            "fullName": f"Cloud {role.title()}",
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


@pytest.fixture()
def scanned(client: TestClient, auth_headers: dict) -> dict:
    response = client.post("/api/v1/cloud/scan", headers=auth_headers)
    assert response.status_code == 200, response.text
    return response.json()


def _cloud_incident(
    client: TestClient, headers: dict, *, normalized: dict
) -> dict:
    event = ingest(
        client,
        headers,
        source="AWS CloudTrail",
        sourceType="cloud",
        eventType="privilege_escalation",
        title="AWS AttachRolePolicy by aegisx-deploy",
        hostname=None,
        normalizedData=normalized,
    )
    response = client.post(f"/api/v1/events/{event['id']}/promote", headers=headers)
    assert response.status_code == 201, response.text
    return response.json()


def _evidence(client: TestClient, headers: dict, incident_id: str, **params):
    return client.get(
        f"/api/v1/incidents/{incident_id}/evidence", headers=headers, params=params
    )


# --- Nothing may look like a real integration ------------------------------


class TestSimulationIsNeverHidden:
    def test_the_scan_says_it_contacted_nothing(self, scanned: dict) -> None:
        assert scanned["isSimulated"] is True
        assert "no cloud account has been contacted" in scanned["note"].lower()
        for scan in scanned["scans"]:
            assert scan["isSimulated"] is True
            assert "no cloud provider was contacted" in scan["executionNote"].lower()

    def test_every_finding_is_flagged_simulated(
        self, client: TestClient, auth_headers: dict, scanned: dict
    ) -> None:
        body = client.get("/api/v1/cloud/findings", headers=auth_headers).json()
        assert body["items"]
        assert all(item["isSimulated"] is True for item in body["items"])
        assert "simulated" in body["note"].lower()

    def test_the_evidence_provider_never_reports_healthy(
        self, client: TestClient, auth_headers: dict
    ) -> None:
        """A healthy cloud posture provider would claim a capability that does
        not exist. It is degraded even when it has findings."""
        body = client.get("/api/v1/providers", headers=auth_headers).json()
        entry = next(p for p in body["providers"] if p["name"] == "aegisx.cloudposture")
        assert entry["health"]["status"] == "degraded"
        assert "simulated" in entry["health"]["reason"].lower()
        assert entry["isExternal"] is False

    def test_no_cloud_sdk_is_installed(self) -> None:
        """The claim in the docstrings, asserted rather than asserted-in-prose."""
        import importlib.util

        for module in ("boto3", "botocore", "azure", "google"):
            try:
                found = importlib.util.find_spec(module)
            except ModuleNotFoundError:
                found = None
            assert found is None, module


# --- The scan itself -------------------------------------------------------


class TestScanning:
    def test_it_finds_the_misconfigurations_in_the_snapshot(self, scanned: dict) -> None:
        # created + updated rather than created alone: the test database is
        # shared across the session, so this scan is not necessarily the first.
        assert scanned["resourcesScanned"] == 9
        assert scanned["findingsCreated"] + scanned["findingsUpdated"] == 9

    def test_rescanning_updates_rather_than_duplicates(
        self, client: TestClient, auth_headers: dict, scanned: dict
    ) -> None:
        """Posture is a current state. A nightly scan of an unremediated bucket
        must not leave a year of identical rows behind it."""
        again = client.post("/api/v1/cloud/scan", headers=auth_headers).json()
        assert again["findingsCreated"] == 0
        assert again["findingsUpdated"] == 9

        body = client.get("/api/v1/cloud/findings", headers=auth_headers).json()
        assert body["total"] == 9

    def test_a_clean_resource_produces_no_finding(
        self, client: TestClient, auth_headers: dict, scanned: dict
    ) -> None:
        """A fixture where everything is broken would never prove a check can
        decline to fire."""
        body = client.get("/api/v1/cloud/findings", headers=auth_headers).json()
        resources = {item["resource"]["resourceId"] for item in body["items"]}
        assert "aegisx-terraform-state" not in resources
        assert "aegisx-readonly" not in resources
        assert "ci-runner" not in resources

    def test_findings_come_back_worst_first(
        self, client: TestClient, auth_headers: dict, scanned: dict
    ) -> None:
        body = client.get("/api/v1/cloud/findings", headers=auth_headers).json()
        order = ["Critical", "High", "Medium", "Low"]
        ranks = [order.index(item["severity"]) for item in body["items"]]
        assert ranks == sorted(ranks)

    def test_an_analyst_may_not_run_a_scan(
        self, client: TestClient, analyst_headers: dict
    ) -> None:
        """Scanning writes rows the whole SOC reads."""
        assert client.post("/api/v1/cloud/scan", headers=analyst_headers).status_code == 403

    def test_a_viewer_may_read_findings(
        self, client: TestClient, viewer_headers: dict, scanned: dict
    ) -> None:
        assert client.get("/api/v1/cloud/findings", headers=viewer_headers).status_code == 200

    def test_reading_requires_a_session(self, client: TestClient) -> None:
        assert client.get("/api/v1/cloud/findings").status_code == 401
        assert client.post("/api/v1/cloud/scan").status_code == 401

    def test_the_scan_is_audited(
        self, client: TestClient, auth_headers: dict, scanned: dict
    ) -> None:
        logs = client.get(
            "/api/v1/audit", headers=auth_headers, params={"action": "cloud.posture_scanned"}
        )
        assert logs.status_code == 200, logs.text
        assert logs.json()["items"], "a scan that writes shared state must be attributable"


# --- Correlation, which is where the security boundary is ------------------


class TestIncidentCorrelation:
    def test_a_finding_about_the_principal_reaches_the_incident(
        self, client: TestClient, auth_headers: dict, scanned: dict
    ) -> None:
        incident = _cloud_incident(
            client,
            auth_headers,
            normalized={"aws_account_id": ACCOUNT, "principal_arn": DEPLOY_ROLE},
        )
        body = _evidence(client, auth_headers, incident["id"], kind="cloud_finding").json()

        checks = {item["content"]["checkId"] for item in body["items"]}
        assert "AEGISX-CLD-IAM-001" in checks
        assert "AEGISX-CLD-IAM-002" in checks

    def test_a_finding_about_a_named_resource_reaches_the_incident(
        self, client: TestClient, auth_headers: dict, scanned: dict
    ) -> None:
        incident = _cloud_incident(
            client,
            auth_headers,
            normalized={
                "aws_account_id": ACCOUNT,
                "principal_arn": DEPLOY_ROLE,
                "request_parameters": {"bucketName": PAYROLL_BUCKET},
            },
        )
        body = _evidence(client, auth_headers, incident["id"], kind="cloud_finding").json()
        resources = {item["content"]["resourceId"] for item in body["items"]}
        assert "aegisx-payroll-exports" in resources

    def test_a_named_resource_in_another_account_is_refused(
        self, client: TestClient, auth_headers: dict, scanned: dict
    ) -> None:
        """The security boundary. Request parameters are attacker-influenced:
        without the account check, naming a resource in an account you have
        nothing to do with would render that account's posture on your
        incident."""
        incident = _cloud_incident(
            client,
            auth_headers,
            normalized={
                "aws_account_id": OTHER_ACCOUNT,
                "principal_arn": f"arn:aws:iam::{OTHER_ACCOUNT}:role/theirs",
                # An account-scoped resource in the scanned account, named by
                # an event recorded in a different one.
                "request_parameters": {"roleArn": DEPLOY_ROLE},
            },
        )
        body = _evidence(client, auth_headers, incident["id"], kind="cloud_finding").json()
        assert body["items"] == []

    def test_a_globally_unique_name_is_matched_without_an_account(
        self, client: TestClient, auth_headers: dict, scanned: dict
    ) -> None:
        """S3 ARNs carry no account because bucket names are globally unique,
        so the name is the identity. Demanding an account here would not
        tighten anything - it would mean no bucket ever correlates."""
        incident = _cloud_incident(
            client,
            auth_headers,
            normalized={
                "aws_account_id": OTHER_ACCOUNT,
                "principal_arn": f"arn:aws:iam::{OTHER_ACCOUNT}:role/theirs",
                "request_parameters": {"bucketName": PAYROLL_BUCKET},
            },
        )
        body = _evidence(client, auth_headers, incident["id"], kind="cloud_finding").json()
        resources = {item["content"]["resourceId"] for item in body["items"]}
        assert resources == {"aegisx-payroll-exports"}

    def test_a_principal_from_another_account_is_refused(
        self, client: TestClient, auth_headers: dict, scanned: dict
    ) -> None:
        incident = _cloud_incident(
            client,
            auth_headers,
            normalized={
                "aws_account_id": OTHER_ACCOUNT,
                # Claims to be the scanned account's role while the event was
                # recorded elsewhere.
                "principal_arn": DEPLOY_ROLE,
            },
        )
        body = _evidence(client, auth_headers, incident["id"], kind="cloud_finding").json()
        assert body["items"] == []

    def test_an_event_without_an_account_correlates_nothing(
        self, client: TestClient, auth_headers: dict, scanned: dict
    ) -> None:
        """With no account on the event there is nothing to check a named
        resource against, so nothing from it is trusted."""
        incident = _cloud_incident(
            client, auth_headers, normalized={"principal_arn": DEPLOY_ROLE}
        )
        body = _evidence(client, auth_headers, incident["id"], kind="cloud_finding").json()
        assert body["items"] == []

    def test_a_non_cloud_incident_gets_no_posture(
        self, client: TestClient, auth_headers: dict, scanned: dict
    ) -> None:
        event = ingest(client, auth_headers)
        incident = client.post(
            f"/api/v1/events/{event['id']}/promote", headers=auth_headers
        ).json()
        body = _evidence(client, auth_headers, incident["id"], kind="cloud_finding").json()
        assert body["items"] == []

    def test_a_hostile_resource_name_cannot_reach_another_account(
        self, client: TestClient, auth_headers: dict, scanned: dict
    ) -> None:
        incident = _cloud_incident(
            client,
            auth_headers,
            normalized={
                "aws_account_id": OTHER_ACCOUNT,
                "principal_arn": (
                    f"arn:aws:iam::{OTHER_ACCOUNT}:role/x:{ACCOUNT}:role/aegisx-deploy"
                ),
            },
        )
        body = _evidence(client, auth_headers, incident["id"], kind="cloud_finding").json()
        assert body["items"] == []


# --- Provenance ------------------------------------------------------------


class TestProvenance:
    def test_a_posture_finding_is_reported_and_mutable(
        self, client: TestClient, auth_headers: dict, scanned: dict
    ) -> None:
        """Not observed - nothing happened. Not immutable - a rescan rewrites
        the row, which is the same admission the threat-intel provider makes."""
        incident = _cloud_incident(
            client,
            auth_headers,
            normalized={"aws_account_id": ACCOUNT, "principal_arn": DEPLOY_ROLE},
        )
        body = _evidence(client, auth_headers, incident["id"], kind="cloud_finding").json()
        item = body["items"][0]

        assert item["provenance"]["origin"] == "reported"
        assert item["provenance"]["integrity"] == "mutable"
        assert item["provenance"]["provider"] == "aegisx.cloudposture"
        assert item["provenance"]["isSynthetic"] is True
        assert item["provenance"]["sourceRef"].startswith("cloud_finding:CF-")

    def test_a_posture_finding_carries_no_confidence(
        self, client: TestClient, auth_headers: dict, scanned: dict
    ) -> None:
        """A check either matched the configuration or it did not. A number
        would invent a doubt the check does not have."""
        incident = _cloud_incident(
            client,
            auth_headers,
            normalized={"aws_account_id": ACCOUNT, "principal_arn": DEPLOY_ROLE},
        )
        body = _evidence(client, auth_headers, incident["id"], kind="cloud_finding").json()
        assert body["items"][0]["provenance"]["confidence"] is None

    def test_posture_findings_change_the_evidence_manifest(
        self, client: TestClient, auth_headers: dict, scanned: dict
    ) -> None:
        """They are part of the evidence a decision is bound to, so they must
        move the digest - otherwise a decision could be verified as unchanged
        while its cloud context had been rewritten underneath it."""
        incident = _cloud_incident(
            client,
            auth_headers,
            normalized={"aws_account_id": ACCOUNT, "principal_arn": DEPLOY_ROLE},
        )
        with_posture = _evidence(client, auth_headers, incident["id"]).json()
        without = _evidence(
            client, auth_headers, incident["id"], provider="aegisx.telemetry"
        ).json()
        assert with_posture["manifestDigest"] != without["manifestDigest"]
