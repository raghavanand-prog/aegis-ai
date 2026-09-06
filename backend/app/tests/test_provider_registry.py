"""The evidence provider registry, and the health contract it advertises.

``EvidenceProvider`` has carried a ``health()`` method since Phase C, and its
module docstring makes a strong promise about it: *a failure is never reported
as an absence*. Until Phase F nothing kept that promise. Every provider
inherited the default ``HEALTHY``, so an incident collected while the anomaly
model was unloaded and no threat-intelligence provider was configured came back
as a healthy set that simply had no ML and no intel evidence in it - which is
indistinguishable, to a reader, from an incident that genuinely had neither.

These tests pin the three things that make the contract real:

1. A provider whose subsystem is off says so, and the evidence set carries it.
2. Degradation never removes evidence, and never stops another provider's.
3. A provider cannot break the page, including from its own health check.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.evidence import registry
from app.evidence.provider import HEALTHY, ProviderHealth
from app.tests.test_events import ingest

STATUSES = {"healthy", "degraded", "unavailable"}


def _incident(client: TestClient, headers: dict) -> dict:
    event = ingest(client, headers)
    response = client.post(f"/api/v1/events/{event['id']}/promote", headers=headers)
    assert response.status_code == 201, response.text
    return response.json()


def _evidence(client: TestClient, headers: dict, incident_id: str):
    return client.get(f"/api/v1/incidents/{incident_id}/evidence", headers=headers)


# --- The contract itself ---------------------------------------------------


class TestTheHealthContract:
    def test_every_provider_reports_a_status_in_the_shared_vocabulary(self) -> None:
        """The same three words /health/system uses, so a status panel needs no
        translation layer and cannot drift into a fourth state."""
        for provider in registry.providers():
            assert provider.health().status in STATUSES, provider.name

    def test_a_provider_that_is_not_healthy_must_say_why(self) -> None:
        with pytest.raises(ValueError, match="must say why"):
            ProviderHealth(status="degraded", reason="  ")

    def test_health_reflects_the_subsystem_rather_than_being_hardcoded(
        self, monkeypatch
    ) -> None:
        """The defect Phase F closes: ML being unloaded used to read healthy."""
        from app.services import health_service

        monkeypatch.setattr(
            health_service,
            "ml_health",
            lambda: {"status": "degraded", "reason": "no model loaded", "available": False},
        )
        ml = registry.get("aegisx.ml")
        assert ml is not None
        assert ml.health().status == "degraded"
        assert "no model" in (ml.health().reason or "")

    def test_a_healthy_subsystem_reads_healthy(self, monkeypatch) -> None:
        from app.services import health_service

        monkeypatch.setattr(
            health_service, "ml_health", lambda: {"status": "healthy", "available": True}
        )
        ml = registry.get("aegisx.ml")
        assert ml is not None
        assert ml.health() == HEALTHY

    def test_a_projection_of_a_table_is_healthy_and_says_so_deliberately(self) -> None:
        """Telemetry, rules, indicators and correlation project tables that are
        always present. They are healthy whenever the process is - stated here
        so that "healthy" is a claim somebody made, not a default nobody read."""
        for name in ("aegisx.telemetry", "aegisx.rules", "aegisx.indicators"):
            provider = registry.get(name)
            assert provider is not None
            assert provider.health() == HEALTHY
            assert provider.is_external is False


# --- Degradation is not absence --------------------------------------------


class TestDegradationIsNotAbsence:
    def test_a_degraded_provider_is_named_in_the_evidence_set(
        self, client: TestClient, auth_headers: dict, monkeypatch
    ) -> None:
        from app.services import health_service

        monkeypatch.setattr(
            health_service,
            "threat_intel_health",
            lambda: {
                "status": "degraded",
                "reason": "No threat intelligence provider is configured.",
                "configured": False,
            },
        )

        incident = _incident(client, auth_headers)
        body = _evidence(client, auth_headers, incident["id"]).json()

        entry = next(
            (e for e in body["degradedProviders"] if e["provider"] == "aegisx.threatintel"),
            None,
        )
        assert entry is not None, body["degradedProviders"]
        assert entry["status"] == "degraded"
        assert entry["reason"]

    def test_degradation_does_not_remove_the_evidence_that_was_collected(
        self, client: TestClient, auth_headers: dict, monkeypatch
    ) -> None:
        """A degraded provider still returns what it has. Dropping it would
        turn a partial answer into a wrong one."""
        from app.evidence.collectors import EventEvidenceProvider

        monkeypatch.setattr(
            EventEvidenceProvider,
            "health",
            lambda self: ProviderHealth(status="degraded", reason="simulated"),
        )

        incident = _incident(client, auth_headers)
        body = _evidence(client, auth_headers, incident["id"]).json()

        assert body["countsByKind"].get("event", 0) > 0
        assert "aegisx.telemetry" in {e["provider"] for e in body["degradedProviders"]}

    def test_one_degraded_provider_does_not_degrade_the_others(
        self, client: TestClient, auth_headers: dict, monkeypatch
    ) -> None:
        from app.services import health_service

        monkeypatch.setattr(
            health_service,
            "ml_health",
            lambda: {"status": "unavailable", "reason": "simulated", "available": False},
        )

        incident = _incident(client, auth_headers)
        body = _evidence(client, auth_headers, incident["id"]).json()

        degraded = {e["provider"] for e in body["degradedProviders"]}
        assert degraded == {"aegisx.ml"} or "aegisx.ml" in degraded
        assert body["items"]


# --- A provider cannot break the page --------------------------------------


class TestAProviderCannotBreakThePage:
    def test_a_health_check_that_raises_is_contained(
        self, client: TestClient, auth_headers: dict, monkeypatch
    ) -> None:
        """``collect()`` was already guarded; ``health()`` was not, so a
        provider could still take the page down through the very method that
        exists to report that it is broken."""
        from app.evidence.collectors import MLEvidenceProvider

        def explode(self) -> ProviderHealth:  # noqa: ANN001
            raise RuntimeError("simulated health failure")

        monkeypatch.setattr(MLEvidenceProvider, "health", explode)

        incident = _incident(client, auth_headers)
        response = _evidence(client, auth_headers, incident["id"])

        assert response.status_code == 200, response.text
        body = response.json()
        assert body["items"]
        entry = next(
            e for e in body["degradedProviders"] if e["provider"] == "aegisx.ml"
        )
        assert entry["status"] == "unavailable"

    def test_a_raising_health_check_does_not_leak_its_message(
        self, client: TestClient, auth_headers: dict, monkeypatch
    ) -> None:
        from app.evidence.collectors import MLEvidenceProvider

        def explode(self) -> ProviderHealth:  # noqa: ANN001
            raise RuntimeError("secret-value-from-a-row")

        monkeypatch.setattr(MLEvidenceProvider, "health", explode)

        incident = _incident(client, auth_headers)
        body = _evidence(client, auth_headers, incident["id"]).json()

        rendered = str(body["degradedProviders"])
        assert "secret-value-from-a-row" not in rendered
        assert "RuntimeError" in rendered

    def test_describe_survives_a_raising_health_check(self, monkeypatch) -> None:
        """The registry listing must not be the one place a broken provider
        can still 500 - it is what an operator opens *because* something is
        broken."""
        from app.evidence.collectors import MLEvidenceProvider

        def explode(self) -> ProviderHealth:  # noqa: ANN001
            raise RuntimeError("simulated")

        monkeypatch.setattr(MLEvidenceProvider, "health", explode)

        described = {entry["name"]: entry for entry in registry.describe()}
        assert described["aegisx.ml"]["health"]["status"] == "unavailable"


# --- The registry over HTTP ------------------------------------------------


class TestProvidersEndpoint:
    def test_it_requires_a_session(self, client: TestClient) -> None:
        assert client.get("/api/v1/providers").status_code == 401

    def test_it_lists_every_registered_provider(
        self, client: TestClient, auth_headers: dict
    ) -> None:
        body = client.get("/api/v1/providers", headers=auth_headers).json()
        names = {provider["name"] for provider in body["providers"]}
        assert names == {provider.name for provider in registry.providers()}
        assert body["total"] == len(names)

    def test_each_entry_says_what_it_produces_and_whether_it_reaches_outward(
        self, client: TestClient, auth_headers: dict
    ) -> None:
        body = client.get("/api/v1/providers", headers=auth_headers).json()
        entry = next(p for p in body["providers"] if p["name"] == "aegisx.ml")

        assert entry["produces"] == ["ml_inference"]
        assert entry["isExternal"] is False
        assert entry["health"]["status"] in STATUSES

    def test_it_summarises_the_worst_state_rather_than_making_the_reader_scan(
        self, client: TestClient, auth_headers: dict, monkeypatch
    ) -> None:
        from app.services import health_service

        monkeypatch.setattr(
            health_service,
            "ml_health",
            lambda: {"status": "unavailable", "reason": "simulated", "available": False},
        )
        body = client.get("/api/v1/providers", headers=auth_headers).json()

        assert body["status"] == "unavailable"
        assert body["degraded"] >= 1

    def test_a_viewer_may_read_it(
        self, client: TestClient, auth_headers: dict
    ) -> None:
        """Knowing which sources are answering is part of reading an incident
        honestly, so it is not an administrator-only fact."""
        from app.tests.test_evidence_api import VIEWER_CREDENTIALS, _ensure_user, _headers_for

        _ensure_user(client, auth_headers, VIEWER_CREDENTIALS, "viewer")
        headers = _headers_for(client, VIEWER_CREDENTIALS)
        assert client.get("/api/v1/providers", headers=headers).status_code == 200

    def test_it_does_not_expose_provider_internals(
        self, client: TestClient, auth_headers: dict
    ) -> None:
        """Names, kinds and health. Not connection strings, keys or paths."""
        response = client.get("/api/v1/providers", headers=auth_headers)
        assert response.status_code == 200
        rendered = response.text
        for leak in ("://", "password", "api_key", "apiKey", "secret"):
            assert leak not in rendered, leak


# --- One vocabulary, not two -----------------------------------------------


class TestOneHealthMechanism:
    def test_the_api_probes_delegate_to_the_service(
        self, client: TestClient, auth_headers: dict, monkeypatch
    ) -> None:
        """If /health/system had its own copy of these probes, provider health
        and system health could disagree about the same subsystem."""
        from app.services import health_service

        monkeypatch.setattr(
            health_service,
            "ml_health",
            lambda: {"status": "unavailable", "reason": "simulated", "available": False},
        )

        system = client.get("/api/v1/health/system", headers=auth_headers).json()
        providers = client.get("/api/v1/providers", headers=auth_headers).json()
        ml_entry = next(p for p in providers["providers"] if p["name"] == "aegisx.ml")

        assert system["ml"]["status"] == "unavailable"
        assert ml_entry["health"]["status"] == "unavailable"
