"""Threat intelligence tests.

The failure paths matter more than the success path here. A reputation service
that times out must never look like a clean bill of health, and enrichment must
never be able to stop an event being ingested.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from app.models.enums import ThreatIntelReputation, ThreatIntelStatus
from app.repositories.ioc_repository import ioc_repository
from app.threatintel import service as intel_service
from app.threatintel.base import IntelLookup, ThreatIntelProvider
from app.threatintel.providers.null import NullProvider
from app.threatintel.providers.virustotal import VirusTotalProvider
from app.threatintel.validation import InvalidIndicator, is_valid, validate


class StubProvider(ThreatIntelProvider):
    """Records calls and returns whatever the test asked for."""

    name = "virustotal"  # matches the configured provider name
    supports = frozenset({"ip", "domain", "url", "hash"})

    def __init__(self, lookup: IntelLookup | None = None) -> None:
        self._lookup = lookup
        self.calls: list[tuple[str, str]] = []

    @property
    def configured(self) -> bool:
        return True

    def lookup(self, ioc_type: str, value: str) -> IntelLookup:
        self.calls.append((ioc_type, value))
        if self._lookup is not None:
            return self._lookup
        return IntelLookup(
            provider=self.name,
            ioc_type=ioc_type,
            ioc_value=value,
            status=ThreatIntelStatus.OK,
            reputation=ThreatIntelReputation.MALICIOUS,
            confidence=80,
            malicious_count=12,
            suspicious_count=2,
            harmless_count=40,
        )


@pytest.fixture()
def stub():
    provider = StubProvider()
    intel_service.set_provider(provider)
    yield provider
    intel_service.reset_provider()


# ------------------------------------------------------------- validation
def test_public_indicators_are_accepted() -> None:
    assert validate("ip", "8.8.8.8") == "8.8.8.8"
    assert validate("domain", "Evil.Example.COM.") == "evil.example.com"
    assert validate("hash", "3F786850E387550FDAB836ED7E6DC881DE23001B").islower()
    assert validate("url", "https://example.com/a") == "https://example.com/a"


@pytest.mark.parametrize(
    "value",
    ["10.0.0.1", "192.168.1.5", "127.0.0.1", "169.254.169.254", "172.16.0.9"],
)
def test_internal_addresses_are_never_sent_to_a_provider(value: str) -> None:
    """Two reasons: it leaks the estate's topology, and it is an SSRF primitive."""
    with pytest.raises(InvalidIndicator):
        validate("ip", value)


@pytest.mark.parametrize("value", ["203.0.113.9", "198.51.100.4", "192.0.2.7"])
def test_documentation_ranges_are_refused_with_their_own_reason(value: str) -> None:
    """The synthetic generator's 'external' addresses live here. Looking one up
    would ask a real provider about an address that does not exist."""
    with pytest.raises(InvalidIndicator, match="documentation range"):
        validate("ip", value)


def test_cloud_metadata_address_is_refused_however_it_is_dressed_up() -> None:
    with pytest.raises(InvalidIndicator):
        validate("domain", "169.254.169.254")
    with pytest.raises(InvalidIndicator):
        validate("url", "http://169.254.169.254/latest/meta-data")


@pytest.mark.parametrize(
    ("kind", "value"),
    [
        ("ip", "not-an-ip"),
        ("domain", "no-tld"),
        ("domain", "-leading-hyphen.com"),
        ("hash", "abc"),
        ("url", "ftp://example.com"),
        ("url", "javascript:alert(1)"),
        ("ip", ""),
        ("process", "powershell.exe"),
    ],
)
def test_malformed_or_out_of_scope_indicators_are_refused(kind: str, value: str) -> None:
    assert not is_valid(kind, value)


def test_indicators_with_control_characters_are_refused() -> None:
    assert not is_valid("domain", "evil.com\nHost: internal")
    assert not is_valid("ip", "8.8.8.8 8.8.4.4")


def test_overlong_indicator_is_refused() -> None:
    assert not is_valid("domain", "a" * 600 + ".com")


# --------------------------------------------------------------- providers
def test_null_provider_reports_unavailable_not_harmless() -> None:
    result = NullProvider().lookup("ip", "8.8.8.8")
    assert result.status is ThreatIntelStatus.UNAVAILABLE
    assert result.reputation is ThreatIntelReputation.UNKNOWN
    assert not result.is_actionable
    assert "is configured" in result.error


def test_virustotal_without_a_key_reports_unavailable() -> None:
    provider = VirusTotalProvider(api_key="")
    assert not provider.configured
    result = provider.lookup("ip", "8.8.8.8")
    assert result.status is ThreatIntelStatus.UNAVAILABLE
    assert result.reputation is ThreatIntelReputation.UNKNOWN


def test_virustotal_refuses_an_internal_address_before_making_a_request() -> None:
    provider = VirusTotalProvider(api_key="fake-key-for-tests")
    result = provider.lookup("ip", "10.0.0.5")
    assert result.status is ThreatIntelStatus.ERROR
    assert not result.is_actionable


def test_virustotal_parses_vote_counts_into_a_reputation() -> None:
    provider = VirusTotalProvider(api_key="fake-key-for-tests")
    payload = {
        "data": {
            "attributes": {
                "last_analysis_stats": {
                    "malicious": 9,
                    "suspicious": 1,
                    "harmless": 50,
                    "undetected": 10,
                },
                "country": "RU",
            }
        }
    }
    result = provider._parse("ip", "93.184.216.40", payload)  # noqa: SLF001
    assert result.reputation is ThreatIntelReputation.MALICIOUS
    assert result.malicious_count == 9
    assert result.is_actionable
    assert result.details["country"] == "RU"


def test_virustotal_reports_unknown_when_no_engine_has_an_opinion() -> None:
    """Zero votes is 'nobody knows', not 'harmless'."""
    provider = VirusTotalProvider(api_key="fake-key-for-tests")
    result = provider._parse("ip", "93.184.216.40", {"data": {"attributes": {}}})  # noqa: SLF001
    assert result.reputation is ThreatIntelReputation.UNKNOWN
    assert result.confidence == 0


def test_provider_error_never_leaks_the_api_key() -> None:
    provider = VirusTotalProvider(api_key="super-secret-key-value")
    result = provider.lookup("ip", "10.0.0.1")
    serialized = f"{result.error} {result.details} {result.provider}"
    assert "super-secret-key-value" not in serialized


# ----------------------------------------------------------------- service
def test_lookup_is_stored_and_then_served_from_cache(db, stub) -> None:
    ioc = ioc_repository.upsert(db, ioc_type="ip", value="93.184.216.34")
    db.flush()

    first = intel_service.enrich_indicator(db, "ip", "93.184.216.34", ioc=ioc)
    assert first.status == ThreatIntelStatus.OK.value
    assert first.reputation == ThreatIntelReputation.MALICIOUS.value
    assert len(stub.calls) == 1

    # Second call inside the TTL must not reach the provider.
    second = intel_service.enrich_indicator(db, "ip", "93.184.216.34", ioc=ioc)
    assert second.id == first.id
    assert len(stub.calls) == 1

    # `force` bypasses the cache deliberately.
    intel_service.enrich_indicator(db, "ip", "93.184.216.34", ioc=ioc, force=True)
    assert len(stub.calls) == 2
    db.rollback()


def test_a_malicious_verdict_raises_the_indicator_severity(db, stub) -> None:
    ioc = ioc_repository.upsert(db, ioc_type="ip", value="93.184.216.35", severity="Low")
    db.flush()
    intel_service.enrich_indicator(db, "ip", "93.184.216.35", ioc=ioc)
    assert ioc.severity == "Critical"
    db.rollback()


@pytest.mark.parametrize(
    "status",
    [
        ThreatIntelStatus.TIMEOUT,
        ThreatIntelStatus.RATE_LIMITED,
        ThreatIntelStatus.ERROR,
        ThreatIntelStatus.UNAVAILABLE,
    ],
)
def test_a_failed_lookup_is_stored_as_a_failure_not_a_clean_verdict(
    db, status: ThreatIntelStatus
) -> None:
    provider = StubProvider(
        IntelLookup.failed("virustotal", "ip", "93.184.216.36", status, "boom")
    )
    intel_service.set_provider(provider)
    try:
        result = intel_service.enrich_indicator(db, "ip", "93.184.216.36")
        assert result.status == status.value
        assert result.reputation == ThreatIntelReputation.UNKNOWN.value
        assert not result.is_actionable
        assert result.confidence == 0
    finally:
        intel_service.reset_provider()
        db.rollback()


def test_failed_lookups_are_cached_briefly_so_an_outage_self_heals(db) -> None:
    provider = StubProvider(
        IntelLookup.failed(
            "virustotal", "ip", "93.184.216.37", ThreatIntelStatus.TIMEOUT, "slow"
        )
    )
    intel_service.set_provider(provider)
    try:
        result = intel_service.enrich_indicator(db, "ip", "93.184.216.37")
        lifetime = result.expires_at - result.looked_up_at
        assert lifetime <= timedelta(minutes=intel_service.FAILURE_RETRY_MINUTES)
        # Far shorter than a successful verdict's TTL.
        assert lifetime < timedelta(hours=1)
    finally:
        intel_service.reset_provider()
        db.rollback()


def test_out_of_scope_indicators_produce_no_row_at_all(db, stub) -> None:
    """An internal address is not a failed lookup - it is simply never looked
    up, and storing a row would imply an attempt was made."""
    assert intel_service.enrich_indicator(db, "ip", "10.0.0.5") is None
    assert intel_service.enrich_indicator(db, "process", "powershell.exe") is None
    assert stub.calls == []
    db.rollback()


def test_enrich_iocs_skips_what_it_cannot_look_up(db, stub) -> None:
    internal = ioc_repository.upsert(db, ioc_type="ip", value="198.51.100.5")
    external = ioc_repository.upsert(db, ioc_type="ip", value="93.184.216.38")
    db.flush()

    results = intel_service.enrich_iocs(db, [internal, external])
    assert len(results) == 1
    assert results[0].ioc_value == "93.184.216.38"
    db.rollback()


def test_status_reports_configuration_without_the_key() -> None:
    state = intel_service.status()
    assert set(state) >= {"enabled", "provider", "configured", "budget"}
    assert "apiKey" not in state
    assert "key" not in str(state).lower() or "aegisx" not in str(state).lower()


def test_expired_cache_entries_are_refetched(db, stub) -> None:
    ioc = ioc_repository.upsert(db, ioc_type="ip", value="93.184.216.39")
    db.flush()
    result = intel_service.enrich_indicator(db, "ip", "93.184.216.39", ioc=ioc)
    assert len(stub.calls) == 1

    result.expires_at = datetime.now(timezone.utc) - timedelta(hours=1)
    db.flush()

    intel_service.enrich_indicator(db, "ip", "93.184.216.39", ioc=ioc)
    assert len(stub.calls) == 2
    db.rollback()
