"""Microsoft Entra ID sign-in logs.

The mapping below is the V6 implementation, moved rather than rewritten. Its
output is pinned by ``test_telemetry_normalizer_characterization.py``: this file
changing what the detection engine sees is a deliberate act, never a side effect
of the V7 refactor.
"""

from __future__ import annotations

from typing import Any

from app.models.enums import Severity, SourceType
from app.telemetry.adapters.base import TelemetryAdapter, candidate, ioc


def _normalize_entra(raw: dict[str, Any]) -> dict[str, Any]:
    upn = raw.get("userPrincipalName", "")
    username = upn.split("@")[0] if upn else None
    location = raw.get("location") or {}
    country = location.get("countryOrRegion")

    if raw.get("impossibleTravel") or raw.get("riskEventType") == "impossibleTravel":
        return candidate(
            event_type="anomalous_signin",
            title=f"Impossible travel sign-in for {username}",
            description=(
                f"Sign-in from {country} shortly after activity in "
                f"{(raw.get('previousLocation') or {}).get('countryOrRegion')}."
            ),
            severity=Severity.HIGH.value,
            username=username,
            source_ip=raw.get("ipAddress"),
            normalized_data={
                "impossible_travel": True,
                "risk_level": raw.get("riskLevelDuringSignIn"),
                "country": country,
                "previous_country": (raw.get("previousLocation") or {}).get("countryOrRegion"),
                "upn": upn,
            },
            iocs=[ioc for ioc in [ioc("ip", raw.get("ipAddress"))] if ioc],
        )

    failures = int(raw.get("failureCount", 0) or 0)
    if raw.get("resultType") not in {"0", 0} or failures:
        return candidate(
            event_type="auth_failure",
            title=f"{failures or 1} failed sign-in attempt(s) for {username}",
            description=f"{raw.get('resultDescription')} from {raw.get('ipAddress')} ({country}).",
            severity=Severity.MEDIUM.value if failures >= 5 else Severity.LOW.value,
            username=username,
            source_ip=raw.get("ipAddress"),
            normalized_data={
                "failure_count": failures,
                "result_type": raw.get("resultType"),
                "result_description": raw.get("resultDescription"),
                "country": country,
                "upn": upn,
            },
            iocs=[ioc for ioc in [ioc("ip", raw.get("ipAddress"))] if ioc],
        )

    return candidate(
        event_type="auth_success",
        title=f"Successful sign-in for {username}",
        description=f"{raw.get('appDisplayName')} sign-in from {raw.get('ipAddress')} ({country}).",
        severity=Severity.LOW.value,
        username=username,
        source_ip=raw.get("ipAddress"),
        normalized_data={
            "application": raw.get("appDisplayName"),
            "country": country,
            "risk_level": raw.get("riskLevelDuringSignIn"),
            "upn": upn,
        },
    )


class EntraAdapter(TelemetryAdapter):
    name = "entra"
    source_names = ("Entra ID",)
    source_type = SourceType.IDENTITY
    fallback_for = SourceType.IDENTITY

    def parse(self, raw: dict[str, Any]):
        return self.from_candidate(_normalize_entra(raw))
