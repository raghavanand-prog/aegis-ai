"""Verify a live external provider, or say honestly that it cannot be verified.

    python -m app.ops.verify_providers            # report configuration only
    python -m app.ops.verify_providers --live     # make one real call per provider

**Why this exists.** V6 recorded "No live external provider. No ``.env``, no API
key; nothing live was called." V7 is in the same position: no key is present in
this environment, so no provider has been verified here either. What V7 adds is
the thing that makes the next attempt cheap and the claim checkable - a single
command whose output is the evidence, rather than a paragraph in a handoff
asserting that someone once tried.

**It never invents a result.** Without a key it reports ``UNVERIFIED`` and exits
non-zero under ``--live``. There is deliberately no code path that reports a
provider as working without having called it.

**It never prints a credential.** Keys are reported as present or absent and by
length only. A verification tool that leaked the key into a terminal, a CI log
or a pasted handoff would be a worse security problem than the one it checks.

Every call is bounded by the project's own watchdog, so a provider that accepts
a connection and never answers fails with a diagnosis instead of hanging - the
V7 brief's rule about long-running commands, applied to the one command whose
latency is somebody else's to control.
"""

from __future__ import annotations

import argparse
import sys
from dataclasses import dataclass

from app.core.config import settings
from app.evaluation import watchdog

#: Wall-clock ceiling for the whole run. Generous for a handful of HTTP calls
#: and far below any CI job timeout.
DEFAULT_MAX_SECONDS = 120

STATUS_UNVERIFIED = "UNVERIFIED"
STATUS_VERIFIED = "VERIFIED"
STATUS_FAILED = "FAILED"
STATUS_SKIPPED = "SKIPPED"


@dataclass(frozen=True)
class ProviderReport:
    """One provider's configuration and, if asked for, its live result."""

    name: str
    provider: str
    enabled: bool
    configured: bool
    key_present: bool
    key_length: int
    status: str
    detail: str

    def render(self) -> str:
        key = f"present ({self.key_length} chars)" if self.key_present else "absent"
        return (
            f"{self.name:<18} provider={self.provider or 'none':<12} "
            f"enabled={str(self.enabled):<5} key={key:<20} "
            f"{self.status}\n    {self.detail}"
        )


def _describe(name: str, provider: str, enabled: bool, configured: bool, key: str):
    return {
        "name": name,
        "provider": provider,
        "enabled": enabled,
        "configured": configured,
        "key_present": bool(key),
        # Length only. Never the value, and never a prefix - a prefix is enough
        # to identify an account with some providers.
        "key_length": len(key or ""),
    }


def _ai_report(live: bool) -> ProviderReport:
    base = _describe(
        "AI analyst",
        settings.ai_provider,
        settings.ai_enabled,
        settings.ai_configured,
        settings.ai_api_key,
    )

    if settings.ai_provider == "mock":
        return ProviderReport(
            **base,
            status=STATUS_SKIPPED,
            detail=(
                "The mock provider answers locally and calls nothing. It proves "
                "the code path, never the integration."
            ),
        )
    if not base["configured"]:
        return ProviderReport(
            **base,
            status=STATUS_UNVERIFIED,
            detail=(
                "No API key configured, so no live call was made and none is "
                "claimed. Set AI_PROVIDER and AI_API_KEY, then re-run with --live."
            ),
        )
    if not live:
        return ProviderReport(
            **base,
            status=STATUS_UNVERIFIED,
            detail="Configured but not called. Pass --live to actually verify it.",
        )

    from app.ai.service import get_provider

    try:
        provider = get_provider()
        response = provider.complete(
            "You are a connectivity check. Answer with one word.",
            "Reply with the single word: ok",
        )
    except Exception as exc:  # noqa: BLE001 - any failure is a failed verification
        return ProviderReport(
            **base,
            status=STATUS_FAILED,
            detail=f"{type(exc).__name__}: {exc}",
        )

    return ProviderReport(
        **base,
        status=STATUS_VERIFIED,
        detail=(
            f"Answered in {getattr(response, 'latency_ms', '?')}ms using "
            f"{getattr(response, 'model', 'an unreported model')}."
        ),
    )


def _threat_intel_report(live: bool) -> ProviderReport:
    base = _describe(
        "Threat intel",
        settings.threat_intel_provider,
        settings.threat_intel_enabled,
        settings.threat_intel_configured,
        settings.virustotal_api_key,
    )

    if not base["configured"]:
        return ProviderReport(
            **base,
            status=STATUS_UNVERIFIED,
            detail=(
                "No API key configured, so no live call was made and none is "
                "claimed. Set THREAT_INTEL_PROVIDER=virustotal and "
                "VIRUSTOTAL_API_KEY, then re-run with --live."
            ),
        )
    if not live:
        return ProviderReport(
            **base,
            status=STATUS_UNVERIFIED,
            detail="Configured but not called. Pass --live to actually verify it.",
        )

    from app.threatintel.service import get_provider

    try:
        provider = get_provider()
        # A well-known benign indicator. Deliberately not a real IOC from this
        # deployment: a verification run should not tell a third party what
        # this SOC is looking at.
        result = provider.lookup("ip", "8.8.8.8")
    except Exception as exc:  # noqa: BLE001
        return ProviderReport(**base, status=STATUS_FAILED, detail=f"{type(exc).__name__}: {exc}")

    return ProviderReport(
        **base,
        status=STATUS_VERIFIED,
        detail=f"Lookup returned {type(result).__name__}.",
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Report external provider configuration, and optionally verify one "
            "live. Never prints a credential and never reports success without "
            "having made a call."
        )
    )
    parser.add_argument(
        "--live",
        action="store_true",
        help=(
            "Make one real API call per configured provider. Costs money on a "
            "metered account, so it is off by default."
        ),
    )
    parser.add_argument("--max-seconds", type=int, default=DEFAULT_MAX_SECONDS)
    args = parser.parse_args(argv)

    timer = watchdog.start(args.max_seconds, label="provider verification")
    try:
        reports = [_ai_report(args.live), _threat_intel_report(args.live)]
    finally:
        if timer is not None:
            timer.cancel()

    print("AEGISX external provider verification")
    print("=" * 72)
    for report in reports:
        print(report.render())
    print("=" * 72)

    unverified = [r for r in reports if r.status == STATUS_UNVERIFIED]
    failed = [r for r in reports if r.status == STATUS_FAILED]

    if failed:
        print(f"{len(failed)} provider(s) FAILED verification.")
        return 1
    if args.live and unverified:
        # Asked to verify, could not. Exiting non-zero is the difference between
        # "we checked and it works" and "we could not check", and those must not
        # look the same to a CI job or to whoever reads the log.
        print(
            f"{len(unverified)} provider(s) could not be verified: no credentials. "
            "Nothing is claimed about them."
        )
        return 2

    print("No provider was called." if not args.live else "All configured providers verified.")
    return 0


if __name__ == "__main__":  # pragma: no cover - CLI entry point
    sys.exit(main())
