"""Which evidence providers exist.

Deliberately a module-level list rather than a plugin system with entry points.
There are seven providers, all in this repository, and a discovery mechanism
would be more machinery than the problem has - the same judgement
``app.core.rbac`` makes about its permission matrix.

What the registry buys is the seam: ``collect_all`` iterates whatever is
registered, so adding a cloud posture provider in a later phase is registering
one object, not editing the assembly code.
"""

from __future__ import annotations

import logging
from typing import Any

from app.evidence.models import EvidenceItem
from app.evidence.provider import EvidenceProvider, ProviderHealth

logger = logging.getLogger(__name__)

_PROVIDERS: list[EvidenceProvider] = []


def register(provider: EvidenceProvider) -> EvidenceProvider:
    """Add a provider. Re-registering the same name replaces it."""
    global _PROVIDERS
    _PROVIDERS = [existing for existing in _PROVIDERS if existing.name != provider.name]
    _PROVIDERS.append(provider)
    return provider


def providers() -> tuple[EvidenceProvider, ...]:
    _ensure_builtins()
    return tuple(_PROVIDERS)


def get(name: str) -> EvidenceProvider | None:
    return next((provider for provider in providers() if provider.name == name), None)


def _health_of(provider: EvidenceProvider) -> ProviderHealth:
    """A provider's health, or ``unavailable`` if asking raised.

    ``collect()`` was guarded from the start; ``health()`` was not. That left
    the one method whose entire job is to report brokenness able to break the
    page instead - and the listing an operator opens *because* something is
    wrong was the most likely place for it to happen.
    """
    try:
        return provider.health()
    except Exception as exc:  # noqa: BLE001 - reporting brokenness must not break
        logger.warning(
            "evidence provider health check failed",
            extra={"provider": provider.name, "error": type(exc).__name__},
        )
        # Type only, for the same reason collect_all withholds the message:
        # exception text can carry row content and this renders in a browser.
        return ProviderHealth(
            status="unavailable",
            reason=f"Health check raised {type(exc).__name__}.",
        )


def describe() -> list[dict[str, Any]]:
    """Every provider, what it produces, and what state it is in."""
    return [
        {**provider.describe(), "health": _health_of(provider).to_dict()}
        for provider in providers()
    ]


def collect_all(db: Any, incident: Any) -> tuple[list[EvidenceItem], list[dict[str, Any]]]:
    """Every provider's evidence for one incident, plus what went wrong.

    Returns ``(items, degraded)``. A provider that raises is caught here and
    reported in ``degraded`` rather than being allowed to empty the page: one
    broken projection must not make an incident look as though it has no
    evidence, which is the most dangerous thing this function could do.
    """
    items: list[EvidenceItem] = []
    degraded: list[dict[str, Any]] = []

    for provider in providers():
        try:
            collected = provider.collect(db, incident)
        except Exception as exc:  # noqa: BLE001 - a provider must not break the page
            logger.warning(
                "evidence provider failed",
                extra={"provider": provider.name, "error": type(exc).__name__},
            )
            degraded.append(
                {
                    "provider": provider.name,
                    "status": "unavailable",
                    # Type only. A provider's exception text can carry row
                    # content, and this response is rendered in a browser.
                    "reason": f"Provider raised {type(exc).__name__}.",
                }
            )
            continue

        health = _health_of(provider)
        if health.status != "healthy":
            degraded.append({"provider": provider.name, **health.to_dict()})
        items.extend(collected)

    return items, degraded


def _ensure_builtins() -> None:
    """Register the built-in projections on first use.

    Imported here rather than at module scope because ``collectors`` imports
    ``register`` from this module, so a top-level import would be circular.
    Registration on first use keeps the dependency one-directional and keeps
    the module importable from the pure domain tests, which touch no database.
    """
    if _PROVIDERS:
        return
    from app.evidence import collectors  # noqa: F401 - registers on import


__all__ = [
    "EvidenceProvider",
    "ProviderHealth",
    "collect_all",
    "describe",
    "get",
    "providers",
    "register",
]
