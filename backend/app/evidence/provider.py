"""The evidence provider contract.

An evidence provider answers one question: *given an incident, what evidence do
you have about it?* It does not know what the incident means, does not score
anything, and does not decide whether its evidence matters.

The shape follows ``app.threatintel.base.ThreatIntelProvider``, which has held
up since V3, and for the same reasons:

1. **A provider never raises into the caller.** A provider that is broken,
   unreachable or misconfigured must not be able to stop an analyst seeing the
   evidence the other providers returned. It reports degradation through
   ``health()`` and returns what it has.
2. **A failure is never reported as an absence.** "This provider could not be
   reached" and "this provider has nothing" are different facts, and an
   investigation that confuses them concludes the wrong thing.
3. **A provider declares what it produces.** ``produces`` is how the registry
   can answer "who could tell me about cloud findings?" without importing every
   provider and asking.

The built-in providers project rows AEGISX already holds. Later phases add ones
that call outward - a cloud posture API, an EDR, an identity provider - and the
only thing that changes is which providers are registered.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any

from app.evidence.models import EvidenceItem, EvidenceKind


@dataclass(frozen=True, slots=True)
class ProviderHealth:
    """What state a provider is in, reported rather than raised."""

    #: ``healthy`` / ``degraded`` / ``unavailable``, matching /health's
    #: vocabulary so a future status panel does not need a translation layer.
    status: str
    #: Why, whenever the status is not healthy. Never ``None`` for a
    #: non-healthy provider - an unexplained degradation is not actionable.
    reason: str | None = None

    def __post_init__(self) -> None:
        if self.status != "healthy" and not (self.reason or "").strip():
            raise ValueError(
                f"A {self.status!r} provider must say why. An unexplained "
                "degradation tells an operator nothing they can act on."
            )

    def to_dict(self) -> dict[str, Any]:
        return {"status": self.status, "reason": self.reason}


HEALTHY = ProviderHealth(status="healthy")


class EvidenceProvider(ABC):
    """One source of investigation evidence."""

    #: Stable identifier recorded in every item's provenance. Not a display
    #: name: provenance that changed when somebody renamed a provider would
    #: stop matching the evidence already recorded under the old one.
    name: str = "unknown"
    #: The kinds this provider can emit. Declared so the registry can route a
    #: filter without instantiating anything.
    produces: tuple[EvidenceKind, ...] = ()
    #: Whether this provider reaches outside the platform. Local projections
    #: are free and always available; an external call is neither.
    is_external: bool = False

    @abstractmethod
    def collect(self, db: Any, incident: Any) -> list[EvidenceItem]:
        """Evidence this provider holds about one incident.

        Must not raise. A provider that cannot answer returns ``[]`` and says
        so through ``health()``.
        """

    def health(self) -> ProviderHealth:
        """Default: a local projection is available whenever the process is."""
        return HEALTHY

    def describe(self) -> dict[str, Any]:
        """The static facts about this provider.

        Health is deliberately **not** included. Asking a broken provider how
        it is can raise, and the registry is the layer that can contain that -
        see ``registry._health_of``. A ``describe`` that called ``health``
        would hand every caller an unguarded copy of the same hazard.
        """
        return {
            "name": self.name,
            "produces": [kind.value for kind in self.produces],
            "isExternal": self.is_external,
        }
