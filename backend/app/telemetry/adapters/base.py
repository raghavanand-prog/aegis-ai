"""What a telemetry adapter is, and the two helpers every one of them needs.

An adapter owns exactly one thing: translating one vendor's record shape into a
``CanonicalEvent``. It does not decide whether the event is interesting, does
not score it, does not touch the database, and does not know that a detection
engine exists.

That narrowness is the point of the V7 refactor. Before it, the seven vendor
mappings lived inside ``telemetry/normalizer.py`` behind a dict keyed on the
source's display name, so every new source meant editing the module every event
passes through - the leak the V6 handoff named and left unfixed. Now the
normalizer resolves an adapter and calls it, and adding a source is adding a
file.

**Adapters are also the shape a future agent's tooling wants.** A ``DataSource``
in the long-term architecture is, concretely, a collector plus an adapter: one
half produces raw records, the other maps them onto a contract the rest of the
platform already understands. Nothing here anticipates that beyond keeping the
seam in the right place.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from app.models.enums import Severity, SourceType
from app.telemetry.canonical import CanonicalEvent


def ioc(kind: str, value: str | None) -> tuple[str, str] | None:
    """One indicator, or ``None`` when the vendor did not supply the value."""
    if not value:
        return None
    return (kind, str(value))


def candidate(**kwargs: Any) -> dict[str, Any]:
    """The V6 mapper helper, kept so the moved mappings stayed byte-identical.

    Adapters written from here on should build a ``CanonicalEvent`` directly.
    This exists because rewriting seven mappings at the same time as relocating
    them would have made the characterization digest unable to tell a move from
    a behaviour change - and telling those apart was the entire safety argument
    for the refactor.
    """
    base: dict[str, Any] = {
        "event_type": "unknown",
        "title": "Security event",
        "description": None,
        "severity": Severity.LOW.value,
        "hostname": None,
        "username": None,
        "source_ip": None,
        "destination_ip": None,
        "destination_port": None,
        "process": None,
        "command_line": None,
        "normalized_data": {},
        "mitre_techniques": [],
        "iocs": [],
    }
    base.update(kwargs)
    return base


class AdapterError(ValueError):
    """Raised when an adapter cannot map a record it was handed."""


class TelemetryAdapter(ABC):
    """Maps one vendor's raw records onto the canonical contract."""

    #: Stable identifier recorded in provenance. Not the display name: display
    #: names change, and provenance that changed with them would stop matching
    #: the events already stored under the old one.
    name: str = "unknown"
    #: Source display names this adapter is registered for.
    source_names: tuple[str, ...] = ()
    #: The telemetry class this adapter produces. Metadata: it says what kind
    #: of events come out, not what this adapter may be used for.
    source_type: SourceType | None = None
    #: The telemetry class an *unregistered* source of that class falls back to
    #: this adapter for. Separate from ``source_type`` and defaulting to
    #: ``None`` - being able to parse a class is not consent to be every
    #: unknown product in it. The seven V6 adapters set it to reproduce
    #: ``FALLBACK_BY_TYPE`` exactly; anything added since leaves it unset, so a
    #: new source is refused rather than guessed at.
    fallback_for: SourceType | None = None

    @abstractmethod
    def parse(self, raw: dict[str, Any]) -> CanonicalEvent:
        """Map one raw vendor record. Raise ``AdapterError`` if it cannot."""

    @staticmethod
    def from_candidate(mapped: dict[str, Any]) -> CanonicalEvent:
        """Build a ``CanonicalEvent`` from the V6 mapper dict shape.

        Unknown keys are refused rather than dropped. A vendor field that
        reached this dict was intended to reach the detection engine, and
        silently discarding it would lose data an adapter author believed they
        had mapped - while silently *accepting* it is the leak V7 closed.
        """
        known = {
            "event_type", "title", "description", "severity", "hostname",
            "username", "source_ip", "destination_ip", "destination_port",
            "process", "command_line", "normalized_data", "mitre_techniques",
            "iocs",
        }
        unexpected = set(mapped) - known
        if unexpected:
            raise AdapterError(
                f"Adapter produced non-canonical field(s) {sorted(unexpected)}. "
                "Vendor-specific detail belongs in normalized_data, which is "
                "preserved verbatim; the canonical fields are the contract "
                "detection is allowed to depend on."
            )
        return CanonicalEvent(
            event_type=mapped["event_type"],
            title=mapped["title"],
            description=mapped.get("description"),
            severity=mapped.get("severity", Severity.LOW.value),
            hostname=mapped.get("hostname"),
            username=mapped.get("username"),
            source_ip=mapped.get("source_ip"),
            destination_ip=mapped.get("destination_ip"),
            destination_port=mapped.get("destination_port"),
            process=mapped.get("process"),
            command_line=mapped.get("command_line"),
            mitre_techniques=list(mapped.get("mitre_techniques") or []),
            iocs=list(mapped.get("iocs") or []),
            vendor_fields=dict(mapped.get("normalized_data") or {}),
        )

    def describe(self) -> dict[str, Any]:
        return {
            "adapter": self.name,
            "sourceNames": list(self.source_names),
            "sourceType": self.source_type.value if self.source_type else None,
            "fallbackFor": self.fallback_for.value if self.fallback_for else None,
        }
