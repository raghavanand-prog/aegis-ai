"""The canonical telemetry contract.

Everything downstream of ingestion - normalization, feature extraction,
detection, storage, the UI - reads this shape and nothing else. A vendor's
schema stops at the adapter that parses it.

**Why this is a class rather than the dict it replaced.** Through V6 each vendor
mapper built a bare ``dict`` and the contract existed only as the keys those
mappers happened to agree on. Nothing prevented one from adding a key of its
own, and the V6 handoff recorded the consequence: ``telemetry/normalizer.py``
hard-codes vendor schemas, and "adding a source by appending another branch
would deepen it". A frozen dataclass with a fixed field set makes the contract
checkable - a vendor field cannot reach the detection engine by accident,
because there is nowhere on this object to put it.

Vendor detail is not discarded. It goes in ``vendor_fields``, which is preserved
verbatim, carried through as ``normalized_data``, and is the one place a
source-specific key legitimately lives. The distinction that matters: the
canonical fields are what detection may *depend* on, and ``vendor_fields`` is
what an analyst may *read*.

**Provenance is part of the contract** (``source``, ``source_type``, ``adapter``,
``resolution``). V6 §6 established that a result and its provenance travel
together; the same applies to an event and the mapping that produced it. When a
detection later looks wrong, "which adapter parsed this, and was it the one
registered for this source or a fallback" is the first question, and before V7
the answer was not recorded anywhere.

What is deliberately **not** here: any notion of maliciousness, score, label or
scenario. ``RawTelemetry.scenario`` is provenance that never crosses into a
candidate, asserted by test since V6, because a detector able to read the
generating scenario would be scoring the answer key.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from app.models.enums import Severity, SourceType

#: How an adapter was chosen for a record.
#:
#: ``exact`` - the source is registered and owns this adapter.
#: ``fallback`` - no adapter is registered for the source, so the one for its
#: telemetry class was used. Recorded rather than silent: a fallback means a
#: foreign vendor's parser read this record, and the fields it produced are a
#: guess. V6 did this too, and did not say so anywhere.
RESOLUTION_EXACT = "exact"
RESOLUTION_FALLBACK = "fallback"


@dataclass(frozen=True)
class CanonicalEvent:
    """One security event, in the only shape AEGISX detection understands.

    Every field below is either present in most vendors' telemetry or derivable
    from it. Adding a field here is a contract change that affects every source
    and every downstream consumer, which is the friction it is meant to have.
    """

    # --- What happened -----------------------------------------------------
    #: The normalized behaviour class - ``process_creation``, ``auth_failure``,
    #: ``ransomware_behavior`` and so on. This is the cap's grouping key and the
    #: detection engine's primary discriminator, so an adapter that invents a
    #: value here changes what the platform detects.
    event_type: str
    title: str
    severity: str = Severity.LOW.value
    description: str | None = None

    # --- Who and where -----------------------------------------------------
    hostname: str | None = None
    username: str | None = None
    source_ip: str | None = None
    destination_ip: str | None = None
    destination_port: int | None = None
    process: str | None = None
    command_line: str | None = None

    # --- Analyst context ---------------------------------------------------
    #: Techniques the *vendor* asserted. Never inferred by an adapter: an
    #: adapter that guessed at attribution would put a claim nobody made in
    #: front of an analyst as though a product had reported it.
    mitre_techniques: list[str] = field(default_factory=list)
    #: ``(kind, value)`` pairs - ip, domain, hash.
    iocs: list[tuple[str, str]] = field(default_factory=list)
    #: Everything the vendor said that the canonical fields have no room for,
    #: verbatim. The only legitimate home for a source-specific key.
    vendor_fields: dict[str, Any] = field(default_factory=dict)

    def to_candidate(self) -> dict[str, Any]:
        """The dict shape ``event_service.ingest_candidate`` has always taken.

        Kept identical to what the V6 mappers returned, key for key. The
        refactor that introduced this class changed where the mapping lives, not
        what it produces - ``test_telemetry_normalizer_characterization.py``
        pins that.
        """
        return {
            "event_type": self.event_type,
            "title": self.title,
            "description": self.description,
            "severity": self.severity,
            "hostname": self.hostname,
            "username": self.username,
            "source_ip": self.source_ip,
            "destination_ip": self.destination_ip,
            "destination_port": self.destination_port,
            "process": self.process,
            "command_line": self.command_line,
            "normalized_data": dict(self.vendor_fields),
            "mitre_techniques": list(self.mitre_techniques),
            "iocs": list(self.iocs),
        }


#: The canonical field names, as a frozen set. Used by tests to assert that no
#: vendor key has leaked into the contract.
CANONICAL_FIELDS: frozenset[str] = frozenset(
    {
        "event_type",
        "title",
        "severity",
        "description",
        "hostname",
        "username",
        "source_ip",
        "destination_ip",
        "destination_port",
        "process",
        "command_line",
        "mitre_techniques",
        "iocs",
        "vendor_fields",
    }
)


@dataclass(frozen=True)
class TelemetryProvenance:
    """Where a canonical event came from and how it was parsed."""

    source: str
    source_type: SourceType
    adapter: str
    resolution: str
    received_at: datetime
    raw_log: str
    is_synthetic: bool

    def as_candidate_fields(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "source_type": self.source_type.value,
            "timestamp": self.received_at,
            "raw_log": self.raw_log,
            "is_synthetic": self.is_synthetic,
        }
