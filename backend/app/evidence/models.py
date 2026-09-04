"""What a piece of investigation evidence is.

The question this exists to answer is the one an analyst asks when they are
handed a conclusion:

    "What evidence caused this, where did each piece come from, when did we
    learn it, and can I still see the original?"

Through V8 the platform could not answer it. Evidence existed as a *rendering* -
the workspace joined risk signals, ML findings and linked events at read time
and drew them on a page - and as a *prompt payload* (``app.ai.evidence``), which
is sanitised, capped and shaped for a model rather than for a person. Neither
was a record. Neither carried the collection time, the confidence basis, or a
reference back to the row it came from.

**An evidence item is a reference with provenance attached, not a copy.**
``content`` is a small normalised projection - the facts an analyst reads in a
list - and ``source_ref`` points at the row that holds the whole truth.
Duplicating events, inference vectors and provider payloads into a second table
would double the storage, and would create a mutable copy of records that are
currently the only version there is.

Three fields carry the honesty of the whole design:

``origin``
    Whether this was *observed*, *derived* by AEGISX, *reported* by a third
    party, produced by an *analytic* (the AI analyst), or *simulated*. A rule
    firing and a vendor's opinion are not the same class of claim.

``integrity``
    How much the platform can actually promise about the underlying row. Some
    sources are append-only. Threat-intelligence rows are **updated in place**
    when an indicator is looked up again, and IOC rows have their sighting
    count incremented. Labelling all of it "immutable" would be a lie about
    exactly the evidence most likely to move under a past decision.

``confidence_basis``
    What a confidence number *means*. 0.82 from an anomaly ranking and 0.82
    from a vendor's vote count are different quantities, and a confidence with
    no basis is a number an analyst will compare with the wrong thing.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any

from app.ai.sanitize import contains_injection_attempt, scrub_text, scrub_value


class EvidenceKind(str, Enum):
    """What sort of thing a piece of evidence is.

    The four ``*_FINDING`` members are **reserved**: declared so the contract
    an analyst and a future provider read is stable from V9 onwards, and
    deliberately produced by nothing yet. A test asserts no registered provider
    emits them, so the reservation cannot quietly become a fabrication.
    """

    EVENT = "event"
    RULE_DETECTION = "rule_detection"
    ML_INFERENCE = "ml_inference"
    INDICATOR = "indicator"
    THREAT_INTEL = "threat_intel"
    CORRELATION = "correlation"
    AI_ANALYSIS = "ai_analysis"

    # --- Reserved for later phases; no producer exists ---------------------
    CLOUD_FINDING = "cloud_finding"
    ENDPOINT_FINDING = "endpoint_finding"
    IDENTITY_FINDING = "identity_finding"
    NETWORK_FINDING = "network_finding"


class EvidenceOrigin(str, Enum):
    """What kind of claim this is, which decides how much it is worth.

    The UI must keep these apart. A model's narrative and a firewall's record
    of a connection are both "evidence" and an analyst weighs them completely
    differently.
    """

    #: Telemetry as it was recorded. The estate said this happened.
    OBSERVED = "observed"
    #: Computed by AEGISX from observed data - a rule, a score, a correlation.
    DERIVED = "derived"
    #: A third party's assertion. True or false independently of our telemetry.
    REPORTED = "reported"
    #: Produced by the AI analyst. Never a fact; always a reading of facts.
    ANALYTIC = "analytic"
    #: Produced by a mock or simulated provider. Reserved for later phases.
    SIMULATED = "simulated"


class Integrity(str, Enum):
    """What the platform can actually promise about the underlying row."""

    #: New rows only; an existing one is never rewritten.
    APPEND_ONLY = "append_only"
    #: Written once at ingestion and not updated afterwards.
    WRITE_ONCE = "write_once"
    #: Updated in place. The content behind this item can change after a
    #: decision was made on it, and only the digest will show that it did.
    MUTABLE = "mutable"


#: Integrity levels where the stored row is not rewritten, so a digest taken
#: now still describes the row later.
_TAMPER_EVIDENT = frozenset({Integrity.APPEND_ONLY, Integrity.WRITE_ONCE})


def _require_aware(value: datetime | None, name: str) -> datetime | None:
    if value is None:
        return None
    if value.tzinfo is None:
        raise ValueError(
            f"{name} is a naive datetime. A timestamp on a security record "
            "without a timezone is an ambiguous instant."
        )
    return value


@dataclass(frozen=True, slots=True)
class Provenance:
    """Where one piece of evidence came from, and what it is worth."""

    #: Who produced it. An AEGISX subsystem (``aegisx.ml``) or an external
    #: provider (``virustotal``). Never a display name - provenance that moved
    #: when somebody renamed a source would stop matching what was recorded.
    provider: str
    #: A typed pointer back to the row: ``"<type>:<id>"``. Typed because a bare
    #: id resolves to nothing, and resolving the original is the whole point.
    source_ref: str
    origin: EvidenceOrigin
    integrity: Integrity
    #: When the thing happened, per whoever observed it. ``None`` when the
    #: source genuinely does not know.
    observed_at: datetime | None
    #: When AEGISX recorded it. Never inferred from ``observed_at``.
    collected_at: datetime
    confidence: float | None = None
    confidence_basis: str | None = None
    incident_ref: str | None = None
    event_ref: str | None = None
    #: The underlying data is simulator output, not activity on a real system.
    is_synthetic: bool = False
    #: Anything else the producer wants on the record. Small, and never a copy
    #: of the source object.
    extra: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not (self.provider or "").strip():
            raise ValueError(
                "provider is required. Evidence whose origin cannot be named "
                "is not evidence."
            )
        if not (self.source_ref or "").strip():
            raise ValueError("source_ref is required.")
        if ":" not in self.source_ref:
            raise ValueError(
                f"source_ref {self.source_ref!r} is not typed. It must read "
                "'<type>:<id>' so the original object can be resolved."
            )
        if self.collected_at is None:
            raise ValueError(
                "collected_at is required. When the platform learned something "
                "is part of the evidence."
            )
        _require_aware(self.collected_at, "collected_at")
        _require_aware(self.observed_at, "observed_at")

        if self.confidence is not None:
            if not 0.0 <= self.confidence <= 1.0:
                raise ValueError(
                    f"confidence {self.confidence} is outside 0..1."
                )
            if not (self.confidence_basis or "").strip():
                raise ValueError(
                    "confidence_basis is required whenever a confidence is "
                    "given. A bare number invites an analyst to compare it "
                    "with a number that means something else."
                )

    @property
    def is_tamper_evident_at_rest(self) -> bool:
        """Whether a digest taken now still describes the row later.

        False for a mutable source. That is not a defect to hide - it is the
        fact an analyst needs when the evidence is a vendor verdict that may
        since have been re-looked-up and overwritten.
        """
        return self.integrity in _TAMPER_EVIDENT

    def to_dict(self) -> dict[str, Any]:
        return {
            "provider": self.provider,
            "sourceRef": self.source_ref,
            "origin": self.origin.value,
            "integrity": self.integrity.value,
            "tamperEvidentAtRest": self.is_tamper_evident_at_rest,
            "observedAt": self.observed_at.isoformat() if self.observed_at else None,
            "collectedAt": self.collected_at.isoformat(),
            "confidence": self.confidence,
            "confidenceBasis": self.confidence_basis,
            "incidentRef": self.incident_ref,
            "eventRef": self.event_ref,
            "isSynthetic": self.is_synthetic,
            "extra": dict(self.extra),
        }


def _canonical(payload: Any) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)


@dataclass(frozen=True, slots=True)
class EvidenceItem:
    """One piece of evidence, with its provenance."""

    kind: EvidenceKind
    title: str
    #: The normalised facts. Small on purpose: this is the projection an
    #: analyst reads, not a copy of the source row.
    content: Mapping[str, Any]
    provenance: Provenance

    @property
    def evidence_id(self) -> str:
        """A stable identity for *this piece of evidence*.

        Derived from what the evidence **is** - its kind and the row it points
        at - and from nothing about when it was collected or what it currently
        says. That separation is the point:

        * collection time is excluded so recomputing the projection does not
          rename everything and rot every stored reference (V8's decision 48);
        * content is excluded so that when a mutable source changes, the item
          remains *the same evidence now saying something different*, rather
          than a new item with the old one vanished. ``content_digest`` is what
          reports the change.
        """
        digest = hashlib.sha256(
            f"{self.kind.value}|{self.provenance.source_ref}".encode()
        ).hexdigest()
        return f"EV-{digest[:16]}"

    @property
    def content_digest(self) -> str:
        """SHA-256 over the canonical content.

        This is what makes a change to a mutable source **detectable**. It is
        deliberately not called an immutability guarantee: nothing here stops
        a row being edited, it only means an edit does not go unnoticed by
        anybody who kept the digest.
        """
        return hashlib.sha256(_canonical(dict(self.content)).encode()).hexdigest()

    @property
    def contains_injection_attempt(self) -> bool:
        """Whether any text here looks like an attempt to steer a model.

        Uses the V3 detector rather than a second one. Evidence text is
        attacker-influenceable by definition - it comes from telemetry - and
        this is a label on the item, not a modification of it.
        """
        return contains_injection_attempt(self.title) or contains_injection_attempt(
            dict(self.content)
        )

    def to_dict(self) -> dict[str, Any]:
        """The analyst-facing form. Content is **not** scrubbed.

        Scrubbing here would hide an attack from the person investigating it:
        the injected command line *is* the evidence. The item is flagged
        instead, and the UI labels it.
        """
        return {
            "evidenceId": self.evidence_id,
            "kind": self.kind.value,
            "title": self.title,
            "content": dict(self.content),
            "contentDigest": self.content_digest,
            "containsInjectionAttempt": self.contains_injection_attempt,
            "provenance": self.provenance.to_dict(),
        }

    def for_model(self) -> dict[str, Any]:
        """The form safe to put in front of a language model.

        Everything goes through ``app.ai.sanitize`` - the existing mechanism,
        not a competing one - and the provenance travels with it, because a
        model that cannot see whether a claim was observed or merely reported
        cannot weigh it.
        """
        return {
            "evidenceId": self.evidence_id,
            "kind": self.kind.value,
            "title": scrub_text(self.title, max_length=255),
            "content": scrub_value(dict(self.content)),
            "provenance": self.provenance.to_dict(),
        }
