"""Evidence API schemas.

Response shapes only. There is deliberately no request body anywhere in this
module: the evidence API is read-only, so there is nothing a caller can send
that would change what an item says about itself.
"""

from __future__ import annotations

from typing import Any

from pydantic import Field

from app.schemas.common import CamelModel


class ProvenanceRead(CamelModel):
    """Where one piece of evidence came from, and what it is worth."""

    provider: str
    #: Typed pointer back to the row: ``"<type>:<id>"``.
    source_ref: str
    #: observed / derived / reported / analytic / simulated.
    origin: str
    #: append_only / write_once / mutable - what the platform can actually
    #: promise about the stored row, not what it would like to claim.
    integrity: str
    #: False for a mutable source: the content behind this item can change
    #: after a decision was made on it.
    tamper_evident_at_rest: bool
    observed_at: str | None = None
    collected_at: str
    confidence: float | None = None
    #: What the confidence number measures. Always present when there is one.
    confidence_basis: str | None = None
    incident_ref: str | None = None
    event_ref: str | None = None
    is_synthetic: bool = False
    extra: dict[str, Any] = Field(default_factory=dict)


class EvidenceItemRead(CamelModel):
    evidence_id: str
    kind: str
    title: str
    #: The normalised facts. Not scrubbed: an injected command line *is* the
    #: evidence, and hiding it from an analyst would hide the attack.
    content: dict[str, Any] = Field(default_factory=dict)
    content_digest: str
    #: True when the text looks like an attempt to steer a language model.
    contains_injection_attempt: bool = False
    provenance: ProvenanceRead


class DegradedProvider(CamelModel):
    provider: str
    status: str
    reason: str | None = None


class EvidenceSetRead(CamelModel):
    incident_id: str
    #: One digest over every item's identity and content. Stable while the
    #: evidence is; changes if anything is added, removed or altered.
    manifest_digest: str
    total: int
    counts_by_kind: dict[str, int] = Field(default_factory=dict)
    counts_by_origin: dict[str, int] = Field(default_factory=dict)
    injection_flagged: list[str] = Field(default_factory=list)
    #: Providers that could not answer. Separate from an empty item list, so
    #: "no evidence" and "we could not ask" never render the same way.
    degraded_providers: list[DegradedProvider] = Field(default_factory=list)
    filters: dict[str, Any] = Field(default_factory=dict)
    items: list[EvidenceItemRead] = Field(default_factory=list)
