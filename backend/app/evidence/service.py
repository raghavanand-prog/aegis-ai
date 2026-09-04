"""Assembling the evidence for one incident.

There is no write path in this module, and that is the design rather than an
omission. Evidence is a **projection** of records the platform already holds,
so there is nothing here that creates, edits or deletes an evidence item -
which is the strongest available form of requirement 8's "an analyst must not
be able to silently rewrite historical evidence". It is not enforced by a
policy that could be forgotten; there is simply no function that would do it.

What the projection cannot do on its own is tell you what the evidence looked
like *at the time a decision was taken*, because two of the six sources are
rewritten in place. ``manifest_digest`` is the answer to that: a single digest
over the identity and content of every item in the set, cheap to record
alongside a decision and sufficient afterwards to prove the evidence has or has
not moved. Recording one against an approval belongs with approvals, in a later
phase; producing one belongs here.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Any

from app.evidence import registry
from app.evidence.models import EvidenceItem, EvidenceKind


@dataclass(frozen=True, slots=True)
class EvidenceSet:
    """Every piece of evidence for one incident, and what could not be reached."""

    incident_ref: str
    items: tuple[EvidenceItem, ...]
    #: Providers that returned nothing because they were degraded or broken.
    #: Carried separately from the items so that "we have no evidence" and "we
    #: could not ask" never render the same way.
    degraded: tuple[dict[str, Any], ...] = ()
    #: Filters that produced this set, echoed back so a caller cannot mistake a
    #: filtered view for the whole picture.
    filters: dict[str, Any] = field(default_factory=dict)

    @property
    def manifest_digest(self) -> str:
        """One digest over the whole set.

        Covers each item's identity **and** its content digest, so it changes
        if an item is added, removed, or altered underneath. Sorted, so the
        order providers happen to run in cannot change it.
        """
        lines = sorted(f"{item.evidence_id}:{item.content_digest}" for item in self.items)
        return hashlib.sha256("\n".join(lines).encode()).hexdigest()

    def counts_by_kind(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for item in self.items:
            counts[item.kind.value] = counts.get(item.kind.value, 0) + 1
        return counts

    def counts_by_origin(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for item in self.items:
            key = item.provenance.origin.value
            counts[key] = counts.get(key, 0) + 1
        return counts

    @property
    def injection_flagged(self) -> tuple[str, ...]:
        return tuple(item.evidence_id for item in self.items if item.contains_injection_attempt)

    def to_dict(self) -> dict[str, Any]:
        return {
            "incidentId": self.incident_ref,
            "manifestDigest": self.manifest_digest,
            "total": len(self.items),
            "countsByKind": self.counts_by_kind(),
            "countsByOrigin": self.counts_by_origin(),
            "injectionFlagged": list(self.injection_flagged),
            "degradedProviders": [dict(entry) for entry in self.degraded],
            "filters": dict(self.filters),
            "items": [item.to_dict() for item in self.items],
        }


def _sort_key(item: EvidenceItem) -> tuple[Any, ...]:
    """Newest first by when the thing happened, then deterministically.

    ``observed_at`` can be ``None`` when a source genuinely does not know, and
    those sort last rather than being dropped or given a fabricated timestamp.
    """
    observed = item.provenance.observed_at
    return (0 if observed is None else 1, observed or "", item.evidence_id)


def collect_for_incident(
    db: Any,
    incident: Any,
    *,
    kind: EvidenceKind | None = None,
    provider: str | None = None,
) -> EvidenceSet:
    """Every provider's evidence for one incident, filtered and ordered."""
    items, degraded = registry.collect_all(db, incident)

    if kind is not None:
        items = [item for item in items if item.kind is kind]
    if provider is not None:
        items = [item for item in items if item.provenance.provider == provider]

    items.sort(key=_sort_key, reverse=True)

    return EvidenceSet(
        incident_ref=incident.incident_id,
        items=tuple(items),
        degraded=tuple(degraded),
        filters={
            "kind": kind.value if kind else None,
            "provider": provider,
        },
    )


def get_item(db: Any, incident: Any, evidence_id: str) -> EvidenceItem | None:
    """One evidence item, **scoped to this incident**.

    The scoping is the security property. Evidence ids are derived from the
    source row, so an analyst who learns the id of an item on an incident they
    cannot see must not be able to fetch it by pointing at one they can. This
    function only ever searches the set belonging to the incident the caller
    was already authorised for, so a foreign id resolves to nothing rather than
    to somebody else's evidence.
    """
    for item in collect_for_incident(db, incident).items:
        if item.evidence_id == evidence_id:
            return item
    return None
