"""Binding evidence to a decision, and telling apart the ways it can move.

Phase C could produce a digest of an incident's evidence. Phase B could record
a decision about the incident. Nothing connected them, so an incident could be
closed on Monday, a threat-intelligence verdict flip from ``malicious`` to
``harmless`` on Tuesday when the cache refreshed, and by Wednesday the closure
would appear to rest on evidence that no longer existed - with nothing recording
what had been there and nothing noticing that it moved.

**The hard part is not detecting change. It is refusing to cry wolf.**

``threatintel/service.py`` overwrites ``status``, ``reputation`` and
``looked_up_at`` on the existing row every time an indicator is looked up
again, and ``ioc_repository`` increments a sighting count on every sighting. A
control that reported "evidence tampered with" each time either happened would
be switched off within a week, and then it would be protecting nothing.

So a binding records **each item's digest alongside its integrity level**, not
just one manifest. That is the only way to say *which* item moved and whether
the application has a legitimate path that could have moved it:

``UNCHANGED``   nothing moved.
``EXTENDED``    items were added and nothing the decision rested on changed.
``REFRESHED``   changes confined to ``mutable`` sources. Mechanically routine,
                **materially serious** - the vendor verdict behind a closure may
                now say the opposite. Never presented as benign.
``TAMPERED``    a ``write_once`` or ``append_only`` item changed, or anything
                was removed. The application has no path that does either.

What this does **not** prove: it compares two projections, so an attacker with
database access who edits a row is detected only because the projection of that
row changes. It is not a defence against someone who can also forge the stored
snapshot. It detects change; it is not an integrity seal, and nothing here
claims to be one.
"""

from __future__ import annotations

import hashlib
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from app.evidence.models import EvidenceItem, Integrity

#: How many per-item digests a snapshot keeps.
#:
#: The manifest covers every item however many there are, so **detection is
#: never capped**. This bounds only attribution - which item moved - and a
#: snapshot that hit the cap says so, because a clean verdict derived from a
#: truncated map would be a lie by omission.
MAX_SNAPSHOT_ENTRIES = 5000


def manifest_for(pairs: Iterable[tuple[str, str]]) -> str:
    """The digest over a whole evidence set.

    Sorted, so the order providers happen to run in cannot change it. Covers
    identity *and* content, so it moves if an item is added, removed or
    altered. This is the single definition; ``EvidenceSet`` uses it too, because
    a binding taken from one and compared against the other must agree.
    """
    lines = sorted(f"{evidence_id}:{digest}" for evidence_id, digest in pairs)
    return hashlib.sha256("\n".join(lines).encode()).hexdigest()


@dataclass(frozen=True, slots=True)
class SnapshotEntry:
    """One item's fingerprint at decision time. Not a copy of the evidence."""

    evidence_id: str
    content_digest: str
    integrity: Integrity
    kind: str
    provider: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "evidenceId": self.evidence_id,
            "contentDigest": self.content_digest,
            "integrity": self.integrity.value,
            "kind": self.kind,
            "provider": self.provider,
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> SnapshotEntry:
        return cls(
            evidence_id=str(payload["evidenceId"]),
            content_digest=str(payload["contentDigest"]),
            integrity=Integrity(payload["integrity"]),
            kind=str(payload.get("kind", "")),
            provider=str(payload.get("provider", "")),
        )


@dataclass(frozen=True, slots=True)
class EvidenceSnapshot:
    """What the evidence looked like at one instant."""

    manifest_digest: str
    entries: tuple[SnapshotEntry, ...]
    #: Providers that could not answer when this was taken. A decision made
    #: while a provider was down was made on partial evidence, and that is as
    #: important to record as evidence changing afterwards.
    degraded_providers: tuple[Mapping[str, Any], ...] = ()
    #: True when there were more items than ``MAX_SNAPSHOT_ENTRIES``.
    truncated: bool = False
    #: How many items there actually were, which is not ``len(entries)`` once
    #: truncated.
    entry_count: int = 0

    @property
    def was_complete(self) -> bool:
        """Whether every provider answered when this was taken."""
        return not self.degraded_providers

    @classmethod
    def from_entries(
        cls,
        entries: list[SnapshotEntry],
        *,
        degraded: list[Mapping[str, Any]] | None = None,
        manifest_digest: str | None = None,
        truncated: bool = False,
        entry_count: int | None = None,
    ) -> EvidenceSnapshot:
        kept = list(entries)
        total = entry_count if entry_count is not None else len(kept)
        digest = manifest_digest or manifest_for(
            (item.evidence_id, item.content_digest) for item in kept
        )
        return cls(
            manifest_digest=digest,
            entries=tuple(kept),
            degraded_providers=tuple(degraded or ()),
            truncated=truncated,
            entry_count=total,
        )

    @classmethod
    def from_items(
        cls,
        items: Iterable[EvidenceItem],
        *,
        degraded: list[Mapping[str, Any]] | None = None,
    ) -> EvidenceSnapshot:
        """Take a snapshot of live evidence.

        The manifest is computed over **every** item before the cap is applied,
        so truncation costs attribution and never costs detection.
        """
        materialised = list(items)
        digest = manifest_for(
            (item.evidence_id, item.content_digest) for item in materialised
        )
        entries = [
            SnapshotEntry(
                evidence_id=item.evidence_id,
                content_digest=item.content_digest,
                integrity=item.provenance.integrity,
                kind=item.kind.value,
                provider=item.provenance.provider,
            )
            for item in materialised[:MAX_SNAPSHOT_ENTRIES]
        ]
        return cls(
            manifest_digest=digest,
            entries=tuple(entries),
            degraded_providers=tuple(degraded or ()),
            truncated=len(materialised) > MAX_SNAPSHOT_ENTRIES,
            entry_count=len(materialised),
        )

    def by_id(self) -> dict[str, SnapshotEntry]:
        return {entry.evidence_id: entry for entry in self.entries}

    def to_dict(self) -> dict[str, Any]:
        return {
            "manifestDigest": self.manifest_digest,
            "entryCount": self.entry_count,
            "truncated": self.truncated,
            "degradedProviders": [dict(entry) for entry in self.degraded_providers],
            "entries": [entry.to_dict() for entry in self.entries],
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> EvidenceSnapshot:
        return cls(
            manifest_digest=str(payload["manifestDigest"]),
            entries=tuple(
                SnapshotEntry.from_dict(entry) for entry in payload.get("entries", [])
            ),
            degraded_providers=tuple(payload.get("degradedProviders", []) or ()),
            truncated=bool(payload.get("truncated", False)),
            entry_count=int(payload.get("entryCount", 0)),
        )


class DriftVerdict(str, Enum):
    """How the evidence behind a decision has moved since it was taken."""

    UNCHANGED = "unchanged"
    EXTENDED = "extended"
    REFRESHED = "refreshed"
    TAMPERED = "tampered"

    @property
    def severity(self) -> int:
        return {"unchanged": 0, "extended": 1, "refreshed": 2, "tampered": 3}[self.value]

    @property
    def undermines_decision(self) -> bool:
        """Whether what the decision *rested on* has moved.

        ``EXTENDED`` is excluded deliberately: new evidence arriving does not
        change the basis of the earlier decision, though it may well deserve a
        fresh look. ``REFRESHED`` is included, because a routine cause does not
        make a changed verdict a routine consequence.
        """
        return self in (DriftVerdict.REFRESHED, DriftVerdict.TAMPERED)


@dataclass(frozen=True, slots=True)
class ChangedEntry:
    evidence_id: str
    integrity: Integrity
    kind: str
    provider: str
    digest_at_decision: str
    digest_now: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "evidenceId": self.evidence_id,
            "integrity": self.integrity.value,
            "kind": self.kind,
            "provider": self.provider,
            # Both ends. "It changed" is not actionable; "it changed from this
            # to that" is what an analyst can follow up.
            "digestAtDecision": self.digest_at_decision,
            "digestNow": self.digest_now,
        }


@dataclass(frozen=True, slots=True)
class DriftReport:
    verdict: DriftVerdict
    manifest_at_decision: str
    manifest_now: str
    added: tuple[str, ...] = ()
    removed: tuple[str, ...] = ()
    changed: tuple[ChangedEntry, ...] = ()
    #: False when the decision-time snapshot was truncated, so some items
    #: cannot be attributed. Detection is still sound - the manifest covers
    #: everything - but "which item" may be unanswerable.
    attribution_complete: bool = True
    #: Providers that were down when the decision was taken.
    degraded_at_decision: tuple[Mapping[str, Any], ...] = field(default_factory=tuple)

    @property
    def manifest_matches(self) -> bool:
        return self.manifest_at_decision == self.manifest_now

    @property
    def undermines_decision(self) -> bool:
        return self.verdict.undermines_decision

    def to_dict(self) -> dict[str, Any]:
        return {
            "verdict": self.verdict.value,
            "severity": self.verdict.severity,
            "undermines_decision": self.undermines_decision,
            "manifest_matches": self.manifest_matches,
            "manifestAtDecision": self.manifest_at_decision,
            "manifestNow": self.manifest_now,
            "added": list(self.added),
            "removed": list(self.removed),
            "changed": [entry.to_dict() for entry in self.changed],
            "attributionComplete": self.attribution_complete,
            "degradedAtDecision": [dict(entry) for entry in self.degraded_at_decision],
        }


def classify_drift(at_decision: EvidenceSnapshot, now: EvidenceSnapshot) -> DriftReport:
    """Compare the evidence behind a decision with the evidence there now.

    The manifest is authoritative for *detection*: if it matches, nothing moved,
    and that holds even for a truncated snapshot because the manifest was
    computed before the cap. The per-item map is what turns detection into
    attribution, and when it was truncated the report says so rather than
    reporting a clean verdict it cannot support.
    """
    before = at_decision.by_id()
    after = now.by_id()

    added = tuple(sorted(set(after) - set(before)))
    removed = tuple(sorted(set(before) - set(after)))

    changed = tuple(
        ChangedEntry(
            evidence_id=evidence_id,
            integrity=before[evidence_id].integrity,
            kind=before[evidence_id].kind,
            provider=before[evidence_id].provider,
            digest_at_decision=before[evidence_id].content_digest,
            digest_now=after[evidence_id].content_digest,
        )
        for evidence_id in sorted(set(before) & set(after))
        if before[evidence_id].content_digest != after[evidence_id].content_digest
    )

    attribution_complete = not at_decision.truncated
    manifest_matches = at_decision.manifest_digest == now.manifest_digest

    verdict = _verdict(
        manifest_matches=manifest_matches,
        added=added,
        removed=removed,
        changed=changed,
        attribution_complete=attribution_complete,
    )

    return DriftReport(
        verdict=verdict,
        manifest_at_decision=at_decision.manifest_digest,
        manifest_now=now.manifest_digest,
        added=added,
        removed=removed,
        changed=changed,
        attribution_complete=attribution_complete,
        degraded_at_decision=at_decision.degraded_providers,
    )


def _verdict(
    *,
    manifest_matches: bool,
    added: tuple[str, ...],
    removed: tuple[str, ...],
    changed: tuple[ChangedEntry, ...],
    attribution_complete: bool,
) -> DriftVerdict:
    if manifest_matches:
        # Authoritative, truncated or not: the manifest covered every item.
        return DriftVerdict.UNCHANGED

    # A removal is never routine. Nothing in the application deletes evidence,
    # and calling a deletion a refresh would let the most damaging change - the
    # finding a closure rested on disappearing - be reported as cache churn.
    if removed:
        return DriftVerdict.TAMPERED

    if any(entry.integrity is not Integrity.MUTABLE for entry in changed):
        return DriftVerdict.TAMPERED

    if changed:
        return DriftVerdict.REFRESHED

    if added:
        return DriftVerdict.EXTENDED

    # The manifest moved but the per-item comparison explains none of it. With
    # a complete map that is a contradiction and the safest reading is
    # tampering; with a truncated one it is simply the part we cannot see.
    return DriftVerdict.TAMPERED if attribution_complete else DriftVerdict.REFRESHED
