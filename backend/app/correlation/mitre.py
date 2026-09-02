"""MITRE ATT&CK provenance.

A technique on a sequence is not automatically the same kind of claim as a
technique on a rule match, and pretending otherwise is how a SOC platform ends
up asserting that "AI discovered T1110".

Three kinds, kept distinct everywhere they are stored or displayed:

``mapped``
    A deterministic rule declared this technique. The rule states the condition
    it matched, so the mapping is as strong as the rule.

``inferred``
    The correlation engine derived it from the *shape* of a sequence - failures
    then a success implies brute force, one account on many hosts implies
    remote services. The inference is stated, and so is the fact that it is one.

``contextual``
    Carried along from a member event for background. It says "this technique
    appears somewhere in this group", not "this group is this technique".

The ML model contributes **no** techniques at all. Isolation Forest identifies
statistical outliers; it has no concept of an attack technique, and asserting
one on its behalf would be a fabrication.
"""

from __future__ import annotations

from typing import Any

MAPPED = "mapped"
INFERRED = "inferred"
CONTEXTUAL = "contextual"

_RANK = {MAPPED: 3, INFERRED: 2, CONTEXTUAL: 1}


def technique(technique_id: str, provenance: str, source: str, detail: str = "") -> dict[str, Any]:
    return {
        "technique": technique_id,
        "provenance": provenance,
        "source": source,
        "detail": detail,
    }


def merge(entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """De-duplicate by technique, keeping the strongest provenance for each.

    A technique that is both directly mapped by a rule and inferred by
    correlation is a mapped technique - the weaker claim adds nothing.
    """
    best: dict[str, dict[str, Any]] = {}
    for entry in entries:
        key = str(entry.get("technique") or "").strip()
        if not key:
            continue
        current = best.get(key)
        if current is None or _RANK.get(entry.get("provenance", ""), 0) > _RANK.get(
            current.get("provenance", ""), 0
        ):
            best[key] = entry
    return sorted(best.values(), key=lambda item: item["technique"])


def ids(entries: list[dict[str, Any]]) -> list[str]:
    """Flat technique ids, for the existing V1/V2 fields that expect strings."""
    return [str(entry["technique"]) for entry in entries]


def from_events(events) -> list[dict[str, Any]]:  # noqa: ANN001 - list[Event]
    """Techniques carried by member events.

    Anything a rule declared is ``mapped``; anything else present on the event
    is ``contextual``.
    """
    entries: list[dict[str, Any]] = []
    for event in events:
        rule_techniques: set[str] = set()
        for detection in event.detections or []:
            rule_id = detection.get("ruleId", "rule")
            for value in detection.get("mitreTechniques") or []:
                rule_techniques.add(str(value))
                entries.append(
                    technique(
                        str(value),
                        MAPPED,
                        rule_id,
                        f"Declared by {rule_id} on {event.event_id}",
                    )
                )
        for value in event.mitre_techniques or []:
            if str(value) not in rule_techniques:
                entries.append(
                    technique(
                        str(value),
                        CONTEXTUAL,
                        event.event_id,
                        "Present on a member event without a rule declaring it",
                    )
                )
    return merge(entries)
