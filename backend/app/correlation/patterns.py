"""Correlation patterns.

A pattern answers two questions about an event:

    "which group does this belong to?"      -> correlation key
    "is this group worth telling anyone about?" -> evaluation

Keeping that in one declarative place, rather than scattered through the
ingestion path, is what makes correlation testable and what lets a new pattern
be added without touching the pipeline.

Patterns are deliberately entity-based and time-bounded. They do not attempt
to reconstruct an attacker's intent; they observe that several things happened
to the same host, user or address inside a window, and say so.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from app.models.enums import Severity
from app.models.event import Event

# --------------------------------------------------------------------------- helpers
AUTH_FAILURE_TYPES = {"auth_failure", "sign_in_failure"}
AUTH_SUCCESS_TYPES = {"auth_success", "sign_in_success", "ssh_login"}
EXECUTION_TYPES = {"process_creation", "credential_access"}
PRIVILEGE_TYPES = {"privilege_escalation", "sudo_abuse"}
NETWORK_TYPES = {"firewall_allow", "firewall_deny", "network_connection", "data_exfiltration"}
LATERAL_TYPES = {"lateral_movement", "network_connection", "ssh_login"}


def _types(events: list[Event]) -> set[str]:
    return {(event.event_type or "").lower() for event in events}


def _distinct(events: list[Event], attribute: str) -> set[str]:
    return {
        str(getattr(event, attribute))
        for event in events
        if getattr(event, attribute, None)
    }


def _has_ml_anomaly(events: list[Event]) -> bool:
    return any(
        any(inference.is_anomaly for inference in (event.ml_inferences or []))
        for event in events
    )


@dataclass
class PatternVerdict:
    """What a pattern concluded about a candidate group of events."""

    matched: bool
    title: str = ""
    description: str = ""
    severity: str = Severity.MEDIUM.value
    #: 0..1. Derived from how many independent things line up - never a model
    #: output, and never presented as a probability of compromise.
    confidence: float = 0.0
    rationale: list[str] = None  # type: ignore[assignment]

    def __post_init__(self) -> None:
        if self.rationale is None:
            self.rationale = []


@dataclass(frozen=True)
class CorrelationPattern:
    """One way of grouping related events, plus what makes a group notable."""

    id: str
    name: str
    description: str
    #: Returns the grouping key for an event, or None when the event is not a
    #: candidate for this pattern at all.
    key_for: Callable[[Event], str | None]
    #: Judges a candidate group. Receives the events ordered oldest first.
    evaluate: Callable[[list[Event]], PatternVerdict]
    #: Minimum group size before ``evaluate`` is even called.
    min_events: int = 2
    #: MITRE techniques this pattern *infers* from the shape of the sequence.
    #: Marked as inferred, never as directly observed - see correlation/mitre.py.
    inferred_techniques: tuple[str, ...] = ()


# --------------------------------------------------------------------------- patterns
def _brute_force_key(event: Event) -> str | None:
    event_type = (event.event_type or "").lower()
    if event_type not in AUTH_FAILURE_TYPES | AUTH_SUCCESS_TYPES:
        return None
    if event.username:
        return f"user:{event.username}"
    if event.source_ip:
        return f"ip:{event.source_ip}"
    return None


def _brute_force(events: list[Event]) -> PatternVerdict:
    failures = [e for e in events if (e.event_type or "").lower() in AUTH_FAILURE_TYPES]
    successes = [e for e in events if (e.event_type or "").lower() in AUTH_SUCCESS_TYPES]
    if len(failures) < 2:
        return PatternVerdict(matched=False)

    sources = _distinct(events, "source_ip")
    rationale = [
        f"{len(failures)} authentication failure(s) in the correlation window",
    ]
    confidence = 0.35 + min(len(failures), 10) * 0.03
    severity = Severity.MEDIUM.value
    title = "Repeated authentication failures"

    if successes:
        # This is the pattern that matters: the attempt eventually worked.
        title = "Authentication failures followed by a successful sign-in"
        severity = Severity.HIGH.value
        confidence += 0.30
        rationale.append(
            f"a successful sign-in followed at {successes[-1].timestamp.isoformat()}"
        )
    if len(sources) > 1:
        confidence += 0.10
        rationale.append(f"attempts came from {len(sources)} distinct source addresses")
    if _has_ml_anomaly(events):
        confidence += 0.10
        rationale.append("at least one event was also flagged anomalous by the ML model")

    principal = next((e.username for e in events if e.username), None)
    return PatternVerdict(
        matched=True,
        title=f"{title}: {principal}" if principal else title,
        description=(
            f"{len(failures)} failed and {len(successes)} successful authentication "
            f"event(s) correlated on the same principal within the window."
        ),
        severity=severity,
        confidence=min(confidence, 0.95),
        rationale=rationale,
    )


def _host_chain_key(event: Event) -> str | None:
    return f"host:{event.hostname}" if event.hostname else None


def _host_chain(events: list[Event]) -> PatternVerdict:
    """Several different *kinds* of activity on one host in a short window.

    This is the closest V3 gets to an attack chain: not an inferred narrative,
    but the observation that authentication, execution, privilege change and
    network activity all touched the same host at once - which is unusual for
    ordinary work and worth an analyst's attention.
    """
    types = _types(events)
    stages = {
        "authentication": bool(types & (AUTH_FAILURE_TYPES | AUTH_SUCCESS_TYPES)),
        "execution": bool(types & EXECUTION_TYPES),
        "privilege escalation": bool(types & PRIVILEGE_TYPES),
        "network activity": bool(types & NETWORK_TYPES),
        "malware": bool(types & {"malware_detected", "threat_detected", "ransomware_behavior"}),
    }
    present = [name for name, seen in stages.items() if seen]
    if len(present) < 3:
        return PatternVerdict(matched=False)

    confidence = 0.30 + 0.12 * len(present)
    rationale = [
        f"{len(events)} events on this host covering {len(present)} distinct activity "
        f"stages: {', '.join(present)}"
    ]
    severity = Severity.HIGH.value if len(present) >= 4 else Severity.MEDIUM.value

    if stages["privilege escalation"] and stages["execution"]:
        confidence += 0.10
        rationale.append("process execution and a privilege change occurred together")
    if _has_ml_anomaly(events):
        confidence += 0.10
        rationale.append("the ML model flagged at least one of these events as anomalous")

    host = next((e.hostname for e in events if e.hostname), "a host")
    return PatternVerdict(
        matched=True,
        title=f"Multi-stage activity on {host}",
        description=(
            f"Activity covering {', '.join(present)} was observed on {host} within the "
            "correlation window. Individually these events are ordinary; together they "
            "form a pattern worth reviewing."
        ),
        severity=severity,
        confidence=min(confidence, 0.90),
        rationale=rationale,
    )


def _lateral_key(event: Event) -> str | None:
    event_type = (event.event_type or "").lower()
    if event_type not in LATERAL_TYPES:
        return None
    return f"user:{event.username}" if event.username else None


def _lateral_movement(events: list[Event]) -> PatternVerdict:
    """One account touching several hosts in a short window.

    The deterministic rule set has no lateral movement rule - that gap is
    measured and reported by the V2 evaluation. Correlation is the natural
    place to close it, because the signal is not in any single event: it is one
    principal appearing on hosts it does not normally appear on.
    """
    hosts = _distinct(events, "hostname")
    destinations = _distinct(events, "destination_ip")
    reach = hosts | destinations
    if len(reach) < 3:
        return PatternVerdict(matched=False)

    confidence = 0.30 + min(len(reach), 8) * 0.06
    rationale = [
        f"one principal was seen against {len(reach)} distinct hosts/destinations "
        "within the correlation window"
    ]
    if _has_ml_anomaly(events):
        confidence += 0.10
        rationale.append("the ML model flagged at least one of these connections as anomalous")

    principal = next((e.username for e in events if e.username), "an account")
    return PatternVerdict(
        matched=True,
        title=f"Account {principal} reached multiple hosts",
        description=(
            f"{principal} produced connection or sign-in activity against {len(reach)} "
            "distinct systems in a short window. This shape is consistent with lateral "
            "movement, and is also consistent with an administrator or a scanner - it is "
            "flagged for review, not classified."
        ),
        severity=Severity.MEDIUM.value,
        confidence=min(confidence, 0.85),
        rationale=rationale,
    )


def _source_ip_key(event: Event) -> str | None:
    return f"ip:{event.source_ip}" if event.source_ip else None


def _external_pressure(events: list[Event]) -> PatternVerdict:
    """One external address producing sustained, varied activity."""
    types = _types(events)
    ports = {event.destination_port for event in events if event.destination_port}
    hosts = _distinct(events, "hostname")

    if len(types) < 2 and len(ports) < 5:
        return PatternVerdict(matched=False)

    confidence = 0.25 + 0.05 * len(types) + min(len(ports), 10) * 0.03
    rationale = [
        f"{len(events)} events from one source address covering {len(types)} event type(s)"
    ]
    if ports:
        rationale.append(f"{len(ports)} distinct destination port(s) touched")
    if len(hosts) > 1:
        confidence += 0.10
        rationale.append(f"{len(hosts)} internal hosts were contacted")
    if _has_ml_anomaly(events):
        confidence += 0.10
        rationale.append("the ML model flagged at least one of these events as anomalous")

    address = next((e.source_ip for e in events if e.source_ip), "a source address")
    return PatternVerdict(
        matched=True,
        title=f"Sustained activity from {address}",
        description=(
            f"{address} produced {len(events)} correlated events against "
            f"{len(hosts) or 1} host(s) within the window."
        ),
        severity=Severity.MEDIUM.value,
        confidence=min(confidence, 0.85),
        rationale=rationale,
    )


PATTERNS: tuple[CorrelationPattern, ...] = (
    CorrelationPattern(
        id="COR-AUTH-001",
        name="Credential attack sequence",
        description=(
            "Repeated authentication failures against one principal, and in particular "
            "failures followed by a success - the shape of a brute force that worked."
        ),
        key_for=_brute_force_key,
        evaluate=_brute_force,
        min_events=3,
        inferred_techniques=("T1110",),
    ),
    CorrelationPattern(
        id="COR-HOST-001",
        name="Multi-stage host activity",
        description=(
            "Authentication, execution, privilege change and network activity touching "
            "one host inside the correlation window."
        ),
        key_for=_host_chain_key,
        evaluate=_host_chain,
        min_events=3,
        inferred_techniques=(),
    ),
    CorrelationPattern(
        id="COR-LAT-001",
        name="Account reaching multiple systems",
        description=(
            "One principal producing connection or sign-in activity against several "
            "distinct hosts in a short window. Closes the lateral-movement gap the "
            "deterministic rule set does not cover."
        ),
        key_for=_lateral_key,
        evaluate=_lateral_movement,
        min_events=3,
        inferred_techniques=("T1021",),
    ),
    CorrelationPattern(
        id="COR-NET-001",
        name="Sustained activity from one source",
        description=(
            "A single source address producing varied, sustained activity against the "
            "estate."
        ),
        key_for=_source_ip_key,
        evaluate=_external_pressure,
        min_events=4,
        inferred_techniques=(),
    ),
)

PATTERNS_BY_ID: dict[str, CorrelationPattern] = {pattern.id: pattern for pattern in PATTERNS}


def catalogue() -> list[dict[str, Any]]:
    return [
        {
            "id": pattern.id,
            "name": pattern.name,
            "description": pattern.description,
            "minEvents": pattern.min_events,
            "inferredTechniques": list(pattern.inferred_techniques),
        }
        for pattern in PATTERNS
    ]
