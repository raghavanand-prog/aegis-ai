"""Incident creation, promotion from events, and updates."""

from __future__ import annotations

import logging
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from app.incidents import lifecycle
from app.models.enums import AuditAction, IncidentStatus, UserRole
from app.models.event import Event
from app.models.incident import Incident
from app.models.user import User
from app.repositories.event_repository import event_repository
from app.repositories.incident_repository import incident_repository
from app.schemas.event import EventPromoteRequest
from app.schemas.incident import IncidentCreate, IncidentUpdate
from app.services import audit_service, decision_service, notification_service
from app.services.serializers import incident_to_schema
from app.ws.manager import manager

logger = logging.getLogger(__name__)


class IncidentError(Exception):
    """Raised for invalid incident operations (e.g. promoting twice)."""


#: States an incident may be created in. Everything else is reached by a
#: transition, which is authorised on its own terms - see `create_incident`.
ENTRY_STATUSES: frozenset[IncidentStatus] = frozenset(
    {IncidentStatus.OPEN, IncidentStatus.TRIAGED, IncidentStatus.INVESTIGATING}
)


def _timeline_entry(action: str, actor: str, detail: str) -> dict:
    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "action": action,
        "actor": actor,
        "detail": detail,
    }


def _lifecycle_actor(user: User | None) -> str:
    """The identity the lifecycle checks, which is not the one the UI shows.

    Two separate jobs. The timeline wants a display name; the lifecycle wants a
    stable identity it can test against the non-human actor prefixes.

    Passing the display name would let a person called ``system`` or an account
    whose full name began ``ai:`` be judged on their name rather than on what
    they are, and - the direction that actually matters - a call with no user at
    all resolved to the bare string ``"system"``, which does **not** match the
    ``system:`` prefix and so read as a human. An unauthenticated internal
    caller would have been allowed to close incidents. The prefix is applied
    here so that cannot depend on how somebody spells a name.
    """
    if user is None:
        return "system:aegisx"
    return user.email


def _resolved_at_for(incident: Incident, target: IncidentStatus) -> datetime | None:
    """When this incident was resolved, after moving to ``target``.

    Through V8 this was ``now() if target is RESOLVED else None``, so **closing
    a resolved incident erased when it had been resolved** - the one transition
    that most obviously should preserve it. The rule is not "is the new state
    RESOLVED" but "is the incident still finished":

    * moving to ``Resolved`` stamps it, first time or on a re-resolve;
    * moving to ``Closed`` keeps whatever is there, because closing seals a
      resolution rather than replacing it;
    * anything else means the incident is being worked again, and a resolution
      timestamp on an incident under investigation is a false statement.
    """
    if target is IncidentStatus.RESOLVED:
        return datetime.now(timezone.utc)
    if target is IncidentStatus.CLOSED:
        return incident.resolved_at
    return None


def _broadcast(incident: Incident, message_type: str) -> None:
    manager.broadcast_threadsafe(
        message_type, incident_to_schema(incident).model_dump(by_alias=True, mode="json")
    )


def recompute_risk(db: Session, incident: Incident) -> None:
    """Make the incident's risk score and its explanation agree.

    An incident inherits evidence from several places: the rule and ML signals
    on each linked event, and the correlation signal from any sequence it was
    promoted from. Taking the score from one source and the signal list from
    another - which is what happened before this existed - produces a panel
    where the number and the reasons underneath it do not add up, and an
    analyst has no way to tell which is wrong.

    The strongest contribution per (type, source) is kept rather than the sum:
    one rule firing across twenty linked events is one finding observed twenty
    times, and summing would let repetition alone manufacture a critical.
    """
    strongest: dict[tuple[str, str], dict] = {}

    def offer(signal: dict) -> None:
        key = (str(signal.get("type", "")), str(signal.get("source", "")))
        current = strongest.get(key)
        if current is None or signal.get("contribution", 0) > current.get("contribution", 0):
            strongest[key] = signal

    for event in incident.events or []:
        for signal in event.risk_signals or []:
            offer(signal)
    for sequence in incident.sequences or []:
        for signal in sequence.risk_signals or []:
            offer(signal)

    signals = sorted(
        strongest.values(), key=lambda item: item.get("contribution", 0), reverse=True
    )
    total = min(sum(int(signal.get("contribution", 0)) for signal in signals), 100)

    incident.risk_signals = signals
    # Events scored before V3 carry no signals at all; falling back to the
    # highest member score keeps those incidents from collapsing to zero.
    incident.risk_score = total if signals else max(
        (event.risk_score for event in incident.events or []), default=incident.risk_score
    )
    db.flush()


def _link_events(db: Session, incident: Incident, events: list[Event]) -> None:
    for event in events:
        event.incident_id = incident.id
        for ioc in event.iocs:
            if ioc not in incident.iocs:
                incident.iocs.append(ioc)
        for technique in event.mitre_techniques or []:
            if technique not in (incident.mitre_techniques or []):
                incident.mitre_techniques = [*(incident.mitre_techniques or []), technique]
    db.flush()


def create_incident(
    db: Session,
    payload: IncidentCreate,
    *,
    user: User | None = None,
    broadcast: bool = True,
) -> Incident:
    if payload.status not in ENTRY_STATUSES:
        # Otherwise creation is a way around the transition rules entirely: an
        # actor holding only `incidents:create` could produce an incident
        # already `Closed`, or one asserting `Contained`, without ever holding
        # the authority those transitions require.
        allowed = ", ".join(sorted(status.value for status in ENTRY_STATUSES))
        raise IncidentError(
            f"An incident cannot be created as {payload.status.value!r}. A new "
            f"incident starts in one of: {allowed}. Reaching any other state is "
            "a transition, and transitions are authorised individually."
        )

    events = event_repository.get_many_by_event_ids(db, payload.event_ids)
    missing = set(payload.event_ids) - {event.event_id for event in events}
    if missing:
        raise IncidentError(f"Unknown event(s): {', '.join(sorted(missing))}")

    risk_score = max((event.risk_score for event in events), default=0)
    actor = user.full_name or user.email if user else "system"

    incident = Incident(
        title=payload.title,
        description=payload.description,
        severity=payload.severity.value,
        status=payload.status.value,
        source=payload.source,
        analyst=payload.analyst,
        assignee_id=user.id if (user and payload.analyst != "Unassigned") else None,
        risk_score=risk_score,
        mitre_techniques=list(payload.mitre_techniques),
        timeline=[_timeline_entry("created", actor, f"Incident opened from {len(events)} event(s).")],
    )
    incident_repository.create(db, incident)
    _link_events(db, incident, events)
    recompute_risk(db, incident)

    audit_service.record(
        db,
        action=AuditAction.INCIDENT_CREATED,
        user=user,
        target_type="incident",
        target_id=incident.incident_id,
        details={"title": incident.title, "eventIds": [event.event_id for event in events]},
    )
    notification_service.notify_incident_created(db, incident, broadcast=broadcast)
    db.flush()

    if broadcast:
        _broadcast(incident, "incident.created")
    return incident


def promote_event(
    db: Session,
    event: Event,
    payload: EventPromoteRequest | None = None,
    *,
    user: User | None = None,
    broadcast: bool = True,
) -> Incident:
    """Promote a single event into a new incident."""
    if event.incident_id is not None:
        raise IncidentError(f"{event.event_id} is already linked to an incident.")

    payload = payload or EventPromoteRequest()
    actor = (user.full_name or user.email) if user else "system"
    severity = (payload.severity.value if payload.severity else event.severity)
    analyst = payload.analyst or (user.full_name or user.email if user else "Unassigned")

    incident = Incident(
        title=payload.title or event.title,
        description=payload.description
        or f"Promoted from {event.event_id}: {event.description or event.title}",
        severity=severity,
        status=IncidentStatus.OPEN.value,
        source=event.source,
        analyst=analyst,
        assignee_id=user.id if user else None,
        risk_score=event.risk_score,
        mitre_techniques=list(event.mitre_techniques or []),
        timeline=[
            _timeline_entry("promoted", actor, f"Incident promoted from event {event.event_id}."),
        ],
    )
    incident_repository.create(db, incident)
    _link_events(db, incident, [event])
    recompute_risk(db, incident)

    audit_service.record(
        db,
        action=AuditAction.EVENT_PROMOTED,
        user=user,
        target_type="event",
        target_id=event.event_id,
        details={"incidentId": incident.incident_id, "severity": severity},
    )
    audit_service.record(
        db,
        action=AuditAction.INCIDENT_CREATED,
        user=user,
        target_type="incident",
        target_id=incident.incident_id,
        details={"promotedFrom": event.event_id},
    )
    notification_service.notify_incident_created(db, incident, broadcast=broadcast)
    db.flush()

    if broadcast:
        _broadcast(incident, "incident.created")
        from app.services.serializers import event_to_schema  # local import avoids a cycle

        manager.broadcast_threadsafe(
            "event.updated", event_to_schema(event).model_dump(by_alias=True, mode="json")
        )
    return incident


def update_incident(
    db: Session,
    incident: Incident,
    payload: IncidentUpdate,
    *,
    user: User | None = None,
    broadcast: bool = True,
) -> Incident:
    actor = (user.full_name or user.email) if user else "system"
    timeline = list(incident.timeline or [])

    # Validate the transition BEFORE touching anything.
    #
    # The router rolls back on a refusal, so relying on that would also work
    # today. It would stop working the moment a worker, a CLI command or a test
    # called this function without one, and the failure mode is a half-applied
    # PATCH: the title edited, the status not, and nothing to say so. A service
    # that is only safe when its caller remembers to clean up is not safe.
    status_change: tuple[str, IncidentStatus, str | None] | None = None
    evidence_snapshot = None
    if payload.status is not None and payload.status.value != incident.status:
        # An unchanged status is short-circuited above rather than validated:
        # the UI sends the whole object back, and a PATCH re-stating the current
        # status while editing a title is not a self-transition.
        reason = (payload.status_reason or "").strip() or None
        _, target = lifecycle.validate_transition(
            incident.status,
            payload.status,
            actor=_lifecycle_actor(user),
            actor_role=user.role if user else UserRole.ADMIN.value,
            reason=reason,
        )
        status_change = (incident.status, target, reason)

        # V9: bind the decision to the evidence it is being taken on.
        #
        # Only for transitions the lifecycle already treats as consequential -
        # containment, closure, and every edge that must carry a reason. Routine
        # forward progress concludes nothing, and collecting from seven
        # providers on every ordinary PATCH would be a cost with no evidentiary
        # return.
        #
        # One collection serves both the expected-digest check and the stored
        # binding. Collecting twice would leave a window in which the evidence
        # changes between the two, and the record would then describe evidence
        # the decision was never actually checked against.
        if decision_service.is_consequential(incident.status, target):
            evidence_snapshot = decision_service.snapshot_for(db, incident)
            decision_service.check_expected_digest(
                evidence_snapshot, payload.expected_evidence_digest
            )

    if payload.title is not None:
        incident.title = payload.title
    if payload.description is not None:
        incident.description = payload.description
    if payload.severity is not None and payload.severity.value != incident.severity:
        timeline.append(
            _timeline_entry(
                "severity_changed", actor, f"{incident.severity} -> {payload.severity.value}"
            )
        )
        incident.severity = payload.severity.value

    if status_change is not None:
        previous_status, target, reason = status_change

        detail = f"{previous_status} -> {target.value}"
        if reason:
            detail = f"{detail}: {reason}"
        timeline.append(_timeline_entry("status_changed", actor, detail))

        incident.status = target.value
        incident.resolved_at = _resolved_at_for(incident, target)

        binding = None
        if evidence_snapshot is not None:
            # Same transaction as the transition, deliberately: a decision whose
            # binding did not write is a decision with no record of what it
            # rested on, and that is worse than the transition failing.
            binding = decision_service.bind(
                db,
                incident,
                snapshot=evidence_snapshot,
                from_state=previous_status,
                to_state=target.value,
                reason=reason,
                decided_by=_lifecycle_actor(user),
                decided_by_role=user.role if user else None,
            )
            audit_service.record(
                db,
                action=AuditAction.DECISION_EVIDENCE_BOUND,
                user=user,
                target_type="decision",
                target_id=binding.decision_ref,
                details={
                    "incidentId": incident.incident_id,
                    "from": previous_status,
                    "to": target.value,
                    "manifestDigest": binding.manifest_digest,
                    "evidenceCount": binding.evidence_count,
                    # A decision taken while a provider was unreachable was
                    # taken on partial evidence. Recorded here so that fact
                    # survives alongside the decision itself.
                    "degradedProviders": [
                        entry.get("provider")
                        for entry in evidence_snapshot.degraded_providers
                    ],
                },
            )

        audit_service.record(
            db,
            action=AuditAction.INCIDENT_STATUS_CHANGED,
            user=user,
            target_type="incident",
            target_id=incident.incident_id,
            details={
                # Both ends, not just the destination. "status: Resolved" tells
                # a reader where an incident ended up and not what was undone to
                # get there, and the reopen edges are the ones worth auditing.
                "from": previous_status,
                "to": target.value,
                "reason": reason,
                "actorRole": user.role if user else "system",
                # The evidence this decision rested on, reachable from the audit
                # trail without having to find the binding first.
                "decisionRef": binding.decision_ref if binding else None,
                "evidenceManifestDigest": binding.manifest_digest if binding else None,
            },
        )

    if payload.analyst is not None and payload.analyst != incident.analyst:
        timeline.append(
            _timeline_entry("assigned", actor, f"{incident.analyst} -> {payload.analyst}")
        )
        incident.analyst = payload.analyst
        incident.assignee_id = payload.assignee_id if payload.assignee_id is not None else incident.assignee_id
        audit_service.record(
            db,
            action=AuditAction.INCIDENT_ASSIGNED,
            user=user,
            target_type="incident",
            target_id=incident.incident_id,
            details={"analyst": incident.analyst},
        )
        notification_service.notify_incident_assigned(db, incident, broadcast=broadcast)

    incident.timeline = timeline
    db.flush()

    if broadcast:
        _broadcast(incident, "incident.updated")
    return incident


def get_incident(db: Session, incident_id: str) -> Incident | None:
    return incident_repository.get_by_incident_id(db, incident_id)


def list_incidents(
    db: Session,
    *,
    search: str | None = None,
    severity: str | None = None,
    status: str | None = None,
    limit: int = 100,
    offset: int = 0,
) -> tuple[list[Incident], int]:
    return incident_repository.list_paginated(
        db, search=search, severity=severity, status=status, limit=limit, offset=offset
    )
