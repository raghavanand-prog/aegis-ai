"""Correlation engine.

    new event -> candidate keys -> fetch window -> evaluate patterns
              -> open or extend a SecuritySequence -> rescore -> notify

Correlation runs on the enrichment path, not on the ingestion path. An event is
persisted, broadcast and visible to analysts before the correlator ever looks at
it; correlation then adds to the picture. That ordering is deliberate: a slow
correlation query must never be able to delay telemetry landing.

The engine never creates an incident by itself. It raises a sequence, scores it
with the same transparent strategy events use, and - above a configured risk
threshold - raises a notification so an analyst can decide. Automatic incident
creation from a statistical grouping is exactly the behaviour that buries a SOC.
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.correlation import mitre
from app.correlation.patterns import PATTERNS, CorrelationPattern, PatternVerdict
from app.models.enums import AuditAction, NotificationCategory, SequenceStatus
from app.models.event import Event
from app.models.sequence import SecuritySequence
from app.scoring import risk
from app.services import audit_service
from app.ws.manager import manager

logger = logging.getLogger(__name__)


def _iso(value) -> str | None:  # noqa: ANN001 - datetime | None
    """UTC-stamped ISO string, or None. See app.schemas.common.as_utc."""
    from app.schemas.common import as_utc

    stamped = as_utc(value)
    return stamped.isoformat() if stamped else None

#: Hard ceiling on how many events one window query may return. A pathological
#: key (a scanner hammering one host) must not turn correlation into a table
#: scan of the whole events table.
MAX_WINDOW_EVENTS = 200


def _window_start(now: datetime) -> datetime:
    return now - timedelta(minutes=settings.correlation_window_minutes)


def _utc(value: datetime) -> datetime:
    """Naive timestamps come back from SQLite; see schemas.common.as_utc."""
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


def _events_for_key(
    db: Session, pattern: CorrelationPattern, key: str, since: datetime
) -> list[Event]:
    """Recent events this pattern considers members of ``key``, oldest first.

    The entity query is the cheap first pass; the pattern's own ``key_for`` is
    then applied to every row. Without that second filter a "credential attack
    sequence" keyed on a user would absorb every unrelated event that user
    produced in the window - inflating the count, the score and the story it
    tells. A sequence must contain the events its pattern is actually about.
    """
    kind, _, value = key.partition(":")
    column = {
        "user": Event.username,
        "ip": Event.source_ip,
        "host": Event.hostname,
    }.get(kind)
    if column is None or not value:
        return []

    rows = db.scalars(
        select(Event)
        .where(column == value, Event.timestamp >= since)
        .order_by(Event.timestamp.asc())
        .limit(MAX_WINDOW_EVENTS)
    )

    members: list[Event] = []
    for event in rows:
        try:
            if pattern.key_for(event) == key:
                members.append(event)
        except Exception:  # noqa: BLE001, S112 - a broken pattern must not drop the batch
            continue
    return members


def _next_sequence_id(db: Session, sequence: SecuritySequence) -> None:
    """Assign the human readable identifier after the primary key exists."""
    if not sequence.sequence_id:
        sequence.sequence_id = f"SEQ-NEW-{uuid.uuid4().hex[:16]}"
    db.add(sequence)
    db.flush()
    if sequence.sequence_id.startswith("SEQ-NEW-"):
        sequence.sequence_id = f"SEQ-{sequence.id:06d}"
        db.flush()


def _existing_sequence(
    db: Session, pattern_id: str, key: str, since: datetime
) -> SecuritySequence | None:
    """An open sequence for this pattern and key that is still in the window."""
    return db.scalar(
        select(SecuritySequence)
        .where(
            SecuritySequence.pattern == pattern_id,
            SecuritySequence.correlation_key == key,
            SecuritySequence.status == SequenceStatus.OPEN.value,
            SecuritySequence.end_time >= since,
        )
        .order_by(SecuritySequence.end_time.desc())
    )


def _entities(events: list[Event]) -> dict[str, list[str]]:
    def unique(attribute: str) -> list[str]:
        return sorted(
            {
                str(getattr(event, attribute))
                for event in events
                if getattr(event, attribute, None)
            }
        )

    return {
        "hosts": unique("hostname"),
        "users": unique("username"),
        "sourceIps": unique("source_ip"),
        "destinationIps": unique("destination_ip"),
        "processes": unique("process"),
    }


def _score_sequence(
    events: list[Event], verdict: PatternVerdict, pattern: CorrelationPattern
) -> risk.RiskAssessment:
    """Score a sequence from its member events plus the correlation itself.

    The highest rule contribution among the members is used rather than the
    sum: twenty failed logins from one rule is one finding observed twenty
    times, not twenty independent findings, and summing would let repetition
    alone manufacture a critical.
    """
    signals: list[risk.Signal] = []
    total = 0

    best_rule: dict | None = None
    for event in events:
        for detection in event.detections or []:
            if best_rule is None or detection.get("riskContribution", 0) > best_rule.get(
                "riskContribution", 0
            ):
                best_rule = detection

    if best_rule:
        contribution = int(best_rule.get("riskContribution", 0))
        total += contribution
        signals.append(
            risk.Signal(
                type=risk.SignalType.RULE,
                source=str(best_rule.get("ruleId", "rule")),
                contribution=contribution,
                detail=str(best_rule.get("reason", "")),
                metadata={"strongestOf": len(events)},
            )
        )

    anomalies = [
        inference
        for event in events
        for inference in (event.ml_inferences or [])
        if inference.is_anomaly
    ]
    if anomalies:
        strongest = max(anomalies, key=lambda item: item.anomaly_score)
        contribution = risk.ml_contribution(strongest.anomaly_score)
        if contribution:
            total += contribution
            signals.append(
                risk.Signal(
                    type=risk.SignalType.ML,
                    source=strongest.model_name,
                    contribution=contribution,
                    detail=(
                        f"{len(anomalies)} of {len(events)} events in this sequence were "
                        "flagged as statistically unusual"
                    ),
                    metadata={
                        "modelVersion": strongest.model_version,
                        "anomalyScore": round(strongest.anomaly_score, 4),
                        "anomalousEvents": len(anomalies),
                        "scoreKind": "anomaly_score",
                    },
                )
            )

    correlation_contribution = int(
        round(risk.CORRELATION_MAX_CONTRIBUTION * min(verdict.confidence, 1.0))
    )
    total += correlation_contribution
    signals.append(
        risk.Signal(
            type=risk.SignalType.CORRELATION,
            source=pattern.id,
            contribution=correlation_contribution,
            detail=verdict.description,
            metadata={
                "pattern": pattern.name,
                "confidence": round(verdict.confidence, 3),
                "eventCount": len(events),
            },
        )
    )

    score = max(0, min(total, 100))
    return risk.RiskAssessment(
        risk_score=score,
        risk_level=risk.risk_level(score, verdict.severity),
        signals=signals,
    )


def correlate_event(db: Session, event: Event, *, broadcast: bool = True) -> list[SecuritySequence]:
    """Run every pattern against one newly persisted event.

    Returns the sequences that were opened or extended. Never raises: a
    correlation failure must not affect the event that triggered it.
    """
    if not settings.correlation_enabled:
        return []

    now = datetime.now(timezone.utc)
    since = _window_start(now)
    touched: list[SecuritySequence] = []

    for pattern in PATTERNS:
        try:
            key = pattern.key_for(event)
        except Exception:  # noqa: BLE001, S112 - a broken pattern must not stop the rest
            continue
        if not key:
            continue

        events = _events_for_key(db, pattern, key, since)
        if len(events) < max(pattern.min_events, settings.correlation_min_events):
            continue

        try:
            verdict = pattern.evaluate(events)
        except Exception:  # noqa: BLE001, S112
            logger.exception("Correlation pattern %s failed", pattern.id)
            continue
        if not verdict.matched:
            continue

        sequence = _upsert_sequence(db, pattern, key, events, verdict, broadcast=broadcast)
        if sequence is not None:
            touched.append(sequence)

    return touched


def _upsert_sequence(
    db: Session,
    pattern: CorrelationPattern,
    key: str,
    events: list[Event],
    verdict: PatternVerdict,
    *,
    broadcast: bool,
) -> SecuritySequence | None:
    now = datetime.now(timezone.utc)
    assessment = _score_sequence(events, verdict, pattern)

    techniques = mitre.from_events(events)
    for value in pattern.inferred_techniques:
        techniques.append(
            mitre.technique(
                value,
                mitre.INFERRED,
                pattern.id,
                f"Inferred from the shape of the sequence by {pattern.name}",
            )
        )
    techniques = mitre.merge(techniques)

    existing = _existing_sequence(db, pattern.id, key, _window_start(now))
    is_new = existing is None

    sequence = existing or SecuritySequence(
        sequence_id="",
        pattern=pattern.id,
        correlation_key=key,
        start_time=_utc(events[0].timestamp),
    )

    sequence.title = verdict.title
    sequence.description = verdict.description
    sequence.severity = assessment.risk_level
    sequence.risk_score = assessment.risk_score
    sequence.confidence = round(min(verdict.confidence, 1.0), 4)
    sequence.start_time = _utc(events[0].timestamp)
    sequence.end_time = _utc(events[-1].timestamp)
    sequence.event_count = len(events)
    sequence.techniques = techniques
    sequence.entities = _entities(events)
    sequence.rationale = list(verdict.rationale)
    sequence.risk_signals = assessment.signals_as_dicts()

    if is_new:
        _next_sequence_id(db, sequence)

    existing_ids = {member.id for member in sequence.events}
    for member in events:
        if member.id not in existing_ids:
            sequence.events.append(member)
    db.flush()

    if is_new:
        audit_service.record(
            db,
            action=AuditAction.SEQUENCE_CREATED,
            target_type="sequence",
            target_id=sequence.sequence_id,
            details={
                "pattern": pattern.id,
                "correlationKey": key,
                "eventCount": sequence.event_count,
                "riskScore": sequence.risk_score,
            },
        )
        logger.info(
            "Correlated sequence opened",
            extra={
                "sequence": sequence.sequence_id,
                "pattern": pattern.id,
                "operation": "correlation.open",
            },
        )

    _maybe_notify(db, sequence, is_new=is_new, broadcast=broadcast)

    if broadcast:
        manager.broadcast_threadsafe(
            "sequence.created" if is_new else "sequence.updated", to_dict(sequence)
        )
    return sequence


def _maybe_notify(
    db: Session, sequence: SecuritySequence, *, is_new: bool, broadcast: bool
) -> None:
    """Raise a notification for a genuinely notable sequence, once."""
    if not is_new or sequence.risk_score < settings.correlation_incident_risk:
        return

    # Imported here rather than at module scope: notification_service imports
    # the serializers, which import the models, which import this package.
    from app.services import notification_service

    notification_service.create(
        db,
        title=f"Correlated activity: {sequence.title}",
        description=(
            f"{sequence.sequence_id} groups {sequence.event_count} related events "
            f"({sequence.pattern}, risk {sequence.risk_score}/100). Review and promote "
            "if this is an incident."
        ),
        severity=notification_service.to_notification_severity(sequence.severity),
        category=NotificationCategory.INCIDENT,
        broadcast=broadcast,
    )


def to_dict(sequence: SecuritySequence, *, include_events: bool = True) -> dict:
    """Serializable view of a sequence, camelCase for the frontend."""
    return {
        "id": sequence.sequence_id,
        "title": sequence.title,
        "description": sequence.description,
        "pattern": sequence.pattern,
        "correlationKey": sequence.correlation_key,
        "severity": sequence.severity,
        "status": sequence.status,
        "riskScore": sequence.risk_score,
        "confidence": sequence.confidence,
        "startTime": _utc(sequence.start_time).isoformat(),
        "endTime": _utc(sequence.end_time).isoformat(),
        "eventCount": sequence.event_count,
        "techniques": sequence.techniques or [],
        "entities": sequence.entities or {},
        "rationale": sequence.rationale or [],
        "riskSignals": sequence.risk_signals or [],
        "incidentId": sequence.incident.incident_id if sequence.incident else None,
        "eventIds": (
            [event.event_id for event in sequence.events] if include_events else []
        ),
        "createdAt": _iso(sequence.created_at),
        "updatedAt": _iso(sequence.updated_at),
    }


def correlation_confidence_for(event: Event) -> tuple[float, str | None]:
    """Strongest correlation currently attached to an event.

    Used when an event is rescored after correlation runs, so the correlation
    signal appears in the event's own breakdown rather than only on the sequence.
    """
    best = 0.0
    source: str | None = None
    for sequence in event.sequences or []:
        if sequence.confidence > best:
            best = sequence.confidence
            source = sequence.sequence_id
    return best, source


def status() -> dict:
    return {
        "enabled": settings.correlation_enabled,
        "windowMinutes": settings.correlation_window_minutes,
        "minEvents": settings.correlation_min_events,
        "notifyAboveRisk": settings.correlation_incident_risk,
        "maxWindowEvents": MAX_WINDOW_EVENTS,
        "patterns": [pattern.id for pattern in PATTERNS],
    }


__all__ = [
    "MAX_WINDOW_EVENTS",
    "correlate_event",
    "correlation_confidence_for",
    "status",
    "to_dict",
]
