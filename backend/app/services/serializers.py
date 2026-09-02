"""Model -> schema conversion.

Kept in one place so the wire format is defined once. The API always exposes
the human readable identifier (``EVT-000042`` / ``INC-1024``) as ``id``; the
integer primary key never leaves the backend.
"""

from __future__ import annotations

from app.models.event import Event
from app.models.incident import Incident
from app.models.ioc import IOC
from app.models.ml import MLInference
from app.models.notification import Notification
from app.schemas.event import EventRead
from app.schemas.incident import IncidentEventSummary, IncidentRead
from app.schemas.ioc import IOCRead
from app.schemas.ml import MLInferenceRead
from app.schemas.notification import NotificationRead


def ioc_to_schema(ioc: IOC) -> IOCRead:
    return IOCRead(
        id=ioc.id,
        type=ioc.type,
        value=ioc.value,
        description=ioc.description,
        severity=ioc.severity,
        confidence=ioc.confidence,
        source=ioc.source,
        sighting_count=ioc.sighting_count,
        first_seen=ioc.first_seen,
        last_seen=ioc.last_seen,
    )


def inference_to_schema(event_id: str, inference: MLInference) -> MLInferenceRead:
    return MLInferenceRead(
        event_id=event_id,
        model=inference.model_name,
        model_version=inference.model_version,
        feature_schema_version=inference.feature_schema_version,
        anomaly_score=inference.anomaly_score,
        is_anomaly=inference.is_anomaly,
        threshold=inference.threshold,
        top_contributors=inference.top_contributors or [],
        latency_ms=inference.latency_ms,
        inferred_at=inference.inferred_at,
    )


def _latest_inference(event: Event) -> MLInference | None:
    """Most recent verdict for an event.

    An event can carry one row per model version; the newest is the one the
    running system currently stands behind.
    """
    rows = list(event.ml_inferences or [])
    if not rows:
        return None
    return max(rows, key=lambda row: row.inferred_at)


def event_to_schema(event: Event) -> EventRead:
    return EventRead(
        id=event.event_id,
        timestamp=event.timestamp,
        source=event.source,
        source_type=event.source_type,
        event_type=event.event_type,
        title=event.title,
        description=event.description,
        severity=event.severity,
        status=event.status,
        risk_score=event.risk_score,
        hostname=event.hostname,
        username=event.username,
        source_ip=event.source_ip,
        destination_ip=event.destination_ip,
        destination_port=event.destination_port,
        process=event.process,
        command_line=event.command_line,
        raw_log=event.raw_log,
        normalized_data=event.normalized_data or {},
        mitre_techniques=event.mitre_techniques or [],
        risk_level=event.risk_level or event.severity,
        risk_signals=event.risk_signals or [],
        detection_rules=event.detection_rules or [],
        detections=event.detections or [],
        ml_findings=[
            inference_to_schema(event.event_id, inference)
            for inference in sorted(
                event.ml_inferences or [], key=lambda row: row.inferred_at, reverse=True
            )
        ],
        is_synthetic=event.is_synthetic,
        incident_id=event.incident.incident_id if event.incident else None,
        iocs=[ioc_to_schema(ioc) for ioc in event.iocs],
        created_at=event.created_at,
    )


def event_to_summary(event: Event) -> IncidentEventSummary:
    latest = _latest_inference(event)
    return IncidentEventSummary(
        id=event.event_id,
        timestamp=event.timestamp,
        source=event.source,
        title=event.title,
        severity=event.severity,
        status=event.status,
        risk_score=event.risk_score,
        is_anomaly=bool(latest and latest.is_anomaly),
        anomaly_score=round(latest.anomaly_score, 4) if latest else None,
    )


def _incident_risk_signals(incident: Incident) -> list[dict]:
    """Aggregate the member events' signals, keeping the strongest per source.

    Summing every event's contribution would let one rule firing twenty times
    look like twenty findings. The incident view wants "what kinds of evidence
    are present and how strong is each", not a total.
    """
    if incident.risk_signals:
        return list(incident.risk_signals)

    strongest: dict[tuple[str, str], dict] = {}
    for event in incident.events or []:
        for signal in event.risk_signals or []:
            key = (signal.get("type", ""), signal.get("source", ""))
            current = strongest.get(key)
            if current is None or signal.get("contribution", 0) > current.get("contribution", 0):
                strongest[key] = signal
    return sorted(
        strongest.values(), key=lambda item: item.get("contribution", 0), reverse=True
    )


def incident_to_schema(incident: Incident, *, include_events: bool = True) -> IncidentRead:
    from app.ai import service as ai_service  # local import avoids a cycle
    from app.correlation import engine as correlation_engine

    events = list(incident.events or [])

    sequences: list[dict] = []
    seen: set[int] = set()
    for event in events:
        for sequence in event.sequences or []:
            if sequence.id not in seen:
                seen.add(sequence.id)
                sequences.append(correlation_engine.to_dict(sequence))

    anomaly_count = sum(
        1
        for event in events
        if any(inference.is_anomaly for inference in (event.ml_inferences or []))
    )

    return IncidentRead(
        id=incident.incident_id,
        title=incident.title,
        description=incident.description,
        severity=incident.severity,
        status=incident.status,
        source=incident.source,
        analyst=incident.analyst,
        assignee_id=incident.assignee_id,
        risk_score=incident.risk_score,
        mitre_techniques=incident.mitre_techniques or [],
        risk_signals=_incident_risk_signals(incident),
        sequences=sequences,
        ai_analyses=[
            ai_service.to_dict(analysis) for analysis in (incident.ai_analyses or [])
        ],
        ml_anomaly_count=anomaly_count,
        timeline=incident.timeline or [],
        event_ids=[event.event_id for event in events],
        events=[event_to_summary(event) for event in events] if include_events else [],
        iocs=[ioc_to_schema(ioc) for ioc in incident.iocs],
        event_count=len(events),
        created_at=incident.created_at,
        updated_at=incident.updated_at,
        resolved_at=incident.resolved_at,
    )


def notification_to_schema(notification: Notification, *, event_id: str | None = None,
                           incident_id: str | None = None) -> NotificationRead:
    return NotificationRead(
        id=notification.id,
        title=notification.title,
        description=notification.description,
        severity=notification.severity,
        category=notification.category,
        is_read=notification.is_read,
        event_id=event_id,
        incident_id=incident_id,
        created_at=notification.created_at,
    )
