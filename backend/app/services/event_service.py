"""Event ingestion and queries.

Pipeline for a single record (V3):

    normalized candidate
        -> deterministic rules
        -> ML anomaly inference          (in-process, sub-millisecond)
        -> hybrid risk scoring           (explainable, signal by signal)
        -> persist event + inference row
        -> IOC extraction
        -> notification
        -> WebSocket broadcast
        -> queue background enrichment   (threat intel + correlation)

Everything up to the broadcast is the fast path and runs synchronously. Threat
intelligence and correlation happen afterwards on a worker thread, and the event
is rescored and rebroadcast if they find anything - see
``app/services/enrichment_service.py``.

Each stage after the rules is optional. With ML disabled, threat intelligence
unconfigured and correlation off, this is exactly the V2 pipeline, and the SOC
works.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

from sqlalchemy.orm import Session

from app.detection import rules as detection
from app.ml.features.extractor import _is_internal  # single source of truth for "internal"
from app.ml.inference import engine as ml_engine
from app.ml.schemas import InferenceResult
from app.models.enums import EventStatus, Severity
from app.models.event import Event
from app.models.ml import MLInference
from app.repositories.event_repository import event_repository
from app.repositories.ioc_repository import ioc_repository
from app.schemas.event import EventIngest
from app.scoring import risk
from app.services import notification_service
from app.services.serializers import event_to_schema
from app.ws.manager import manager

logger = logging.getLogger(__name__)

#: Hours considered outside the working day, used as a contextual risk nudge.
OFF_HOURS = set(range(0, 7)) | set(range(19, 24))


def _attach_iocs(db: Session, event: Event, indicators: list[tuple[str, str]]) -> None:
    for ioc_type, value in indicators:
        if not value:
            continue
        ioc = ioc_repository.upsert(
            db,
            ioc_type=ioc_type,
            value=value,
            severity=event.severity,
            source=event.source,
            description=f"First observed in {event.event_id or 'a new event'}: {event.title}",
            confidence=min(50 + event.risk_score // 2, 95),
        )
        if ioc not in event.iocs:
            event.iocs.append(ioc)


def _risk_context(candidate: dict[str, Any]) -> dict[str, bool]:
    """Cheap contextual flags the scorer can use, derived from the event itself."""
    stamp = candidate.get("timestamp")
    if not isinstance(stamp, datetime):
        stamp = datetime.now(timezone.utc)
    source_ip = candidate.get("source_ip")
    return {
        "off_hours": stamp.hour in OFF_HOURS,
        "external_source": bool(source_ip) and not _is_internal(source_ip),
    }


def _record_inference(db: Session, event: Event, inference: InferenceResult) -> MLInference:
    """Persist one model verdict against an event."""
    row = MLInference(
        event_id=event.id,
        model_name=inference.model_name,
        model_version=inference.model_version,
        feature_schema_version=inference.feature_schema_version,
        anomaly_score=inference.anomaly_score,
        is_anomaly=inference.is_anomaly,
        threshold=inference.threshold,
        # The full vector is kept: it is what makes a stored score reproducible
        # and is what a V4 experiment reads.
        features={name: round(value, 6) for name, value in inference.features.items()},
        top_contributors=[c.to_dict() for c in inference.top_contributors],
        latency_ms=inference.latency_ms,
    )
    db.add(row)
    db.flush()
    return row


def ingest_candidate(
    db: Session, candidate: dict[str, Any], *, broadcast: bool = True, enrich: bool = True
) -> Event:
    """Persist one normalized candidate after running detection over it."""
    result = detection.evaluate(
        candidate, base_severity=candidate.get("severity", Severity.LOW.value)
    )

    # ML scores the candidate before it is persisted, so the event's risk is
    # complete the first time anyone sees it. Returns None whenever the model
    # is unavailable, and the pipeline carries on unchanged.
    inference = ml_engine.engine.score(candidate)

    assessment = risk.score_event(
        detection_result=result,
        inference=inference,
        context=_risk_context(candidate),
        base_severity=result.severity,
    )

    event = Event(
        timestamp=candidate.get("timestamp") or datetime.now(timezone.utc),
        source=candidate["source"],
        source_type=candidate["source_type"],
        event_type=candidate.get("event_type", "unknown"),
        title=candidate.get("title", "Security event"),
        description=candidate.get("description"),
        severity=result.severity,
        status=candidate.get("status", EventStatus.NEW.value),
        risk_score=assessment.risk_score,
        risk_level=assessment.risk_level,
        risk_signals=assessment.signals_as_dicts(),
        hostname=candidate.get("hostname"),
        username=candidate.get("username"),
        source_ip=candidate.get("source_ip"),
        destination_ip=candidate.get("destination_ip"),
        destination_port=candidate.get("destination_port"),
        process=candidate.get("process"),
        command_line=candidate.get("command_line"),
        raw_log=candidate.get("raw_log"),
        normalized_data=candidate.get("normalized_data") or {},
        mitre_techniques=result.mitre_techniques,
        detection_rules=result.matched_rules,
        detections=result.detections_as_dicts(),
        is_synthetic=bool(candidate.get("is_synthetic", True)),
    )

    event_repository.create(db, event)
    if inference is not None:
        _record_inference(db, event, inference)
    _attach_iocs(db, event, list(candidate.get("iocs") or []))
    db.flush()

    notification_service.notify_for_event(db, event, broadcast=broadcast)

    if broadcast:
        manager.broadcast_threadsafe(
            "event.created", event_to_schema(event).model_dump(by_alias=True, mode="json")
        )

    if enrich:
        # Deferred: threat intelligence and correlation happen after the event
        # is already durable and on screen.
        from app.services.enrichment_service import worker

        worker.submit(event.id)

    return event


def rescore_event(
    db: Session,
    event: Event,
    *,
    threat_intel: list[Any] | None = None,
    broadcast: bool = True,
) -> Event:
    """Recompute an event's risk after background enrichment found something.

    Re-runs the same scoring strategy with the newly available signals. The
    deterministic rule verdict is not re-evaluated - the rules already ran on
    the original candidate, and their conclusion does not change because a
    reputation service answered.
    """
    from app.correlation import engine as correlation_engine

    detections = [
        detection.Detection(
            rule_id=item.get("ruleId", ""),
            rule_version=item.get("ruleVersion", ""),
            rule_name=item.get("ruleName", ""),
            reason=item.get("reason", ""),
            severity=item.get("severity", Severity.LOW.value),
            risk_contribution=int(item.get("riskContribution", 0) or 0),
            mitre_techniques=list(item.get("mitreTechniques") or []),
            matched_at=item.get("matchedAt", ""),
        )
        for item in (event.detections or [])
    ]
    replayed = detection.DetectionResult(
        severity=event.severity,
        risk_score=event.risk_score,
        mitre_techniques=list(event.mitre_techniques or []),
        matched_rules=list(event.detection_rules or []),
        detections=detections,
    )

    inference = None
    rows = sorted(
        event.ml_inferences or [], key=lambda row: row.inferred_at, reverse=True
    )
    if rows:
        latest = rows[0]
        inference = InferenceResult(
            model_name=latest.model_name,
            model_version=latest.model_version,
            feature_schema_version=latest.feature_schema_version,
            anomaly_score=latest.anomaly_score,
            is_anomaly=latest.is_anomaly,
            threshold=latest.threshold,
            features=latest.features or {},
            top_contributors=[],
        )

    confidence, source = correlation_engine.correlation_confidence_for(event)

    assessment = risk.score_event(
        detection_result=replayed,
        inference=inference,
        threat_intel=threat_intel or [],
        correlation_confidence=confidence,
        correlation_source=source,
        context={
            "off_hours": event.timestamp.hour in OFF_HOURS,
            "external_source": bool(event.source_ip) and not _is_internal(event.source_ip),
        },
        base_severity=event.severity,
    )

    changed = (
        assessment.risk_score != event.risk_score
        or assessment.risk_level != event.risk_level
    )
    event.risk_score = assessment.risk_score
    event.risk_level = assessment.risk_level
    event.risk_signals = assessment.signals_as_dicts()
    db.flush()

    if broadcast and changed:
        manager.broadcast_threadsafe(
            "event.updated", event_to_schema(event).model_dump(by_alias=True, mode="json")
        )
    return event


def ingest_payload(db: Session, payload: EventIngest, *, broadcast: bool = True) -> Event:
    """Ingest an event submitted through ``POST /events`` by an external collector."""
    candidate: dict[str, Any] = payload.model_dump()
    candidate["source_type"] = payload.source_type.value
    candidate["severity"] = payload.severity.value
    candidate["status"] = payload.status.value
    candidate["iocs"] = [("ip", value) for value in payload.iocs]
    return ingest_candidate(db, candidate, broadcast=broadcast)


def get_event(db: Session, event_id: str) -> Event | None:
    return event_repository.get_by_event_id(db, event_id)


def list_events(
    db: Session,
    *,
    search: str | None = None,
    severity: str | None = None,
    status: str | None = None,
    source: str | None = None,
    source_type: str | None = None,
    is_anomaly: bool | None = None,
    limit: int = 100,
    offset: int = 0,
) -> tuple[list[Event], int]:
    return event_repository.list_paginated(
        db,
        search=search,
        severity=severity,
        status=status,
        source=source,
        source_type=source_type,
        is_anomaly=is_anomaly,
        limit=limit,
        offset=offset,
    )


def update_status(db: Session, event: Event, status: EventStatus, *, broadcast: bool = True) -> Event:
    event.status = status.value
    db.flush()
    if broadcast:
        manager.broadcast_threadsafe(
            "event.updated", event_to_schema(event).model_dump(by_alias=True, mode="json")
        )
    return event
