"""Analytics aggregation.

Everything the Analytics page shows is computed here from persisted rows. No
value on that page is fabricated once the backend is reachable.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.ml.inference import engine as ml_engine
from app.models.enums import EventStatus, IncidentStatus, Severity
from app.models.event import Event
from app.models.incident import Incident
from app.models.ml import MLInference
from app.models.sequence import SecuritySequence, sequence_events
from app.models.threat_intel import ThreatIntelResult
from app.repositories.event_repository import event_repository
from app.repositories.incident_repository import incident_repository
from app.repositories.ioc_repository import ioc_repository
from app.schemas.analytics import (
    AnalystWorkload,
    AnalyticsSummary,
    CorrelationAnalytics,
    CountByKey,
    MLAnalytics,
    ThreatIntelAnalytics,
    TimeBucket,
)
from app.threatintel import service as threat_intel_service

SEVERITIES = [s.value for s in Severity]


def _ensure_utc(value: datetime) -> datetime:
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


def _bucket_series(
    rows, since: datetime, window_hours: int
) -> list[TimeBucket]:
    """Group (timestamp, severity) rows into hourly buckets, oldest first."""
    bucket_count = max(1, min(window_hours, 168))
    start = since.replace(minute=0, second=0, microsecond=0)

    totals: dict[str, int] = {}
    critical: dict[str, int] = {}
    high: dict[str, int] = {}

    labels: list[str] = []
    for offset in range(bucket_count + 1):
        label = (start + timedelta(hours=offset)).strftime("%Y-%m-%dT%H:00")
        labels.append(label)
        totals[label] = 0
        critical[label] = 0
        high[label] = 0

    for timestamp, severity in rows:
        stamp = _ensure_utc(timestamp).replace(minute=0, second=0, microsecond=0)
        label = stamp.strftime("%Y-%m-%dT%H:00")
        if label not in totals:
            continue
        totals[label] += 1
        if severity == Severity.CRITICAL.value:
            critical[label] += 1
        elif severity == Severity.HIGH.value:
            high[label] += 1

    return [
        TimeBucket(bucket=label, count=totals[label], critical=critical[label], high=high[label])
        for label in labels
    ]


def _ml_analytics(db: Session, since: datetime, window_hours: int) -> MLAnalytics:
    """ML aggregates, every one of them counted from stored inference rows."""
    state = ml_engine.engine.status()
    counts = event_repository.ml_counts(db)
    scored = counts["scored"]
    anomalous = counts["anomalous"]

    # Rule-only / ML-only / both. This is the comparison that says whether the
    # anomaly model is contributing anything the rules were not already
    # catching, which is the whole reason for adding it.
    anomaly_events = list(
        db.execute(
            select(Event.id, Event.detection_rules)
            .join(MLInference, MLInference.event_id == Event.id)
            .where(MLInference.is_anomaly.is_(True))
        )
    )
    ml_only = sum(1 for _, detected in anomaly_events if not detected)
    both = len(anomaly_events) - ml_only

    return MLAnalytics(
        model_available=state["available"],
        model_name=state["modelName"],
        model_version=state["modelVersion"],
        feature_schema_version=state["featureSchemaVersion"],
        reason=state["reason"],
        threshold=state["threshold"],
        total_scored_events=scored,
        anomalies_detected=anomalous,
        anomaly_rate=round(anomalous / scored, 4) if scored else None,
        ml_assisted_incidents=event_repository.ml_assisted_incident_count(db),
        anomalies_correlated=int(
            db.scalar(
                select(func.count(func.distinct(Event.id)))
                .join(MLInference, MLInference.event_id == Event.id)
                .join(sequence_events, sequence_events.c.event_id == Event.id)
                .where(MLInference.is_anomaly.is_(True))
            )
            or 0
        ),
        anomalies_by_source=[
            CountByKey(key=str(row[0]), count=int(row[1]))
            for row in event_repository.anomaly_group_count(db, Event.source)
        ],
        anomalies_by_severity=[
            CountByKey(key=str(row[0]), count=int(row[1]))
            for row in event_repository.anomaly_group_count(db, Event.severity)
        ],
        anomalies_over_time=_bucket_series(
            event_repository.anomaly_timeline_rows(db, since), since, window_hours
        ),
        score_distribution=[
            CountByKey(key=label, count=count)
            for label, count in event_repository.anomaly_score_buckets(db)
        ],
        detection_overlap={
            "mlOnly": ml_only,
            "ruleAndMl": both,
            "ruleOnly": max(_rule_hit_count(db) - both, 0),
        },
    )


def _rule_hit_count(db: Session) -> int:
    """Events with at least one rule match.

    Counted in Python over the id/rules pairs rather than with a JSON predicate,
    because `detection_rules` is JSONB on PostgreSQL and plain JSON on the SQLite
    the tests use, and a dialect-specific query here would mean the tests stop
    exercising this path.
    """
    rows = db.execute(select(Event.detection_rules))
    return sum(1 for (rules,) in rows if rules)


def _correlation_analytics(db: Session) -> CorrelationAnalytics:
    rows = list(
        db.execute(
            select(SecuritySequence.pattern, func.count())
            .group_by(SecuritySequence.pattern)
            .order_by(func.count().desc())
        )
    )
    total = int(db.scalar(select(func.count()).select_from(SecuritySequence)) or 0)
    mean_confidence = db.scalar(select(func.avg(SecuritySequence.confidence)))
    return CorrelationAnalytics(
        enabled=settings.correlation_enabled,
        total_sequences=total,
        open_sequences=int(
            db.scalar(
                select(func.count())
                .select_from(SecuritySequence)
                .where(SecuritySequence.status == "Open")
            )
            or 0
        ),
        promoted_sequences=int(
            db.scalar(
                select(func.count())
                .select_from(SecuritySequence)
                .where(SecuritySequence.status == "Promoted")
            )
            or 0
        ),
        sequences_by_pattern=[
            CountByKey(key=str(row[0]), count=int(row[1])) for row in rows
        ],
        mean_confidence=round(float(mean_confidence), 3) if mean_confidence else None,
    )


def _threat_intel_analytics(db: Session) -> ThreatIntelAnalytics:
    state = threat_intel_service.status()
    counts = {
        str(row[0]): int(row[1])
        for row in db.execute(
            select(ThreatIntelResult.reputation, func.count()).group_by(
                ThreatIntelResult.reputation
            )
        )
    }
    total = int(db.scalar(select(func.count()).select_from(ThreatIntelResult)) or 0)
    failed = int(
        db.scalar(
            select(func.count())
            .select_from(ThreatIntelResult)
            .where(ThreatIntelResult.status != "ok")
        )
        or 0
    )
    return ThreatIntelAnalytics(
        enabled=state["enabled"],
        provider=state["provider"],
        configured=state["configured"],
        total_lookups=total,
        malicious=counts.get("malicious", 0),
        suspicious=counts.get("suspicious", 0),
        harmless=counts.get("harmless", 0),
        unknown=counts.get("unknown", 0),
        failed_lookups=failed,
    )


def build_summary(db: Session, *, window_hours: int = 24) -> AnalyticsSummary:
    now = datetime.now(timezone.utc)
    since = now - timedelta(hours=window_hours)

    # --- Headline counters (all-time, matching what the SOC lists show) -----
    total_events = event_repository.count_since(db)
    critical_events = event_repository.count_since(db, severity=Severity.CRITICAL.value)
    high_events = event_repository.count_since(db, severity=Severity.HIGH.value)
    new_events = event_repository.count_since(db, status=EventStatus.NEW.value)

    total_incidents = incident_repository.count(db)
    open_incidents = incident_repository.count(db, status=IncidentStatus.OPEN.value)
    critical_incidents = incident_repository.count(db, severity=Severity.CRITICAL.value)
    resolved_incidents = incident_repository.count(db, status=IncidentStatus.RESOLVED.value)

    # --- Distributions -----------------------------------------------------
    events_by_severity_raw = {
        row[0]: row[1] for row in event_repository.group_count(db, Event.severity)
    }
    incidents_by_severity_raw = {
        row[0]: row[1] for row in incident_repository.group_count(db, Incident.severity)
    }

    events_by_severity = [
        CountByKey(key=severity, count=int(events_by_severity_raw.get(severity, 0)))
        for severity in SEVERITIES
    ]
    incidents_by_severity = [
        CountByKey(key=severity, count=int(incidents_by_severity_raw.get(severity, 0)))
        for severity in SEVERITIES
    ]
    events_by_source = [
        CountByKey(key=str(row[0]), count=int(row[1]))
        for row in event_repository.group_count(db, Event.source, limit=10)
    ]
    events_by_source_type = [
        CountByKey(key=str(row[0]), count=int(row[1]))
        for row in event_repository.group_count(db, Event.source_type, limit=10)
    ]

    # --- MITRE coverage ----------------------------------------------------
    technique_counter: Counter[str] = Counter()
    for (techniques,) in event_repository.mitre_rows(db, since):
        for technique in techniques or []:
            technique_counter[str(technique)] += 1
    mitre_coverage = [
        CountByKey(key=technique, count=count)
        for technique, count in technique_counter.most_common(12)
    ]

    # --- Time series -------------------------------------------------------
    events_over_time = _bucket_series(
        event_repository.timeline_rows(db, since), since, window_hours
    )
    incidents_over_time = _bucket_series(
        incident_repository.timeline_rows(db, since), since, window_hours
    )

    # --- Analyst workload --------------------------------------------------
    workload: dict[str, dict[str, int]] = defaultdict(
        lambda: {"open": 0, "investigating": 0, "contained": 0, "resolved": 0, "total": 0}
    )
    for analyst, status, count in incident_repository.workload_rows(db):
        entry = workload[str(analyst or "Unassigned")]
        key = str(status).lower()
        if key in entry:
            entry[key] += int(count)
        entry["total"] += int(count)

    analyst_workload = [
        AnalystWorkload(
            analyst=analyst,
            open=values["open"],
            investigating=values["investigating"],
            contained=values["contained"],
            resolved=values["resolved"],
            total=values["total"],
        )
        for analyst, values in sorted(workload.items(), key=lambda item: -item[1]["total"])
    ]

    return AnalyticsSummary(
        total_events=total_events,
        critical_events=critical_events,
        high_events=high_events,
        new_events=new_events,
        open_incidents=open_incidents,
        critical_incidents=critical_incidents,
        resolved_incidents=resolved_incidents,
        total_incidents=total_incidents,
        total_iocs=ioc_repository.count(db),
        mean_risk_score=round(event_repository.mean_risk_score(db), 2),
        events_by_severity=events_by_severity,
        incidents_by_severity=incidents_by_severity,
        events_by_source=events_by_source,
        events_by_source_type=events_by_source_type,
        mitre_coverage=mitre_coverage,
        events_over_time=events_over_time,
        incidents_over_time=incidents_over_time,
        analyst_workload=analyst_workload,
        ml=_ml_analytics(db, since, window_hours),
        correlation=_correlation_analytics(db),
        threat_intel=_threat_intel_analytics(db),
        window_hours=window_hours,
        generated_at=now.isoformat(),
    )
