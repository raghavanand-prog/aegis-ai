"""Analytics aggregation schemas.

Every number the Analytics page renders comes from these aggregates; nothing
on that page is fabricated once the backend is reachable.
"""

from __future__ import annotations

from pydantic import Field

from app.schemas.common import CamelModel


class CountByKey(CamelModel):
    key: str
    count: int


class TimeBucket(CamelModel):
    bucket: str
    count: int
    critical: int = 0
    high: int = 0


class AnalystWorkload(CamelModel):
    analyst: str
    open: int
    investigating: int
    contained: int
    resolved: int
    total: int


class MLAnalytics(CamelModel):
    """Machine learning aggregates, computed from stored inference rows.

    Every field here counts real rows. When no model has ever run, the counts
    are zero and ``modelAvailable`` is false - the UI must render that as
    "no model" rather than as "no anomalies found".
    """

    model_available: bool
    model_name: str | None = None
    model_version: str | None = None
    feature_schema_version: str | None = None
    reason: str | None = Field(
        default=None, description="Why the model is unavailable, when it is."
    )
    threshold: float | None = None

    total_scored_events: int = 0
    anomalies_detected: int = 0
    anomaly_rate: float | None = Field(
        default=None,
        description="anomalies / scored events. Null when nothing has been scored.",
    )
    ml_assisted_incidents: int = Field(
        default=0,
        description="Incidents containing at least one event the model flagged.",
    )
    anomalies_correlated: int = Field(
        default=0, description="Anomalous events that ended up in a correlated sequence."
    )
    anomalies_by_source: list[CountByKey] = Field(default_factory=list)
    anomalies_by_severity: list[CountByKey] = Field(default_factory=list)
    anomalies_over_time: list[TimeBucket] = Field(default_factory=list)
    score_distribution: list[CountByKey] = Field(default_factory=list)
    #: Rule-only / ML-only / both, so the two signals can be compared honestly.
    detection_overlap: dict[str, int] = Field(default_factory=dict)


class CorrelationAnalytics(CamelModel):
    enabled: bool
    total_sequences: int = 0
    open_sequences: int = 0
    promoted_sequences: int = 0
    sequences_by_pattern: list[CountByKey] = Field(default_factory=list)
    mean_confidence: float | None = None


class ThreatIntelAnalytics(CamelModel):
    enabled: bool
    provider: str
    configured: bool
    total_lookups: int = 0
    malicious: int = 0
    suspicious: int = 0
    harmless: int = 0
    unknown: int = 0
    failed_lookups: int = Field(
        default=0,
        description="Lookups that produced no verdict. Not the same as 'clean'.",
    )


class AnalyticsSummary(CamelModel):
    # Headline counters
    total_events: int
    critical_events: int
    high_events: int
    new_events: int
    open_incidents: int
    critical_incidents: int
    resolved_incidents: int
    total_incidents: int
    total_iocs: int
    mean_risk_score: float

    # Distributions
    events_by_severity: list[CountByKey] = Field(default_factory=list)
    incidents_by_severity: list[CountByKey] = Field(default_factory=list)
    events_by_source: list[CountByKey] = Field(default_factory=list)
    events_by_source_type: list[CountByKey] = Field(default_factory=list)
    mitre_coverage: list[CountByKey] = Field(default_factory=list)

    # Time series (hourly buckets, oldest first)
    events_over_time: list[TimeBucket] = Field(default_factory=list)
    incidents_over_time: list[TimeBucket] = Field(default_factory=list)

    # Analyst view
    analyst_workload: list[AnalystWorkload] = Field(default_factory=list)

    # V3 - hybrid detection. Present but empty/unavailable when the relevant
    # subsystem is off, never omitted, so the UI always has something to explain.
    ml: MLAnalytics | None = None
    correlation: CorrelationAnalytics | None = None
    threat_intel: ThreatIntelAnalytics | None = None

    # Context
    window_hours: int
    generated_at: str
