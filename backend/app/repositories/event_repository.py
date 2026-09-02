"""Event queries."""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import Row, func, or_, select
from sqlalchemy.orm import Session

from app.models.event import Event
from app.models.ml import MLInference
from app.repositories.base import BaseRepository


class EventRepository(BaseRepository[Event]):
    def __init__(self) -> None:
        super().__init__(Event)

    # --- Writes ------------------------------------------------------------
    def create(self, db: Session, event: Event) -> Event:
        """Persist an event and assign its human readable identifier.

        ``event_id`` is NOT NULL and unique, but the sequential number depends
        on the primary key, which only exists after the INSERT. A collision
        free placeholder is written first and replaced in the same
        transaction, so no two writers can ever claim the same number. A
        database sequence would remove the extra UPDATE; that is a V2 change.
        """
        if not event.event_id:
            event.event_id = f"EVT-NEW-{uuid.uuid4().hex[:16]}"
        db.add(event)
        db.flush()  # populates the integer primary key
        if event.event_id.startswith("EVT-NEW-"):
            event.event_id = f"EVT-{event.id:06d}"
            db.flush()
        return event

    # --- Reads -------------------------------------------------------------
    def get_by_event_id(self, db: Session, event_id: str) -> Event | None:
        return db.scalar(select(Event).where(Event.event_id == event_id))

    def get_many_by_event_ids(self, db: Session, event_ids: list[str]) -> list[Event]:
        if not event_ids:
            return []
        return list(db.scalars(select(Event).where(Event.event_id.in_(event_ids))))

    def list_paginated(
        self,
        db: Session,
        *,
        search: str | None = None,
        severity: str | None = None,
        status: str | None = None,
        source: str | None = None,
        source_type: str | None = None,
        is_anomaly: bool | None = None,
        incident_id: int | None = None,
        since: datetime | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> tuple[list[Event], int]:
        stmt = select(Event)
        count_stmt = select(func.count()).select_from(Event)

        def apply(condition):
            nonlocal stmt, count_stmt
            stmt = stmt.where(condition)
            count_stmt = count_stmt.where(condition)

        if search:
            pattern = f"%{search.lower()}%"
            apply(
                or_(
                    func.lower(Event.title).like(pattern),
                    func.lower(Event.source).like(pattern),
                    func.lower(Event.event_type).like(pattern),
                    func.lower(func.coalesce(Event.hostname, "")).like(pattern),
                    func.lower(func.coalesce(Event.username, "")).like(pattern),
                    func.lower(func.coalesce(Event.source_ip, "")).like(pattern),
                    func.lower(Event.event_id).like(pattern),
                )
            )
        if severity:
            apply(Event.severity == severity)
        if status:
            apply(Event.status == status)
        if source:
            apply(Event.source == source)
        if source_type:
            apply(Event.source_type == source_type)
        if is_anomaly is not None:
            # EXISTS rather than a join: an event can carry several inference
            # rows (one per model version) and a join would duplicate it.
            condition = Event.ml_inferences.any(MLInference.is_anomaly.is_(True))
            apply(condition if is_anomaly else ~condition)
        if incident_id is not None:
            apply(Event.incident_id == incident_id)
        if since is not None:
            apply(Event.timestamp >= since)

        total = int(db.scalar(count_stmt) or 0)
        items = list(
            db.scalars(
                stmt.order_by(Event.timestamp.desc(), Event.id.desc()).limit(limit).offset(offset)
            )
        )
        return items, total

    # --- Aggregates --------------------------------------------------------
    def count_since(self, db: Session, since: datetime | None = None, **filters) -> int:
        stmt = select(func.count()).select_from(Event)
        if since is not None:
            stmt = stmt.where(Event.timestamp >= since)
        for column, value in filters.items():
            stmt = stmt.where(getattr(Event, column) == value)
        return int(db.scalar(stmt) or 0)

    def group_count(
        self, db: Session, column, since: datetime | None = None, limit: int | None = None
    ) -> list[Row]:
        stmt = select(column, func.count().label("count")).group_by(column)
        if since is not None:
            stmt = stmt.where(Event.timestamp >= since)
        stmt = stmt.order_by(func.count().desc())
        if limit:
            stmt = stmt.limit(limit)
        return list(db.execute(stmt))

    def mean_risk_score(self, db: Session, since: datetime | None = None) -> float:
        stmt = select(func.avg(Event.risk_score))
        if since is not None:
            stmt = stmt.where(Event.timestamp >= since)
        return float(db.scalar(stmt) or 0.0)

    def timeline_rows(self, db: Session, since: datetime) -> list[Row]:
        """Return (timestamp, severity) pairs for time-series bucketing.

        Bucketing happens in Python so the same query works on PostgreSQL and
        on the SQLite database used by the tests. At V1 event volumes this is
        cheap; a pre-aggregated rollup table is the V2 optimisation.
        """
        return list(
            db.execute(
                select(Event.timestamp, Event.severity)
                .where(Event.timestamp >= since)
                .order_by(Event.timestamp)
            )
        )

    # --- V3: ML aggregates -------------------------------------------------
    def ml_counts(self, db: Session, since: datetime | None = None) -> dict[str, int]:
        """Scored / anomalous event counts, computed from stored rows."""
        scored = select(func.count(func.distinct(MLInference.event_id)))
        anomalous = select(func.count(func.distinct(MLInference.event_id))).where(
            MLInference.is_anomaly.is_(True)
        )
        if since is not None:
            scored = scored.where(MLInference.inferred_at >= since)
            anomalous = anomalous.where(MLInference.inferred_at >= since)
        return {
            "scored": int(db.scalar(scored) or 0),
            "anomalous": int(db.scalar(anomalous) or 0),
        }

    def anomaly_timeline_rows(self, db: Session, since: datetime) -> list[Row]:
        """(timestamp, severity) for anomalous events, for time-series bucketing."""
        return list(
            db.execute(
                select(Event.timestamp, Event.severity)
                .join(MLInference, MLInference.event_id == Event.id)
                .where(MLInference.is_anomaly.is_(True), Event.timestamp >= since)
                .order_by(Event.timestamp)
            )
        )

    def anomaly_group_count(self, db: Session, column, limit: int = 10) -> list[Row]:
        """Anomalous event counts grouped by one Event column."""
        return list(
            db.execute(
                select(column, func.count(func.distinct(Event.id)).label("count"))
                .join(MLInference, MLInference.event_id == Event.id)
                .where(MLInference.is_anomaly.is_(True))
                .group_by(column)
                .order_by(func.count(func.distinct(Event.id)).desc())
                .limit(limit)
            )
        )

    def anomaly_score_buckets(self, db: Session, buckets: int = 10) -> list[tuple[str, int]]:
        """Distribution of anomaly scores. Bucketing in Python keeps this
        portable between PostgreSQL and the SQLite the tests run on."""
        scores = list(db.scalars(select(MLInference.anomaly_score)))
        counts = [0] * buckets
        for score in scores:
            index = min(int(float(score) * buckets), buckets - 1)
            counts[index] += 1
        return [
            (f"{index / buckets:.1f}-{(index + 1) / buckets:.1f}", counts[index])
            for index in range(buckets)
        ]

    def ml_assisted_incident_count(self, db: Session) -> int:
        """Incidents with at least one event the model flagged as anomalous."""
        return int(
            db.scalar(
                select(func.count(func.distinct(Event.incident_id)))
                .join(MLInference, MLInference.event_id == Event.id)
                .where(MLInference.is_anomaly.is_(True), Event.incident_id.is_not(None))
            )
            or 0
        )

    def mitre_rows(self, db: Session, since: datetime) -> list[Row]:
        return list(
            db.execute(select(Event.mitre_techniques).where(Event.timestamp >= since))
        )


event_repository = EventRepository()
