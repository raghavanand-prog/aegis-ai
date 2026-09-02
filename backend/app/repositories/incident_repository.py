"""Incident queries."""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import Row, func, or_, select
from sqlalchemy.orm import Session

from app.models.incident import Incident
from app.repositories.base import BaseRepository

# Incident numbering starts at 1000 so identifiers look like the INC-1024 the
# SOC UI already displays.
INCIDENT_ID_OFFSET = 1000


class IncidentRepository(BaseRepository[Incident]):
    def __init__(self) -> None:
        super().__init__(Incident)

    def create(self, db: Session, incident: Incident) -> Incident:
        """Persist an incident and assign its human readable identifier.

        Same two-step assignment as events: a unique placeholder satisfies the
        NOT NULL constraint, then the sequential INC-#### number is written
        once the primary key is known.
        """
        if not incident.incident_id:
            incident.incident_id = f"INC-NEW-{uuid.uuid4().hex[:16]}"
        db.add(incident)
        db.flush()
        if incident.incident_id.startswith("INC-NEW-"):
            incident.incident_id = f"INC-{INCIDENT_ID_OFFSET + incident.id}"
            db.flush()
        return incident

    def get_by_incident_id(self, db: Session, incident_id: str) -> Incident | None:
        return db.scalar(select(Incident).where(Incident.incident_id == incident_id))

    def list_paginated(
        self,
        db: Session,
        *,
        search: str | None = None,
        severity: str | None = None,
        status: str | None = None,
        analyst: str | None = None,
        since: datetime | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> tuple[list[Incident], int]:
        stmt = select(Incident)
        count_stmt = select(func.count()).select_from(Incident)

        def apply(condition):
            nonlocal stmt, count_stmt
            stmt = stmt.where(condition)
            count_stmt = count_stmt.where(condition)

        if search:
            pattern = f"%{search.lower()}%"
            apply(
                or_(
                    func.lower(Incident.title).like(pattern),
                    func.lower(Incident.description).like(pattern),
                    func.lower(Incident.incident_id).like(pattern),
                    func.lower(Incident.source).like(pattern),
                )
            )
        if severity:
            apply(Incident.severity == severity)
        if status:
            apply(Incident.status == status)
        if analyst:
            apply(Incident.analyst == analyst)
        if since is not None:
            apply(Incident.created_at >= since)

        total = int(db.scalar(count_stmt) or 0)
        items = list(
            db.scalars(
                stmt.order_by(Incident.created_at.desc(), Incident.id.desc())
                .limit(limit)
                .offset(offset)
            )
        )
        return items, total

    def count(self, db: Session, since: datetime | None = None, **filters) -> int:
        stmt = select(func.count()).select_from(Incident)
        if since is not None:
            stmt = stmt.where(Incident.created_at >= since)
        for column, value in filters.items():
            stmt = stmt.where(getattr(Incident, column) == value)
        return int(db.scalar(stmt) or 0)

    def group_count(self, db: Session, column, since: datetime | None = None) -> list[Row]:
        stmt = select(column, func.count().label("count")).group_by(column)
        if since is not None:
            stmt = stmt.where(Incident.created_at >= since)
        return list(db.execute(stmt.order_by(func.count().desc())))

    def workload_rows(self, db: Session, since: datetime | None = None) -> list[Row]:
        stmt = select(Incident.analyst, Incident.status, func.count().label("count")).group_by(
            Incident.analyst, Incident.status
        )
        if since is not None:
            stmt = stmt.where(Incident.created_at >= since)
        return list(db.execute(stmt))

    def timeline_rows(self, db: Session, since: datetime) -> list[Row]:
        return list(
            db.execute(
                select(Incident.created_at, Incident.severity)
                .where(Incident.created_at >= since)
                .order_by(Incident.created_at)
            )
        )


incident_repository = IncidentRepository()
