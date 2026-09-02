"""IOC queries."""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models.ioc import IOC
from app.repositories.base import BaseRepository


class IOCRepository(BaseRepository[IOC]):
    def __init__(self) -> None:
        super().__init__(IOC)

    def get_by_value(self, db: Session, ioc_type: str, value: str) -> IOC | None:
        return db.scalar(select(IOC).where(IOC.type == ioc_type, IOC.value == value))

    def upsert(
        self,
        db: Session,
        *,
        ioc_type: str,
        value: str,
        severity: str = "Medium",
        source: str | None = None,
        description: str | None = None,
        confidence: int = 50,
    ) -> IOC:
        """Insert an indicator or bump its sighting counter if already known."""
        existing = self.get_by_value(db, ioc_type, value)
        now = datetime.now(timezone.utc)
        if existing:
            existing.sighting_count += 1
            existing.last_seen = now
            if description and not existing.description:
                existing.description = description
            db.flush()
            return existing

        ioc = IOC(
            type=ioc_type,
            value=value,
            severity=severity,
            source=source,
            description=description,
            confidence=confidence,
            first_seen=now,
            last_seen=now,
        )
        return self.add(db, ioc)

    def list_paginated(
        self,
        db: Session,
        *,
        ioc_type: str | None = None,
        search: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> tuple[list[IOC], int]:
        stmt = select(IOC)
        count_stmt = select(func.count()).select_from(IOC)

        if ioc_type:
            stmt = stmt.where(IOC.type == ioc_type)
            count_stmt = count_stmt.where(IOC.type == ioc_type)
        if search:
            pattern = f"%{search.lower()}%"
            stmt = stmt.where(func.lower(IOC.value).like(pattern))
            count_stmt = count_stmt.where(func.lower(IOC.value).like(pattern))

        total = int(db.scalar(count_stmt) or 0)
        items = list(
            db.scalars(stmt.order_by(IOC.last_seen.desc()).limit(limit).offset(offset))
        )
        return items, total


ioc_repository = IOCRepository()
