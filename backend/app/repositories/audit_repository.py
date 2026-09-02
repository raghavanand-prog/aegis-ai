"""Audit trail queries."""

from __future__ import annotations

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models.audit import AuditLog
from app.repositories.base import BaseRepository


class AuditRepository(BaseRepository[AuditLog]):
    def __init__(self) -> None:
        super().__init__(AuditLog)

    def list_paginated(
        self,
        db: Session,
        *,
        action: str | None = None,
        target_id: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> tuple[list[AuditLog], int]:
        stmt = select(AuditLog)
        count_stmt = select(func.count()).select_from(AuditLog)

        if action:
            stmt = stmt.where(AuditLog.action == action)
            count_stmt = count_stmt.where(AuditLog.action == action)
        if target_id:
            stmt = stmt.where(AuditLog.target_id == target_id)
            count_stmt = count_stmt.where(AuditLog.target_id == target_id)

        total = int(db.scalar(count_stmt) or 0)
        items = list(
            db.scalars(stmt.order_by(AuditLog.timestamp.desc()).limit(limit).offset(offset))
        )
        return items, total


audit_repository = AuditRepository()
