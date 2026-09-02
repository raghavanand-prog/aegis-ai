"""Notification queries."""

from __future__ import annotations

from sqlalchemy import func, select, update
from sqlalchemy.orm import Session

from app.models.notification import Notification
from app.repositories.base import BaseRepository


class NotificationRepository(BaseRepository[Notification]):
    def __init__(self) -> None:
        super().__init__(Notification)

    def list_paginated(
        self,
        db: Session,
        *,
        unread_only: bool = False,
        limit: int = 50,
        offset: int = 0,
    ) -> tuple[list[Notification], int]:
        stmt = select(Notification)
        count_stmt = select(func.count()).select_from(Notification)

        if unread_only:
            stmt = stmt.where(Notification.is_read.is_(False))
            count_stmt = count_stmt.where(Notification.is_read.is_(False))

        total = int(db.scalar(count_stmt) or 0)
        items = list(
            db.scalars(stmt.order_by(Notification.created_at.desc()).limit(limit).offset(offset))
        )
        return items, total

    def unread_count(self, db: Session) -> int:
        return int(
            db.scalar(
                select(func.count()).select_from(Notification).where(Notification.is_read.is_(False))
            )
            or 0
        )

    def mark_all_read(self, db: Session) -> int:
        result = db.execute(
            update(Notification).where(Notification.is_read.is_(False)).values(is_read=True)
        )
        db.flush()
        return int(result.rowcount or 0)


notification_repository = NotificationRepository()
