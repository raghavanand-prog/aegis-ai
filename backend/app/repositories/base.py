"""Repository base class.

Repositories own all query construction. Services orchestrate them and never
build SQL themselves, which keeps the query surface small enough to review.
"""

from __future__ import annotations

from typing import Generic, TypeVar

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models.base import Base

ModelT = TypeVar("ModelT", bound=Base)


class BaseRepository(Generic[ModelT]):
    model: type[ModelT]

    def __init__(self, model: type[ModelT]) -> None:
        self.model = model

    def get(self, db: Session, pk: int) -> ModelT | None:
        return db.get(self.model, pk)

    def add(self, db: Session, instance: ModelT) -> ModelT:
        db.add(instance)
        db.flush()
        return instance

    def count(self, db: Session) -> int:
        return int(db.scalar(select(func.count()).select_from(self.model)) or 0)

    def delete(self, db: Session, instance: ModelT) -> None:
        db.delete(instance)
        db.flush()
