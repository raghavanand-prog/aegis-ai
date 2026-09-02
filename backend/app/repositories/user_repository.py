"""User queries."""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.user import User
from app.repositories.base import BaseRepository


class UserRepository(BaseRepository[User]):
    def __init__(self) -> None:
        super().__init__(User)

    def get_by_email(self, db: Session, email: str) -> User | None:
        return db.scalar(select(User).where(User.email == email.lower().strip()))

    def list_all(self, db: Session) -> list[User]:
        return list(db.scalars(select(User).order_by(User.id)))


user_repository = UserRepository()
