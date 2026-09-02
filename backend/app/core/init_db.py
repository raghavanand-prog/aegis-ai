"""Database bootstrap helpers.

Alembic owns the schema. These helpers only verify that migrations have been
applied and create the bootstrap analyst account; the single exception is
SQLite (used by the test suite) where the schema is created directly.
"""

from __future__ import annotations

import logging

from sqlalchemy import inspect

from app.core.config import settings
from app.core.database import SessionLocal, get_engine
from app.models.base import Base
from app.services import auth_service

logger = logging.getLogger(__name__)

MIGRATION_HINT = (
    "Database schema is missing. Run migrations from the backend directory:\n"
    "    alembic upgrade head"
)


def create_all() -> None:
    """Create every table directly (SQLite/test path only)."""
    Base.metadata.create_all(bind=get_engine())


def schema_exists() -> bool:
    return inspect(get_engine()).has_table("events")


def bootstrap() -> None:
    """Prepare the database at application startup."""
    if settings.is_sqlite:
        create_all()

    if not schema_exists():
        logger.error(MIGRATION_HINT)
        return

    with SessionLocal() as db:
        auth_service.ensure_seed_user(db)
        db.commit()
