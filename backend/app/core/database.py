"""Database engine, session factory and session helpers.

The engine is created lazily on first use. Importing an application module
should never open a database connection or require a driver to be installed -
that is what let the detection evaluation CLI (which touches no database) fail
on a missing PostgreSQL driver during V2 development.
"""

from __future__ import annotations

from collections.abc import Generator, Iterator
from contextlib import contextmanager
from threading import RLock

from sqlalchemy import create_engine
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import settings

_engine: Engine | None = None
_session_factory: sessionmaker | None = None
#: Reentrant on purpose. ``get_session_factory`` holds this lock and then calls
#: ``get_engine``, which takes it again to build the engine on first use. With a
#: plain Lock that is a self-deadlock, and it only shows up when the session
#: factory is the very first thing to touch the database - which is exactly what
#: a CLI entrypoint does, and never what the API does, because startup builds the
#: engine first. Reproduced by `python -m app.ml.evaluation.run_ml_eval`.
_lock = RLock()


def get_engine() -> Engine:
    """Return the process-wide engine, creating it on first use."""
    global _engine
    if _engine is None:
        with _lock:
            if _engine is None:
                connect_args: dict = {}
                if settings.is_sqlite:
                    # Only used by the test suite.
                    connect_args = {"check_same_thread": False}

                _engine = create_engine(
                    settings.database_url,
                    echo=settings.db_echo,
                    pool_pre_ping=True,
                    future=True,
                    connect_args=connect_args,
                )
    return _engine


def get_session_factory() -> sessionmaker:
    global _session_factory
    if _session_factory is None:
        with _lock:
            if _session_factory is None:
                _session_factory = sessionmaker(
                    bind=get_engine(),
                    autoflush=False,
                    autocommit=False,
                    expire_on_commit=False,
                )
    return _session_factory


def SessionLocal() -> Session:  # noqa: N802 - kept as a call-compatible name
    """Create a new session (call-compatible with the previous sessionmaker)."""
    return get_session_factory()()


def reset_engine() -> None:
    """Drop the cached engine. Used by tests that repoint the database URL."""
    global _engine, _session_factory
    with _lock:
        if _engine is not None:
            _engine.dispose()
        _engine = None
        _session_factory = None


def get_db() -> Generator[Session, None, None]:
    """FastAPI dependency yielding a request scoped session."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@contextmanager
def session_scope() -> Iterator[Session]:
    """Session context manager for background workers (telemetry collector)."""
    db = SessionLocal()
    try:
        yield db
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()
