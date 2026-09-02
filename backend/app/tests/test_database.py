"""Database-level guarantees: constraints, indexes, timestamps, relationships.

These test the schema rather than the API. A value the database refuses can
never be persisted by a bug in the application layer.
"""

from __future__ import annotations

import pytest
from sqlalchemy import inspect
from sqlalchemy.exc import IntegrityError

from app.core.database import get_engine
from app.models.event import Event
from app.models.incident import Incident
from app.models.ioc import IOC
from app.models.user import User


def _event(**overrides) -> Event:
    values = {
        "event_id": None,
        "source": "Sysmon",
        "source_type": "endpoint",
        "event_type": "process_creation",
        "title": "Test event",
        "severity": "Low",
        "status": "New",
        "risk_score": 0,
        "normalized_data": {},
        "mitre_techniques": [],
        "detection_rules": [],
        "detections": [],
    }
    values.update(overrides)
    return Event(**values)


# ---------------------------------------------------------------- constraints
def test_event_severity_vocabulary_is_enforced_by_the_database(db) -> None:
    from app.repositories.event_repository import event_repository

    with pytest.raises(IntegrityError):
        event_repository.create(db, _event(severity="Catastrophic"))
    db.rollback()


def test_event_status_vocabulary_is_enforced(db) -> None:
    from app.repositories.event_repository import event_repository

    with pytest.raises(IntegrityError):
        event_repository.create(db, _event(status="Whatever"))
    db.rollback()


def test_risk_score_is_bounded(db) -> None:
    from app.repositories.event_repository import event_repository

    with pytest.raises(IntegrityError):
        event_repository.create(db, _event(risk_score=5000))
    db.rollback()


def test_incident_status_vocabulary_is_enforced(db) -> None:
    from app.repositories.incident_repository import incident_repository

    with pytest.raises(IntegrityError):
        incident_repository.create(
            db, Incident(title="bad", severity="High", status="Escalated")
        )
    db.rollback()


def test_user_role_vocabulary_is_enforced(db) -> None:
    with pytest.raises(IntegrityError):
        db.add(
            User(
                email="rogue@aegisx.dev",
                full_name="Rogue",
                hashed_password="x",
                role="superuser",
            )
        )
        db.flush()
    db.rollback()


def test_indicator_values_are_unique_per_type(db) -> None:
    db.add(IOC(type="ip", value="203.0.113.99"))
    db.flush()
    with pytest.raises(IntegrityError):
        db.add(IOC(type="ip", value="203.0.113.99"))
        db.flush()
    db.rollback()


# -------------------------------------------------------------------- indexes
def test_soc_query_indexes_exist() -> None:
    """Every documented SOC access pattern has a supporting index."""
    inspector = inspect(get_engine())

    expected = {
        "events": {
            "ix_events_severity_timestamp",
            "ix_events_source_timestamp",
            "ix_events_status_timestamp",
            "ix_events_hostname_timestamp",
            "ix_events_incident_timestamp",
            "ix_events_timestamp",
        },
        "incidents": {
            "ix_incidents_status_created",
            "ix_incidents_severity_created",
            "ix_incidents_analyst_status",
        },
        "iocs": {"ix_iocs_type_lastseen"},
        "notifications": {"ix_notifications_read_created"},
        "audit_logs": {"ix_audit_action_timestamp", "ix_audit_target"},
    }

    for table, required in expected.items():
        present = {index["name"] for index in inspector.get_indexes(table)}
        missing = required - present
        assert not missing, f"{table} is missing indexes: {sorted(missing)}"


def test_no_index_on_free_text_payload_columns() -> None:
    """Write amplification without a reader is a cost, not a safeguard."""
    inspector = inspect(get_engine())
    indexed_columns = {
        column
        for index in inspector.get_indexes("events")
        for column in index["column_names"]
    }
    assert "raw_log" not in indexed_columns
    assert "command_line" not in indexed_columns


# ----------------------------------------------------------------- timestamps
def test_rows_are_timestamped_automatically(db) -> None:
    from app.repositories.event_repository import event_repository

    event = event_repository.create(db, _event())
    db.flush()

    assert event.created_at is not None
    assert event.updated_at is not None
    assert event.timestamp is not None
    db.rollback()


# -------------------------------------------------------------- relationships
def test_event_links_to_its_incident(db) -> None:
    from app.repositories.event_repository import event_repository
    from app.repositories.incident_repository import incident_repository

    incident = incident_repository.create(db, Incident(title="Linked", severity="High"))
    event = event_repository.create(db, _event())
    event.incident_id = incident.id
    db.flush()

    assert event.incident is incident
    assert event in incident.events
    db.rollback()


def test_indicators_are_shared_between_events(db) -> None:
    from app.repositories.event_repository import event_repository
    from app.repositories.ioc_repository import ioc_repository

    first = event_repository.create(db, _event())
    second = event_repository.create(db, _event())

    ioc = ioc_repository.upsert(db, ioc_type="ip", value="203.0.113.200")
    first.iocs.append(ioc)
    second.iocs.append(ioc)
    db.flush()

    assert len(ioc.events) == 2
    db.rollback()


def test_repeated_sightings_increment_rather_than_duplicate(db) -> None:
    from app.repositories.ioc_repository import ioc_repository

    first = ioc_repository.upsert(db, ioc_type="domain", value="beacon.example")
    again = ioc_repository.upsert(db, ioc_type="domain", value="beacon.example")

    assert first.id == again.id
    assert again.sighting_count == 2
    db.rollback()


def test_session_factory_does_not_self_deadlock() -> None:
    """The session factory must be usable as the first thing to touch the database.

    Regression guard. ``get_session_factory`` holds the module lock and then
    calls ``get_engine``, which takes it again. With a non-reentrant Lock that
    is a self-deadlock, and it is invisible from the API because startup builds
    the engine first - so only a CLI entrypoint hits it. It cost an evaluation
    run that hung at zero CPU having written nothing.

    Run in a worker thread with a join timeout so a regression fails this test
    in seconds instead of hanging the whole suite, which is the failure mode
    being guarded against.
    """
    import threading

    from app.core.database import get_session_factory, reset_engine

    reset_engine()  # force the cold path: no engine cached yet

    done = threading.Event()
    error: list[BaseException] = []

    def _touch() -> None:
        try:
            factory = get_session_factory()
            session = factory()
            session.close()
        except BaseException as exc:  # noqa: BLE001 - reported, not swallowed
            error.append(exc)
        finally:
            done.set()

    worker = threading.Thread(target=_touch, daemon=True)
    worker.start()

    assert done.wait(timeout=10), (
        "get_session_factory() deadlocked on the cold path - the module lock "
        "must be reentrant (see app/core/database.py)"
    )
    assert not error, f"cold-path session creation raised: {error[0]!r}"
