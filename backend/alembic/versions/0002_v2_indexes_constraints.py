"""V2: detection explanations, session versioning, SOC indexes and value constraints.

Revision ID: 0002_v2_hardening
Revises: 0001_initial
Create Date: 2026-09-02

Indexing decisions (documented deliberately - indexes are not free):

* ``events`` is always read newest-first and filtered by exactly one of
  severity / source / status / hostname, or scoped to an incident. Each
  composite index leads with that filter column and trails ``timestamp`` so one
  index satisfies both the predicate and the ordering.
* ``incidents`` is read by status and by severity (queue views) and grouped by
  analyst (workload view).
* ``iocs`` lookup is "have we seen this value" - already covered by the unique
  constraint - plus "recent indicators of this type".
* ``notifications`` is read unread-first, newest-first.
* ``audit_logs`` is queried by action over time and by target object.

No index was added for columns nothing queries (``process``, ``command_line``,
``raw_log``): write amplification without a reader is a cost, not a safeguard.

Check constraints move the severity/status vocabularies into the database, so a
bug in the application cannot persist a value the UI has no way to render.
"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op
from app.models.base import JSONType

revision = "0002_v2_hardening"
down_revision = "0001_initial"
branch_labels = None
depends_on = None

EVENT_INDEXES = [
    ("ix_events_severity_timestamp", "events", ["severity", "timestamp"]),
    ("ix_events_source_timestamp", "events", ["source", "timestamp"]),
    ("ix_events_status_timestamp", "events", ["status", "timestamp"]),
    ("ix_events_hostname_timestamp", "events", ["hostname", "timestamp"]),
    ("ix_events_incident_timestamp", "events", ["incident_id", "timestamp"]),
    ("ix_incidents_status_created", "incidents", ["status", "created_at"]),
    ("ix_incidents_severity_created", "incidents", ["severity", "created_at"]),
    ("ix_incidents_analyst_status", "incidents", ["analyst", "status"]),
    ("ix_iocs_type_lastseen", "iocs", ["type", "last_seen"]),
    ("ix_notifications_read_created", "notifications", ["is_read", "created_at"]),
    ("ix_audit_action_timestamp", "audit_logs", ["action", "timestamp"]),
    ("ix_audit_target", "audit_logs", ["target_type", "target_id"]),
]

CHECK_CONSTRAINTS = [
    ("events", "ck_events_severity", "severity IN ('Low', 'Medium', 'High', 'Critical')"),
    ("events", "ck_events_status", "status IN ('New', 'Investigating', 'Resolved')"),
    ("events", "ck_events_risk_score", "risk_score >= 0 AND risk_score <= 100"),
    ("incidents", "ck_incidents_severity", "severity IN ('Low', 'Medium', 'High', 'Critical')"),
    (
        "incidents",
        "ck_incidents_status",
        "status IN ('Open', 'Investigating', 'Contained', 'Resolved')",
    ),
    ("incidents", "ck_incidents_risk_score", "risk_score >= 0 AND risk_score <= 100"),
    ("iocs", "ck_iocs_confidence", "confidence >= 0 AND confidence <= 100"),
    (
        "notifications",
        "ck_notifications_severity",
        "severity IN ('low', 'medium', 'high', 'critical')",
    ),
    ("users", "ck_users_role", "role IN ('admin', 'analyst', 'viewer')"),
    ("users", "ck_users_token_version", "token_version >= 1"),
]


def upgrade() -> None:
    # --- new columns -------------------------------------------------------
    op.add_column(
        "events",
        sa.Column("detections", JSONType, nullable=False, server_default=sa.text("'[]'")),
    )
    op.add_column(
        "users",
        sa.Column("token_version", sa.Integer(), nullable=False, server_default=sa.text("1")),
    )

    # Existing rows keep their rule ids; the richer explanation only exists for
    # events detected from V2 onwards, and the API reports it as an empty list
    # rather than inventing reasons after the fact.

    # --- indexes -----------------------------------------------------------
    for name, table, columns in EVENT_INDEXES:
        op.create_index(name, table, columns)

    # --- constraints -------------------------------------------------------
    # batch mode so SQLite (used by the test suite) rebuilds the table instead
    # of failing on ALTER TABLE ADD CONSTRAINT.
    for table, name, condition in CHECK_CONSTRAINTS:
        with op.batch_alter_table(table) as batch:
            batch.create_check_constraint(name, condition)


def downgrade() -> None:
    for table, name, _ in reversed(CHECK_CONSTRAINTS):
        with op.batch_alter_table(table) as batch:
            batch.drop_constraint(name, type_="check")

    for name, table, _ in reversed(EVENT_INDEXES):
        op.drop_index(name, table_name=table)

    op.drop_column("users", "token_version")
    op.drop_column("events", "detections")
