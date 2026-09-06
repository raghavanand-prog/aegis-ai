"""V9: widen the incident status constraint to the full lifecycle.

Adds ``Triaged``, ``Containment Pending`` and ``Closed`` to the values
``incidents.status`` may hold. The four V1 values keep their exact spelling, so
**no data migration is needed** - every existing row is already one of them and
every one of them stays valid. The upgrade only relaxes the constraint.

The transition rules themselves are not here and cannot be. A CHECK constraint
sees the row being written, never the row it replaces, so it can say
``'Closed'`` is a legal spelling and can say nothing about whether the incident
was allowed to get there. That lives in ``app.incidents.lifecycle`` and is
enforced in the service layer.

The downgrade refuses rather than rewriting, following ``0008``. An incident in
``Triaged`` has no V8 equivalent; mapping it back onto ``Open`` would erase that
somebody assessed it, and mapping ``Closed`` onto ``Resolved`` would erase a
signed decision and silently reopen a sealed record.

SQLite cannot ALTER a CHECK constraint, so both directions rebuild the table
through ``batch_alter_table``.
"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision = "0012_v9_incident_lifecycle"
down_revision = "0011_v7_approval_governance"
branch_labels = None
depends_on = None

V1_STATUSES = "status IN ('Open', 'Investigating', 'Contained', 'Resolved')"
V9_STATUSES = (
    "status IN ('Open', 'Triaged', 'Investigating', 'Containment Pending', "
    "'Contained', 'Resolved', 'Closed')"
)

#: The states this migration introduces, and therefore the ones that have
#: nowhere to go on the way back down.
V9_ONLY = ("Triaged", "Containment Pending", "Closed")


def upgrade() -> None:
    with op.batch_alter_table("incidents") as batch:
        batch.drop_constraint("ck_incidents_status", type_="check")
        batch.create_check_constraint("ck_incidents_status", V9_STATUSES)


def downgrade() -> None:
    connection = op.get_bind()
    stranded = connection.execute(
        sa.text(
            "SELECT COUNT(*) FROM incidents WHERE status IN "
            "('Triaged', 'Containment Pending', 'Closed')"
        )
    ).scalar()
    if stranded:
        raise RuntimeError(
            f"{stranded} incident(s) are in a V9 lifecycle state "
            f"({', '.join(V9_ONLY)}) with no V1 equivalent. Downgrading would "
            "have to rewrite them, which would erase that an incident was "
            "triaged, or reopen one that was closed and signed. Resolve them "
            "first."
        )
    with op.batch_alter_table("incidents") as batch:
        batch.drop_constraint("ck_incidents_status", type_="check")
        batch.create_check_constraint("ck_incidents_status", V1_STATUSES)
