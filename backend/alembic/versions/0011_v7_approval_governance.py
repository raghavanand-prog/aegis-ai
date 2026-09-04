"""V7: approval governance - acting roles and a rejection timestamp.

Revision ID: 0011_v7_approval_governance
Revises: 0010_v7_feedback_identity
Create Date: 2026-09-04

Four columns on ``adaptation_proposals``, all nullable, all recording facts the
V5 schema could state only indirectly or not at all.

``proposed_by_role`` / ``approved_by_role`` / ``rejected_by_role`` record the
role each actor held **at the moment they acted**. Resolving authority by
joining ``users`` at read time would restate every past decision in terms of
today's permissions: promote an analyst and the audit trail would claim they
had always approved as an administrator.

``rejected_at`` closes an asymmetry. Approval, deployment and rollback each
recorded when they happened; rejection did not, so "when was this refused" was
answerable only from the audit log - a different table, with a different
retention story, for one of the four terminal decisions.

**What this migration deliberately does not do.** ``self_approved`` is not
dropped, and no constraint is added forbidding ``approved_by = proposed_by``.
Four-eyes is enforced in ``proposals.approve``, which is the only path to the
APPROVED state; a CHECK constraint would additionally invalidate rows written
before V7, when self-approval was permitted and recorded. Those rows are
history. Making them unrepresentable would mean either rewriting them or
failing the migration, and both amount to backdating a guarantee the system did
not offer at the time.

Nothing is backfilled for the same reason: the role an actor held when they
acted was not captured, and inferring it from their current role would
manufacture provenance. Pre-V7 rows keep nulls and are identifiable by them.

The downgrade drops all four columns; the 0010 schema is recoverable.
"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision = "0011_v7_approval_governance"
down_revision = "0010_v7_feedback_identity"
branch_labels = None
depends_on = None

_ROLE_COLUMNS = ("proposed_by_role", "approved_by_role", "rejected_by_role")


def upgrade() -> None:
    for column in _ROLE_COLUMNS:
        op.add_column(
            "adaptation_proposals", sa.Column(column, sa.String(length=32), nullable=True)
        )
    op.add_column(
        "adaptation_proposals",
        sa.Column("rejected_at", sa.DateTime(timezone=True), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("adaptation_proposals", "rejected_at")
    for column in reversed(_ROLE_COLUMNS):
        op.drop_column("adaptation_proposals", column)
