"""V7: auditable analyst identity on feedback.

Revision ID: 0010_v7_feedback_identity
Revises: 0009_v5_proposals
Create Date: 2026-09-04

Two columns on ``analyst_feedback``, both nullable, both about being able to
answer "who concluded this, and under what authority" months later.

``analyst_id`` is a real foreign key to ``users`` where one exists. Until V7 the
only record of authorship was ``analyst``, a free-text string, so an account
rename or a second person with the same display name broke the trail silently.
It is ``SET NULL`` rather than cascade: deleting an account must not delete the
record of what that account concluded, because that record is exactly what an
investigation into the account would need.

It is nullable because **simulated feedback has no account**. Every result in
V4-V6 rests on a simulator, and minting a synthetic user for it would make a
generated claim indistinguishable from a human's in the one column that is
supposed to tell them apart. A null here is a fact, not a gap.

``analyst_role`` records the role held **at the moment of the claim** rather
than being joined from ``users`` on read. Roles change. If an analyst is later
promoted, a join would retroactively report every claim they ever made as having
been made with the new authority, which is a rewrite of the audit trail dressed
up as normalisation.

Backfill is deliberately absent. Existing rows were written before identity was
captured, and guessing which account each ``analyst`` string referred to would
manufacture provenance that was never recorded. They stay null and are
distinguishable from V7 rows by that null.

The downgrade drops both columns; the 0009 schema is recoverable.
"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision = "0010_v7_feedback_identity"
down_revision = "0009_v5_proposals"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Batch mode: SQLite cannot add a column carrying a foreign key in place, so
    # alembic recreates the table. Postgres takes the plain ALTER path.
    with op.batch_alter_table("analyst_feedback") as batch:
        batch.add_column(sa.Column("analyst_id", sa.Integer(), nullable=True))
        batch.add_column(sa.Column("analyst_role", sa.String(length=32), nullable=True))
        batch.create_foreign_key(
            "fk_analyst_feedback_analyst_id_users",
            "users",
            ["analyst_id"],
            ["id"],
            ondelete="SET NULL",
        )

    op.create_index(
        "ix_analyst_feedback_analyst_id", "analyst_feedback", ["analyst_id"]
    )


def downgrade() -> None:
    op.drop_index("ix_analyst_feedback_analyst_id", table_name="analyst_feedback")
    with op.batch_alter_table("analyst_feedback") as batch:
        batch.drop_constraint("fk_analyst_feedback_analyst_id_users", type_="foreignkey")
        batch.drop_column("analyst_role")
        batch.drop_column("analyst_id")
