"""V5: candidate model lifecycle states.

Revision ID: 0008_v5_model_lifecycle
Revises: 0007_v5_drift
Create Date: 2026-09-03

Widens ``ck_ml_models_status`` to admit the V5 lifecycle. V3 shipped three
states - active, archived, failed - which describe a model that is either
serving, not serving, or broken. V5 needs to distinguish *why* a model is not
serving, because the approval workflow reads that distinction:

* ``candidate``   trained and deliberately inert; never evaluated.
* ``evaluating``  under comparison against the deployed model.
* ``approved``    passed its gates and signed off by a human; may be activated.
* ``rejected``    evaluated and refused. Kept, never deleted: a rejection is a
                  measured result, and discarding it means repeating the work.
* ``rolled_back`` was deployed and withdrawn. Deliberately distinct from
                  archived - this one failed in production, which is worth being
                  able to see a year later.

``archived`` keeps its V3 meaning: registered, reproducible, not serving.

No data migration is needed. Every existing row is 'active', 'archived' or
'failed', all of which remain valid, so the upgrade only relaxes the constraint.
The downgrade re-narrows it and will fail loudly if any row is in a V5 state -
which is correct: silently rewriting a rejected model to 'archived' would erase
the fact that it was refused.

SQLite cannot ALTER a CHECK constraint, so both directions rebuild the table
through batch_alter_table.
"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision = "0008_v5_model_lifecycle"
down_revision = "0007_v5_drift"
branch_labels = None
depends_on = None

V3_STATUSES = "status IN ('active', 'archived', 'failed')"
V5_STATUSES = (
    "status IN ('active', 'archived', 'failed', 'candidate', "
    "'evaluating', 'approved', 'rejected', 'rolled_back')"
)


def upgrade() -> None:
    with op.batch_alter_table("ml_models") as batch:
        batch.drop_constraint("ck_ml_models_status", type_="check")
        batch.create_check_constraint("ck_ml_models_status", V5_STATUSES)


def downgrade() -> None:
    # Refuse rather than rewrite. A model in a V5 state has no V3 equivalent,
    # and mapping 'rejected' onto 'archived' would discard a measured refusal.
    connection = op.get_bind()
    stranded = connection.execute(
        sa.text(
            "SELECT COUNT(*) FROM ml_models WHERE status IN "
            "('candidate', 'evaluating', 'approved', 'rejected', 'rolled_back')"
        )
    ).scalar()
    if stranded:
        raise RuntimeError(
            f"{stranded} model(s) are in a V5 lifecycle state with no V3 "
            "equivalent. Downgrading would have to rewrite them, which would "
            "erase whether a model was refused or withdrawn. Resolve them first."
        )
    with op.batch_alter_table("ml_models") as batch:
        batch.drop_constraint("ck_ml_models_status", type_="check")
        batch.create_check_constraint("ck_ml_models_status", V3_STATUSES)
