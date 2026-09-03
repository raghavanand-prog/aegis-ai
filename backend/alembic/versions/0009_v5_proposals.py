"""V5: adaptation proposals.

Revision ID: 0009_v5_proposals
Revises: 0008_v5_model_lifecycle
Create Date: 2026-09-03

One table, and it is the one that makes the human-in-the-loop requirement
structural rather than conventional. Production detection behaviour changes
through an approved row here or it does not change.

Notes on the choices that are not obvious:

* ``before_state`` is captured at creation and ``rollback_state`` at deployment,
  rather than either being derived later. Reconstructing "what was it before"
  from the current configuration is precisely the operation that fails when it
  is needed most - during an incident caused by the change.
* The actor columns are separate (proposed_by, approved_by, rejected_by,
  deployed_by, rolled_back_by) rather than one polymorphic actor field, because
  the entire point of the workflow is that these are different people, and a
  single column would make "who approved this" a query over an audit log.
* ``self_approved`` records rather than prevents. AEGISX has three roles, so an
  administrator can propose and approve; a boolean that surfaces it is more
  honest than a constraint that pretends the separation exists.
* ``candidate_model_id`` and ``feedback_dataset_id`` are nullable and SET NULL.
  A threshold proposal has no candidate model, and inventing one to satisfy a
  foreign key would be worse than a null.
* No row is ever deleted. A rejected proposal is a measured refusal, and a
  rolled-back one is the most informative row in the table.

The downgrade drops the table cleanly; the 0008 schema is recoverable.
"""

from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

from alembic import op

revision = "0009_v5_proposals"
down_revision = "0008_v5_model_lifecycle"
branch_labels = None
depends_on = None

JSONType = sa.JSON().with_variant(JSONB, "postgresql")


def upgrade() -> None:
    op.create_table(
        "adaptation_proposals",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("proposal_type", sa.String(length=48), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("title", sa.String(length=255), nullable=False),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("affected_component", sa.String(length=128), nullable=False),
        sa.Column("before_state", JSONType, nullable=False),
        sa.Column("after_state", JSONType, nullable=False),
        sa.Column("evidence", JSONType, nullable=False),
        sa.Column("validation", JSONType, nullable=False),
        sa.Column("expected_impact", JSONType, nullable=False),
        sa.Column("risk_assessment", sa.Text(), nullable=True),
        sa.Column("candidate_model_id", sa.Integer(), nullable=True),
        sa.Column("feedback_dataset_id", sa.Integer(), nullable=True),
        sa.Column("proposed_by", sa.String(length=255), nullable=False),
        sa.Column("approved_by", sa.String(length=255), nullable=True),
        sa.Column("rejected_by", sa.String(length=255), nullable=True),
        sa.Column("deployed_by", sa.String(length=255), nullable=True),
        sa.Column("rolled_back_by", sa.String(length=255), nullable=True),
        sa.Column("self_approved", sa.Boolean(), nullable=False),
        sa.Column("rejection_reason", sa.Text(), nullable=True),
        sa.Column("rollback_reason", sa.Text(), nullable=True),
        sa.Column("rollback_state", JSONType, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("approved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("deployed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("rolled_back_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(
            "status IN ('pending', 'approved', 'rejected', 'deployed', "
            "'rolled_back', 'superseded')",
            name="ck_adaptation_proposal_status",
        ),
        sa.ForeignKeyConstraint(["candidate_model_id"], ["ml_models.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(
            ["feedback_dataset_id"], ["feedback_datasets.id"], ondelete="SET NULL"
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_adaptation_proposals_type", "adaptation_proposals", ["proposal_type"])
    op.create_index("ix_adaptation_proposals_status", "adaptation_proposals", ["status"])
    op.create_index("ix_adaptation_proposals_component", "adaptation_proposals", ["affected_component"])
    op.create_index("ix_adaptation_proposals_proposed_by", "adaptation_proposals", ["proposed_by"])
    op.create_index("ix_adaptation_proposals_created_at", "adaptation_proposals", ["created_at"])
    op.create_index(
        "ix_adaptation_proposals_status_created", "adaptation_proposals", ["status", "created_at"]
    )


def downgrade() -> None:
    for name in (
        "ix_adaptation_proposals_status_created",
        "ix_adaptation_proposals_created_at",
        "ix_adaptation_proposals_proposed_by",
        "ix_adaptation_proposals_component",
        "ix_adaptation_proposals_status",
        "ix_adaptation_proposals_type",
    ):
        op.drop_index(name, table_name="adaptation_proposals")
    op.drop_table("adaptation_proposals")
