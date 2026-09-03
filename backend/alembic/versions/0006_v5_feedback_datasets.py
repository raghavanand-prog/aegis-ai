"""V5: versioned feedback datasets.

Revision ID: 0006_v5_feedback_datasets
Revises: 0005_v5_adaptation
Create Date: 2026-09-03

Two tables. Notes on the choices that are not obvious:

* ``feedback_datasets`` is unique on (name, version, **fingerprint**), the same
  identity rule V4 applied to ``evaluation_datasets``. Two snapshots that share
  a name and version but hash differently are not the same data, and results
  produced over them must never be pooled.
* Membership is **materialised** in ``feedback_dataset_members`` rather than
  recomputed from a query over ``analyst_feedback``. A query returns whatever
  the feedback table says today; correcting a single label would then silently
  change what an already-trained model was trained on. Copying ``label`` and
  ``binary_label`` into the member row is deliberate denormalisation, and it is
  the entire reason this table exists.
* ``binary_label`` is NOT NULL here although the projection is nullable in the
  vocabulary. Labels without a projection ('suspicious', 'uncertain') are not
  training-eligible and never become members, so a NULL in this column would
  mean the builder had a bug.
* The member -> feedback foreign key is ``RESTRICT``, not ``CASCADE``. Deleting
  feedback that a dataset was built from would leave a model whose training data
  cannot be reconstructed; the database refuses instead.

The downgrade drops both tables cleanly; the 0005 schema is recoverable.
"""

from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

from alembic import op

revision = "0006_v5_feedback_datasets"
down_revision = "0005_v5_adaptation"
branch_labels = None
depends_on = None

JSONType = sa.JSON().with_variant(JSONB, "postgresql")


def upgrade() -> None:
    op.create_table(
        "feedback_datasets",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("name", sa.String(length=64), nullable=False),
        sa.Column("version", sa.String(length=32), nullable=False),
        sa.Column("fingerprint", sa.String(length=64), nullable=False),
        sa.Column("sample_count", sa.Integer(), nullable=False),
        sa.Column("label_distribution", JSONType, nullable=False),
        sa.Column("feature_schema_version", sa.String(length=16), nullable=False),
        sa.Column("selection", JSONType, nullable=False),
        sa.Column("created_by", sa.String(length=255), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("notes", sa.Text(), nullable=True),
        sa.CheckConstraint("sample_count >= 0", name="ck_feedback_dataset_sample_count"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("name", "version", "fingerprint", name="uq_feedback_dataset_identity"),
    )
    op.create_index("ix_feedback_datasets_name", "feedback_datasets", ["name"])
    op.create_index("ix_feedback_datasets_fingerprint", "feedback_datasets", ["fingerprint"])
    op.create_index("ix_feedback_datasets_created_at", "feedback_datasets", ["created_at"])

    op.create_table(
        "feedback_dataset_members",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("dataset_id", sa.Integer(), nullable=False),
        sa.Column("feedback_id", sa.Integer(), nullable=False),
        sa.Column("target_type", sa.String(length=16), nullable=False),
        sa.Column("target_id", sa.Integer(), nullable=False),
        sa.Column("label", sa.String(length=32), nullable=False),
        sa.Column("binary_label", sa.Boolean(), nullable=False),
        sa.ForeignKeyConstraint(["dataset_id"], ["feedback_datasets.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["feedback_id"], ["analyst_feedback.id"], ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("dataset_id", "feedback_id", name="uq_feedback_member_unique"),
    )
    op.create_index(
        "ix_feedback_dataset_members_dataset_id", "feedback_dataset_members", ["dataset_id"]
    )


def downgrade() -> None:
    op.drop_index("ix_feedback_dataset_members_dataset_id", table_name="feedback_dataset_members")
    op.drop_table("feedback_dataset_members")
    op.drop_index("ix_feedback_datasets_created_at", table_name="feedback_datasets")
    op.drop_index("ix_feedback_datasets_fingerprint", table_name="feedback_datasets")
    op.drop_index("ix_feedback_datasets_name", table_name="feedback_datasets")
    op.drop_table("feedback_datasets")
