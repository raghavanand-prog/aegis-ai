"""V5: analyst feedback.

Revision ID: 0005_v5_adaptation
Revises: 0004_v4_evaluation
Create Date: 2026-09-03

One table in this revision. Notes on the choices that are not obvious:

* ``analyst_feedback`` is **append-only by design**, which is why it carries a
  self-referential ``supersedes_id`` / ``superseded_by_id`` pair instead of
  being updated in place. A feedback row records what a named analyst claimed at
  a moment in time; later disagreement does not make the earlier claim not have
  happened. Corrections insert a new row and both survive, so "why was the model
  trained on that label" still has an answer months later - including when the
  label was wrong and who changed it.
* ``confidence`` is **nullable** and CHECK-constrained to [0, 1]. Nullable is
  the point: an analyst who states no confidence has not stated one, and
  defaulting to 1.0 would invent certainty they never expressed.
* ``feature_schema_version`` is not decoration. A label is a claim about the
  features the analyst was shown; feedback collected across a schema change
  describes different inputs and must never be pooled into one training set.
* ``source`` separates a human verdict from an active-learning review and from a
  simulated one. V5's experiments compare adaptation driven by each, and a
  column is the only way to keep them separable after the fact.
* The self-supersede CHECK is cheap insurance: a row pointing at itself would
  make the active-set query non-terminating and the provenance chain circular.
* ``target_id`` is the primary key of the event, incident or sequence, not its
  public identifier. No foreign key is declared because the column is
  polymorphic across three tables; the API resolves and validates the target
  before a row is written.

The downgrade drops the table cleanly; the V4 schema is recoverable.
"""

from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

from alembic import op

revision = "0005_v5_adaptation"
down_revision = "0004_v4_evaluation"
branch_labels = None
depends_on = None

JSONType = sa.JSON().with_variant(JSONB, "postgresql")


def upgrade() -> None:
    op.create_table(
        "analyst_feedback",
        sa.Column("id", sa.Integer(), nullable=False),
        # What the claim is about.
        sa.Column("target_type", sa.String(length=16), nullable=False),
        sa.Column("target_id", sa.Integer(), nullable=False),
        # The claim itself.
        sa.Column("label", sa.String(length=32), nullable=False),
        sa.Column("confidence", sa.Float(), nullable=True),
        sa.Column("comment", sa.Text(), nullable=True),
        sa.Column("mitre_techniques", JSONType, nullable=False),
        sa.Column("evidence_reference", sa.String(length=512), nullable=True),
        # Provenance.
        sa.Column("analyst", sa.String(length=255), nullable=False),
        sa.Column("source", sa.String(length=32), nullable=False),
        sa.Column("feature_schema_version", sa.String(length=16), nullable=False),
        sa.Column("model_identity", sa.String(length=128), nullable=True),
        sa.Column("submitted_at", sa.DateTime(timezone=True), nullable=False),
        # Correction chain.
        sa.Column("supersedes_id", sa.Integer(), nullable=True),
        sa.Column("superseded_by_id", sa.Integer(), nullable=True),
        sa.Column("correction_reason", sa.Text(), nullable=True),
        sa.CheckConstraint(
            "confidence IS NULL OR (confidence >= 0.0 AND confidence <= 1.0)",
            name="ck_analyst_feedback_confidence_range",
        ),
        sa.CheckConstraint(
            "supersedes_id IS NULL OR supersedes_id <> id",
            name="ck_analyst_feedback_no_self_supersede",
        ),
        sa.ForeignKeyConstraint(["supersedes_id"], ["analyst_feedback.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["superseded_by_id"], ["analyst_feedback.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_analyst_feedback_label", "analyst_feedback", ["label"])
    op.create_index("ix_analyst_feedback_analyst", "analyst_feedback", ["analyst"])
    op.create_index("ix_analyst_feedback_submitted_at", "analyst_feedback", ["submitted_at"])
    op.create_index("ix_analyst_feedback_target", "analyst_feedback", ["target_type", "target_id"])
    op.create_index(
        "ix_analyst_feedback_active", "analyst_feedback", ["superseded_by_id", "label"]
    )


def downgrade() -> None:
    op.drop_index("ix_analyst_feedback_active", table_name="analyst_feedback")
    op.drop_index("ix_analyst_feedback_target", table_name="analyst_feedback")
    op.drop_index("ix_analyst_feedback_submitted_at", table_name="analyst_feedback")
    op.drop_index("ix_analyst_feedback_analyst", table_name="analyst_feedback")
    op.drop_index("ix_analyst_feedback_label", table_name="analyst_feedback")
    op.drop_table("analyst_feedback")
