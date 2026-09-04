"""V9: bind evidence to the decisions taken on it.

One table. A row records what an incident's evidence looked like at the instant
a consequential decision was taken - the manifest digest, each item's digest and
integrity level, and which providers were unreachable at the time.

Nothing existing changes. No column is added to ``incidents``, no constraint is
widened, and no data is migrated: the table starts empty and fills as decisions
are taken from here on. **Decisions taken before this migration have no
binding, and that is reported as "not recorded" rather than as "unchanged"** -
the two are opposite facts and conflating them would be the worst possible
default for a control whose whole purpose is to say what a decision rested on.

The downgrade drops the table. That loses every recorded binding, which is
destructive but not ambiguous: there is no earlier schema these rows could be
folded into, and inventing one would be worse than admitting the loss.
"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision = "0013_v9_decision_evidence"
down_revision = "0012_v9_incident_lifecycle"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "decision_evidence_bindings",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("decision_ref", sa.String(length=64), nullable=False),
        sa.Column("decision_type", sa.String(length=64), nullable=False),
        sa.Column("incident_id", sa.Integer(), nullable=False),
        sa.Column("incident_ref", sa.String(length=32), nullable=False),
        sa.Column("from_state", sa.String(length=32), nullable=True),
        sa.Column("to_state", sa.String(length=32), nullable=False),
        sa.Column("reason", sa.Text(), nullable=True),
        sa.Column("decided_by", sa.String(length=255), nullable=False),
        sa.Column("decided_by_role", sa.String(length=32), nullable=True),
        sa.Column("decided_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("manifest_digest", sa.String(length=64), nullable=False),
        sa.Column("evidence_snapshot", sa.JSON(), nullable=False),
        sa.Column("evidence_count", sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(["incident_id"], ["incidents.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("decision_ref", name="uq_decision_bindings_ref"),
    )
    op.create_index(
        "ix_decision_evidence_bindings_decision_ref",
        "decision_evidence_bindings",
        ["decision_ref"],
    )
    op.create_index(
        "ix_decision_evidence_bindings_decision_type",
        "decision_evidence_bindings",
        ["decision_type"],
    )
    op.create_index(
        "ix_decision_evidence_bindings_incident_id",
        "decision_evidence_bindings",
        ["incident_id"],
    )
    op.create_index(
        "ix_decision_evidence_bindings_decided_at",
        "decision_evidence_bindings",
        ["decided_at"],
    )
    op.create_index(
        "ix_decision_evidence_bindings_manifest_digest",
        "decision_evidence_bindings",
        ["manifest_digest"],
    )
    # The two access paths: the incident's decision list, and one lookup.
    op.create_index(
        "ix_decision_bindings_incident_decided",
        "decision_evidence_bindings",
        ["incident_id", "decided_at"],
    )
    op.create_index(
        "ix_decision_bindings_ref", "decision_evidence_bindings", ["decision_ref"]
    )


def downgrade() -> None:
    op.drop_index("ix_decision_bindings_ref", table_name="decision_evidence_bindings")
    op.drop_index(
        "ix_decision_bindings_incident_decided", table_name="decision_evidence_bindings"
    )
    op.drop_index(
        "ix_decision_evidence_bindings_manifest_digest",
        table_name="decision_evidence_bindings",
    )
    op.drop_index(
        "ix_decision_evidence_bindings_decided_at",
        table_name="decision_evidence_bindings",
    )
    op.drop_index(
        "ix_decision_evidence_bindings_incident_id",
        table_name="decision_evidence_bindings",
    )
    op.drop_index(
        "ix_decision_evidence_bindings_decision_type",
        table_name="decision_evidence_bindings",
    )
    op.drop_index(
        "ix_decision_evidence_bindings_decision_ref",
        table_name="decision_evidence_bindings",
    )
    op.drop_table("decision_evidence_bindings")
