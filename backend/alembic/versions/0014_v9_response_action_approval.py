"""V9: response action requests and their approvals.

One table. A row records a request for a containment action, and - once a
second authorised person decides - the decision and a reference to the evidence
binding that approval was taken on.

**No execution columns.** There is no provider, no execution record and no
result, because V9 has no executor. Adding the columns "ready for later" would
put a field in the schema that nothing can honestly populate, and the first
person to see `status = approved` next to an empty `executed_at` would have to
guess which of the two the system meant.

Nothing existing changes: no column is added to `incidents`, no constraint is
widened, and the evidence binding this points at is the same
`decision_evidence_bindings` row a lifecycle decision produces. The FK is
`ON DELETE SET NULL` rather than CASCADE - losing the binding must not delete
the record that a containment action was approved.

The downgrade drops the table, which loses every recorded request and
approval. Destructive but unambiguous: there is no earlier schema these rows
could fold into, and inventing one would be worse than admitting the loss.
"""

from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

from alembic import op

#: The same JSON variant every other migration and the models use: plain JSON on
#: SQLite, JSONB on PostgreSQL. **The first cut of this migration declared a bare
#: JSON column**, which is a no-op difference on SQLite and a real one on
#: PostgreSQL: the column came out `json`, losing GIN indexing and the
#: containment operators, while the model declared `jsonb`. Only the PostgreSQL
#: validation could catch it, and it did.
JSONType = sa.JSON().with_variant(JSONB, "postgresql")

revision = "0014_v9_response_action_approval"
down_revision = "0013_v9_decision_evidence"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "response_action_requests",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("request_ref", sa.String(length=64), nullable=False),
        sa.Column("incident_id", sa.Integer(), nullable=False),
        sa.Column("incident_ref", sa.String(length=32), nullable=False),
        sa.Column("action_type", sa.String(length=32), nullable=False),
        sa.Column("parameters", JSONType, nullable=False),
        sa.Column("parameters_digest", sa.String(length=64), nullable=False),
        sa.Column("justification", sa.Text(), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("requested_by", sa.String(length=255), nullable=False),
        sa.Column("requested_by_role", sa.String(length=32), nullable=True),
        sa.Column("requested_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("decided_by", sa.String(length=255), nullable=True),
        sa.Column("decided_by_role", sa.String(length=32), nullable=True),
        sa.Column("decided_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("decision_reason", sa.Text(), nullable=True),
        sa.Column("evidence_binding_id", sa.Integer(), nullable=True),
        sa.ForeignKeyConstraint(["incident_id"], ["incidents.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(
            ["evidence_binding_id"],
            ["decision_evidence_bindings.id"],
            ondelete="SET NULL",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("request_ref", name="uq_response_requests_ref"),
        sa.CheckConstraint(
            "status IN ('requested', 'approved', 'rejected', 'withdrawn')",
            name="ck_response_requests_status",
        ),
    )
    op.create_index(
        "ix_response_action_requests_request_ref",
        "response_action_requests",
        ["request_ref"],
    )
    op.create_index(
        "ix_response_action_requests_incident_id",
        "response_action_requests",
        ["incident_id"],
    )
    op.create_index(
        "ix_response_action_requests_action_type",
        "response_action_requests",
        ["action_type"],
    )
    op.create_index(
        "ix_response_action_requests_status", "response_action_requests", ["status"]
    )
    op.create_index(
        "ix_response_action_requests_requested_at",
        "response_action_requests",
        ["requested_at"],
    )
    op.create_index(
        "ix_response_requests_incident_created",
        "response_action_requests",
        ["incident_id", "requested_at"],
    )
    op.create_index(
        "ix_response_requests_status_created",
        "response_action_requests",
        ["status", "requested_at"],
    )


def downgrade() -> None:
    for index in (
        "ix_response_requests_status_created",
        "ix_response_requests_incident_created",
        "ix_response_action_requests_requested_at",
        "ix_response_action_requests_status",
        "ix_response_action_requests_action_type",
        "ix_response_action_requests_incident_id",
        "ix_response_action_requests_request_ref",
    ):
        op.drop_index(index, table_name="response_action_requests")
    op.drop_table("response_action_requests")
