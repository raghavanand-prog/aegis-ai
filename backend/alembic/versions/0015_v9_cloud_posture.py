"""V9 Phase G: cloud posture findings.

One table, `cloud_posture_findings`. A row is one check's verdict about one
resource, keyed by a stable `finding_id` derived from (check, resource) so that
rescanning updates the existing row rather than accumulating a duplicate every
night.

**Every row is simulated, and the column that says so is NOT NULL with no
server default.** AEGISX has never scanned a real cloud account: there is no
SDK in this project, no credential handling and no network call on the posture
path. A row that failed to state its own provenance would be the most
misleading record in the database, so the schema refuses to accept one.

Resource identity is stored **in parts** (provider, account, region, service,
resource_type, resource_id) with the canonical joined `resource_key` alongside.
Storing only the ARN would push parsing onto the query path and, worse, make
correlation depend on two implementations of "the same resource" agreeing.
`resource_key` is built from an already-parsed reference, never from raw input.

Nothing existing changes. No column is added to any table, no constraint is
widened, and no data is rewritten.

The downgrade drops the table. That loses every stored finding, which is
acceptable here in a way it would not be for a decision record: findings are
derived from configuration snapshots and are reproducible by rescanning, so the
loss is recoverable rather than a destroyed audit trail.
"""

from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

from alembic import op

#: Plain JSON on SQLite, JSONB on PostgreSQL - the same variant the models and
#: every other migration use. Declaring a bare `sa.JSON()` here would be a
#: no-op difference on SQLite and a real one on PostgreSQL, which is the exact
#: defect the Phase D/E migrations shipped with and PostgreSQL validation
#: caught.
JSONType = sa.JSON().with_variant(JSONB, "postgresql")

revision = "0015_v9_cloud_posture"
down_revision = "0014_v9_response_action_approval"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "cloud_posture_findings",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("finding_id", sa.String(length=32), nullable=False),
        sa.Column("check_id", sa.String(length=64), nullable=False),
        sa.Column("title", sa.String(length=255), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("severity", sa.String(length=16), nullable=False),
        sa.Column("control", sa.String(length=255), nullable=True),
        sa.Column("provider", sa.String(length=16), nullable=False),
        sa.Column("account", sa.String(length=64), nullable=False),
        sa.Column("region", sa.String(length=64), nullable=True),
        sa.Column("service", sa.String(length=64), nullable=False),
        sa.Column("resource_type", sa.String(length=128), nullable=False),
        sa.Column("resource_id", sa.String(length=512), nullable=False),
        sa.Column("resource_key", sa.String(length=1024), nullable=False),
        sa.Column("detail", JSONType, nullable=False),
        sa.Column("source_file", sa.String(length=255), nullable=True),
        # No server default. A finding must state whether it is simulated at
        # the moment it is written, by the code that knows.
        sa.Column("is_simulated", sa.Boolean(), nullable=False),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "severity IN ('Critical', 'High', 'Medium', 'Low')",
            name="ck_cloud_findings_severity",
        ),
        sa.CheckConstraint(
            "provider IN ('aws', 'azure', 'gcp')",
            name="ck_cloud_findings_provider",
        ),
    )
    op.create_index(
        "ix_cloud_posture_findings_finding_id",
        "cloud_posture_findings",
        ["finding_id"],
        unique=True,
    )
    op.create_index(
        "ix_cloud_posture_findings_check_id", "cloud_posture_findings", ["check_id"]
    )
    op.create_index(
        "ix_cloud_posture_findings_account", "cloud_posture_findings", ["account"]
    )
    # The correlation path: everything known about one resource.
    op.create_index(
        "ix_cloud_findings_resource", "cloud_posture_findings", ["resource_key"]
    )
    # The backlog view: one account's findings, worst first.
    op.create_index(
        "ix_cloud_findings_account_severity",
        "cloud_posture_findings",
        ["account", "severity"],
    )


def downgrade() -> None:
    op.drop_index("ix_cloud_findings_account_severity", table_name="cloud_posture_findings")
    op.drop_index("ix_cloud_findings_resource", table_name="cloud_posture_findings")
    op.drop_index("ix_cloud_posture_findings_account", table_name="cloud_posture_findings")
    op.drop_index("ix_cloud_posture_findings_check_id", table_name="cloud_posture_findings")
    op.drop_index("ix_cloud_posture_findings_finding_id", table_name="cloud_posture_findings")
    op.drop_table("cloud_posture_findings")
