"""V5: drift measurements.

Revision ID: 0007_v5_drift
Revises: 0006_v5_feedback_datasets
Create Date: 2026-09-03

One table. Notes on the choices that are not obvious:

* The **threshold bands are stored on the row**. A status of "significant" is a
  verdict, and a verdict without the bands that produced it is not
  interpretable months later - especially since the bands are configurable per
  deployment. Recording the conclusion while discarding its basis is exactly
  the provenance failure V4's rule 19 warns about.
* ``kind`` is explicit (data | prediction | concept) rather than implied by the
  feature name. The three support different conclusions: data and prediction
  drift are measurable without labels, concept drift is not, and reporting one
  as another turns "the input moved" into "the model is wrong" on evidence that
  never supported it.
* Both a primary and a secondary metric are stored. PSI drives the status
  because its bands are widely understood; the Wasserstein distance is kept
  beside it because it is in the units of the feature, and "the distribution
  moved by 4.2 connections" is actionable where "PSI 0.31" is not.
* ``baseline_label`` and ``window_label`` are free text, not foreign keys. "The
  window the model was fitted on" is a statement about provenance rather than a
  row that exists somewhere.
* No table here triggers anything. There is no column linking a reading to a
  retrain, because in V5 there is no such path.

The downgrade drops the table cleanly; the 0006 schema is recoverable.
"""

from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

from alembic import op

revision = "0007_v5_drift"
down_revision = "0006_v5_feedback_datasets"
branch_labels = None
depends_on = None

JSONType = sa.JSON().with_variant(JSONB, "postgresql")


def upgrade() -> None:
    op.create_table(
        "drift_measurements",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("kind", sa.String(length=16), nullable=False),
        sa.Column("feature", sa.String(length=128), nullable=False),
        sa.Column("baseline_label", sa.String(length=128), nullable=False),
        sa.Column("window_label", sa.String(length=128), nullable=False),
        sa.Column("metric_name", sa.String(length=32), nullable=False),
        sa.Column("metric_value", sa.Float(), nullable=False),
        sa.Column("secondary_metric_name", sa.String(length=32), nullable=True),
        sa.Column("secondary_metric_value", sa.Float(), nullable=True),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("moderate_threshold", sa.Float(), nullable=False),
        sa.Column("significant_threshold", sa.Float(), nullable=False),
        sa.Column("reference_samples", sa.Integer(), nullable=False),
        sa.Column("current_samples", sa.Integer(), nullable=False),
        sa.Column("detail", JSONType, nullable=False),
        sa.Column("model_identity", sa.String(length=128), nullable=True),
        sa.Column("measured_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "reference_samples >= 0 AND current_samples >= 0",
            name="ck_drift_measurement_samples",
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_drift_measurements_kind", "drift_measurements", ["kind"])
    op.create_index("ix_drift_measurements_feature", "drift_measurements", ["feature"])
    op.create_index("ix_drift_measurements_status", "drift_measurements", ["status"])
    op.create_index("ix_drift_measurements_measured_at", "drift_measurements", ["measured_at"])
    op.create_index(
        "ix_drift_measurements_feature_time", "drift_measurements", ["feature", "measured_at"]
    )


def downgrade() -> None:
    op.drop_index("ix_drift_measurements_feature_time", table_name="drift_measurements")
    op.drop_index("ix_drift_measurements_measured_at", table_name="drift_measurements")
    op.drop_index("ix_drift_measurements_status", table_name="drift_measurements")
    op.drop_index("ix_drift_measurements_feature", table_name="drift_measurements")
    op.drop_index("ix_drift_measurements_kind", table_name="drift_measurements")
    op.drop_table("drift_measurements")
