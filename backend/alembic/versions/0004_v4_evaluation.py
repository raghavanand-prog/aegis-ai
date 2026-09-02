"""V4: persisted evaluation datasets, experiments and runs.

Revision ID: 0004_v4_evaluation
Revises: 0003_v3_hybrid
Create Date: 2026-09-02

Three tables. Notes on the choices that are not obvious:

* ``evaluation_datasets`` is unique on (name, version, **fingerprint**). Two
  loads of "unsw-nb15 v1.0" whose contents hash differently are not the same
  data, and pooling results across them would compare numbers that were never
  comparable. The fingerprint is part of the identity, not a detail.
* ``evaluation_experiments`` is unique on ``experiment_id``, which is a hash of
  the configuration. Re-running an identical setup updates one row instead of
  accumulating indistinguishable duplicates; a changed setup gets a new id and
  therefore cannot silently overwrite an earlier result.
* ``evaluation_runs`` is a separate table rather than columns on the experiment
  because repeated seeds are what every variance and confidence-interval claim
  rests on. One row per execution.
* Metric columns are **nullable** and CHECK-constrained to [0, 1] where bounded.
  Nullable is the point: precision with no predictions is undefined, and storing
  0 there would record a measurement that was never made.
* Sweeps, per-class breakdowns and normalized matrices stay in JSON columns.
  They are read whole and never filtered on, so four more tables and a join
  would serve no query. The archival JSON report remains the artifact; these
  rows are the index over it.
* No index is added that no query uses. The three here serve experiment lookup
  by id, listing by detector, and a dataset's experiments.

The downgrade drops all three cleanly; the V3 schema is recoverable.
"""

from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

from alembic import op

revision = "0004_v4_evaluation"
down_revision = "0003_v3_hybrid"
branch_labels = None
depends_on = None

JSONType = sa.JSON().with_variant(JSONB, "postgresql")


def upgrade() -> None:
    op.create_table(
        "evaluation_datasets",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("name", sa.String(length=64), nullable=False),
        sa.Column("version", sa.String(length=32), nullable=False),
        sa.Column("fingerprint", sa.String(length=32), nullable=False),
        sa.Column("source", sa.String(length=512), nullable=True),
        sa.Column("license", sa.Text(), nullable=True),
        sa.Column("citation", sa.Text(), nullable=True),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("total_samples", sa.Integer(), nullable=False),
        sa.Column("malicious_samples", sa.Integer(), nullable=False),
        sa.Column("benign_samples", sa.Integer(), nullable=False),
        sa.Column("distinct_groups", sa.Integer(), nullable=True),
        sa.Column("card", JSONType, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "name", "version", "fingerprint", name="uq_evaluation_dataset_identity"
        ),
    )
    op.create_index(
        "ix_evaluation_datasets_name", "evaluation_datasets", ["name"], unique=False
    )
    op.create_index(
        "ix_evaluation_datasets_created_at",
        "evaluation_datasets",
        ["created_at"],
        unique=False,
    )

    op.create_table(
        "evaluation_experiments",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("experiment_id", sa.String(length=32), nullable=False),
        sa.Column("dataset_id", sa.Integer(), nullable=False),
        sa.Column("detector_name", sa.String(length=64), nullable=False),
        sa.Column("detector_kind", sa.String(length=64), nullable=False),
        sa.Column("score_kind", sa.String(length=128), nullable=False),
        sa.Column("split_strategy", sa.String(length=32), nullable=False),
        sa.Column("split_fingerprint", sa.String(length=32), nullable=False),
        sa.Column("split_seed", sa.Integer(), nullable=False),
        sa.Column("feature_schema_version", sa.String(length=16), nullable=False),
        sa.Column("ruleset_fingerprint", sa.String(length=32), nullable=True),
        sa.Column("model_name", sa.String(length=64), nullable=True),
        sa.Column("model_version", sa.String(length=32), nullable=True),
        sa.Column("model_artifact_sha256", sa.String(length=64), nullable=True),
        sa.Column("objective", sa.String(length=32), nullable=True),
        sa.Column("detector_config", JSONType, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["dataset_id"], ["evaluation_datasets.id"], ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("experiment_id", name="uq_evaluation_experiment_id"),
    )
    op.create_index(
        "ix_evaluation_experiments_detector",
        "evaluation_experiments",
        ["detector_name"],
        unique=False,
    )
    op.create_index(
        "ix_evaluation_experiments_dataset",
        "evaluation_experiments",
        ["dataset_id"],
        unique=False,
    )
    op.create_index(
        "ix_evaluation_experiments_created_at",
        "evaluation_experiments",
        ["created_at"],
        unique=False,
    )

    op.create_table(
        "evaluation_runs",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("experiment_id", sa.Integer(), nullable=False),
        sa.Column("seed", sa.Integer(), nullable=False),
        sa.Column("executed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("threshold", sa.Float(), nullable=False),
        sa.Column("threshold_selection", JSONType, nullable=False),
        sa.Column("true_positives", sa.Integer(), nullable=False),
        sa.Column("true_negatives", sa.Integer(), nullable=False),
        sa.Column("false_positives", sa.Integer(), nullable=False),
        sa.Column("false_negatives", sa.Integer(), nullable=False),
        sa.Column("precision", sa.Float(), nullable=True),
        sa.Column("recall", sa.Float(), nullable=True),
        sa.Column("f1", sa.Float(), nullable=True),
        sa.Column("specificity", sa.Float(), nullable=True),
        sa.Column("accuracy", sa.Float(), nullable=True),
        sa.Column("false_positive_rate", sa.Float(), nullable=True),
        sa.Column("false_negative_rate", sa.Float(), nullable=True),
        sa.Column("mcc", sa.Float(), nullable=True),
        sa.Column("balanced_accuracy", sa.Float(), nullable=True),
        sa.Column("roc_auc", sa.Float(), nullable=True),
        sa.Column("pr_auc", sa.Float(), nullable=True),
        sa.Column("alerts", sa.Integer(), nullable=True),
        sa.Column("alerts_per_thousand", sa.Float(), nullable=True),
        sa.Column("latency_mean_ms", sa.Float(), nullable=True),
        sa.Column("latency_p95_ms", sa.Float(), nullable=True),
        sa.Column("confusion_normalized", JSONType, nullable=False),
        sa.Column("per_class", JSONType, nullable=False),
        sa.Column("threshold_sweep", JSONType, nullable=False),
        sa.Column("validation_metrics", JSONType, nullable=True),
        sa.Column("leakage_audit", JSONType, nullable=True),
        sa.Column("environment", JSONType, nullable=False),
        sa.Column("notes", JSONType, nullable=False),
        sa.Column("report_path", sa.String(length=512), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["experiment_id"], ["evaluation_experiments.id"], ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.CheckConstraint(
            "true_positives >= 0 AND true_negatives >= 0 "
            "AND false_positives >= 0 AND false_negatives >= 0",
            name="ck_evaluation_runs_counts_non_negative",
        ),
        sa.CheckConstraint(
            "precision IS NULL OR (precision >= 0 AND precision <= 1)",
            name="ck_evaluation_runs_precision_range",
        ),
        sa.CheckConstraint(
            "recall IS NULL OR (recall >= 0 AND recall <= 1)",
            name="ck_evaluation_runs_recall_range",
        ),
    )
    op.create_index(
        "ix_evaluation_runs_experiment",
        "evaluation_runs",
        ["experiment_id", "executed_at"],
        unique=False,
    )
    op.create_index(
        "ix_evaluation_runs_created_at", "evaluation_runs", ["created_at"], unique=False
    )


def downgrade() -> None:
    op.drop_index("ix_evaluation_runs_created_at", table_name="evaluation_runs")
    op.drop_index("ix_evaluation_runs_experiment", table_name="evaluation_runs")
    op.drop_table("evaluation_runs")

    op.drop_index(
        "ix_evaluation_experiments_created_at", table_name="evaluation_experiments"
    )
    op.drop_index(
        "ix_evaluation_experiments_dataset", table_name="evaluation_experiments"
    )
    op.drop_index(
        "ix_evaluation_experiments_detector", table_name="evaluation_experiments"
    )
    op.drop_table("evaluation_experiments")

    op.drop_index("ix_evaluation_datasets_created_at", table_name="evaluation_datasets")
    op.drop_index("ix_evaluation_datasets_name", table_name="evaluation_datasets")
    op.drop_table("evaluation_datasets")
