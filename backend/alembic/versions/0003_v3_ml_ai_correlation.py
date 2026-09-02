"""V3: ML registry and inference, threat intelligence cache, correlated sequences, AI analyses.

Revision ID: 0003_v3_hybrid
Revises: 0002_v2_hardening
Create Date: 2026-09-02

Five new tables plus three columns on existing ones. Notes on the choices that
are not obvious:

* ``ml_models`` is unique on (name, version) because model versions are
  immutable. Every ``ml_inferences`` row names the version that produced it; if
  a version could be overwritten, every one of those rows would become
  uninterpretable.
* ``ml_inferences`` is unique on (event_id, model_name, model_version): an event
  is scored once per model version. Re-scoring with the same version would be a
  duplicate row, not new information.
* ``threat_intel_results`` is unique on (provider, ioc_type, ioc_value) because
  the row *is* the cache. ``expires_at`` is indexed since eviction scans it.
* ``events.risk_level`` is backfilled from the severity the rules already
  assigned, so V2 rows render sensibly in the V3 UI. ``risk_signals`` is left
  empty rather than reconstructed: those events were never scored by the V3
  strategy, and inventing a breakdown would explain a number nothing produced
  that way.
* No index is added to columns nothing queries. Every index below serves a query
  that exists in this release.

The downgrade drops all of it cleanly, including the backfilled columns - the
V2 schema is recoverable.
"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op
from app.models.base import JSONType

revision = "0003_v3_hybrid"
down_revision = "0002_v2_hardening"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # ----------------------------------------------------------- ml_models
    op.create_table(
        "ml_models",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("name", sa.String(length=64), nullable=False),
        sa.Column("version", sa.String(length=32), nullable=False),
        sa.Column("model_type", sa.String(length=64), nullable=False),
        sa.Column("feature_schema_version", sa.String(length=16), nullable=False),
        sa.Column("dataset_version", sa.String(length=32), nullable=False),
        sa.Column("dataset_fingerprint", sa.String(length=64), nullable=True),
        sa.Column("training_samples", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("parameters", JSONType, nullable=False),
        sa.Column("metrics", JSONType, nullable=False),
        sa.Column("feature_names", JSONType, nullable=False),
        sa.Column("artifact_path", sa.String(length=512), nullable=False),
        sa.Column("artifact_sha256", sa.String(length=64), nullable=True),
        sa.Column("status", sa.String(length=16), nullable=False, server_default="archived"),
        sa.Column("notes", sa.Text(), nullable=True),
        sa.Column("created_by", sa.String(length=120), nullable=False, server_default="system"),
        sa.Column("trained_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("activated_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("name", "version", name="uq_ml_model_name_version"),
        sa.CheckConstraint(
            "status IN ('active', 'archived', 'failed')", name="ck_ml_models_status"
        ),
    )
    op.create_index("ix_ml_models_name", "ml_models", ["name"])
    op.create_index("ix_ml_models_status", "ml_models", ["status"])
    op.create_index("ix_ml_models_name_status", "ml_models", ["name", "status"])
    op.create_index("ix_ml_models_created_at", "ml_models", ["created_at"])

    # ------------------------------------------------------- ml_inferences
    op.create_table(
        "ml_inferences",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column(
            "event_id",
            sa.Integer(),
            sa.ForeignKey("events.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("model_name", sa.String(length=64), nullable=False),
        sa.Column("model_version", sa.String(length=32), nullable=False),
        sa.Column("feature_schema_version", sa.String(length=16), nullable=False),
        sa.Column("anomaly_score", sa.Float(), nullable=False),
        sa.Column("is_anomaly", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("threshold", sa.Float(), nullable=False),
        sa.Column("features", JSONType, nullable=False),
        sa.Column("top_contributors", JSONType, nullable=False),
        sa.Column("latency_ms", sa.Float(), nullable=False, server_default="0"),
        sa.Column("inferred_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint(
            "event_id", "model_name", "model_version", name="uq_ml_inference_event"
        ),
        sa.CheckConstraint(
            "anomaly_score >= 0 AND anomaly_score <= 1", name="ck_ml_inferences_score"
        ),
    )
    op.create_index("ix_ml_inferences_event_id", "ml_inferences", ["event_id"])
    op.create_index("ix_ml_inferences_is_anomaly", "ml_inferences", ["is_anomaly"])
    op.create_index("ix_ml_inferences_inferred_at", "ml_inferences", ["inferred_at"])
    op.create_index(
        "ix_ml_inferences_anomaly_time", "ml_inferences", ["is_anomaly", "inferred_at"]
    )
    op.create_index("ix_ml_inferences_model", "ml_inferences", ["model_name", "model_version"])

    # ------------------------------------------------ threat_intel_results
    op.create_table(
        "threat_intel_results",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column(
            "ioc_id", sa.Integer(), sa.ForeignKey("iocs.id", ondelete="CASCADE"), nullable=True
        ),
        sa.Column("ioc_type", sa.String(length=32), nullable=False),
        sa.Column("ioc_value", sa.String(length=512), nullable=False),
        sa.Column("provider", sa.String(length=64), nullable=False),
        sa.Column("status", sa.String(length=24), nullable=False, server_default="unavailable"),
        sa.Column("reputation", sa.String(length=16), nullable=False, server_default="unknown"),
        sa.Column("confidence", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("malicious_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("suspicious_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("harmless_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("undetected_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("last_analysis_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("looked_up_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column("details", JSONType, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint(
            "provider", "ioc_type", "ioc_value", name="uq_ti_provider_indicator"
        ),
        sa.CheckConstraint(
            "reputation IN ('malicious', 'suspicious', 'harmless', 'unknown')",
            name="ck_ti_reputation",
        ),
        sa.CheckConstraint("confidence >= 0 AND confidence <= 100", name="ck_ti_confidence"),
    )
    op.create_index("ix_ti_ioc_id", "threat_intel_results", ["ioc_id"])
    op.create_index("ix_ti_ioc_value", "threat_intel_results", ["ioc_value"])
    op.create_index("ix_ti_provider", "threat_intel_results", ["provider"])
    op.create_index("ix_ti_reputation", "threat_intel_results", ["reputation"])
    op.create_index("ix_ti_looked_up_at", "threat_intel_results", ["looked_up_at"])
    op.create_index(
        "ix_ti_reputation_checked", "threat_intel_results", ["reputation", "looked_up_at"]
    )
    op.create_index("ix_ti_expires", "threat_intel_results", ["expires_at"])
    op.create_index("ix_ti_created_at", "threat_intel_results", ["created_at"])

    # --------------------------------------------------- security_sequences
    op.create_table(
        "security_sequences",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("sequence_id", sa.String(length=32), nullable=False),
        sa.Column("title", sa.String(length=255), nullable=False),
        sa.Column("description", sa.Text(), nullable=False, server_default=""),
        sa.Column("pattern", sa.String(length=64), nullable=False),
        sa.Column("correlation_key", sa.String(length=255), nullable=False),
        sa.Column("severity", sa.String(length=16), nullable=False, server_default="Medium"),
        sa.Column("status", sa.String(length=16), nullable=False, server_default="Open"),
        sa.Column("risk_score", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("confidence", sa.Float(), nullable=False, server_default="0"),
        sa.Column("start_time", sa.DateTime(timezone=True), nullable=False),
        sa.Column("end_time", sa.DateTime(timezone=True), nullable=False),
        sa.Column("event_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("techniques", JSONType, nullable=False),
        sa.Column("entities", JSONType, nullable=False),
        sa.Column("rationale", JSONType, nullable=False),
        sa.Column("risk_signals", JSONType, nullable=False),
        sa.Column(
            "incident_id",
            sa.Integer(),
            sa.ForeignKey("incidents.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("sequence_id", name="uq_sequences_sequence_id"),
        sa.CheckConstraint(
            "severity IN ('Low', 'Medium', 'High', 'Critical')", name="ck_sequences_severity"
        ),
        sa.CheckConstraint(
            "status IN ('Open', 'Promoted', 'Dismissed')", name="ck_sequences_status"
        ),
        sa.CheckConstraint(
            "risk_score >= 0 AND risk_score <= 100", name="ck_sequences_risk_score"
        ),
        sa.CheckConstraint("confidence >= 0 AND confidence <= 1", name="ck_sequences_confidence"),
    )
    op.create_index("ix_sequences_sequence_id", "security_sequences", ["sequence_id"])
    op.create_index("ix_sequences_pattern", "security_sequences", ["pattern"])
    op.create_index("ix_sequences_severity", "security_sequences", ["severity"])
    op.create_index("ix_sequences_status", "security_sequences", ["status"])
    op.create_index("ix_sequences_incident_id", "security_sequences", ["incident_id"])
    op.create_index("ix_sequences_created_at", "security_sequences", ["created_at"])
    op.create_index(
        "ix_sequences_status_created", "security_sequences", ["status", "created_at"]
    )
    op.create_index(
        "ix_sequences_pattern_key", "security_sequences", ["pattern", "correlation_key"]
    )

    op.create_table(
        "sequence_events",
        sa.Column(
            "sequence_id",
            sa.Integer(),
            sa.ForeignKey("security_sequences.id", ondelete="CASCADE"),
            primary_key=True,
        ),
        sa.Column(
            "event_id",
            sa.Integer(),
            sa.ForeignKey("events.id", ondelete="CASCADE"),
            primary_key=True,
        ),
    )

    # -------------------------------------------------------- ai_analyses
    op.create_table(
        "ai_analyses",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column(
            "incident_id",
            sa.Integer(),
            sa.ForeignKey("incidents.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("kind", sa.String(length=16), nullable=False, server_default="analyze"),
        sa.Column("provider", sa.String(length=32), nullable=False),
        sa.Column("model", sa.String(length=120), nullable=False, server_default=""),
        sa.Column("prompt_version", sa.String(length=16), nullable=False),
        sa.Column("analysis_version", sa.String(length=16), nullable=False),
        sa.Column("summary", sa.Text(), nullable=False, server_default=""),
        sa.Column("why_it_matters", sa.Text(), nullable=False, server_default=""),
        sa.Column("risk_assessment", sa.Text(), nullable=False, server_default=""),
        sa.Column("likely_behaviour", sa.Text(), nullable=False, server_default=""),
        sa.Column("supporting_evidence", JSONType, nullable=False),
        sa.Column("mitre_techniques", JSONType, nullable=False),
        sa.Column("investigation_steps", JSONType, nullable=False),
        sa.Column("containment_actions", JSONType, nullable=False),
        sa.Column("confidence", sa.String(length=32), nullable=False, server_default="unknown"),
        sa.Column("uncertainty", sa.Text(), nullable=False, server_default=""),
        sa.Column(
            "evidence_fingerprint", sa.String(length=64), nullable=False, server_default=""
        ),
        sa.Column("evidence_summary", JSONType, nullable=False),
        sa.Column("grounded", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("grounding_warnings", JSONType, nullable=False),
        sa.Column("raw_response", sa.Text(), nullable=True),
        sa.Column("latency_ms", sa.Float(), nullable=False, server_default="0"),
        sa.Column("tokens_used", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("requested_by", sa.String(length=255), nullable=False, server_default="system"),
        sa.Column(
            "requested_by_id",
            sa.Integer(),
            sa.ForeignKey("users.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "kind IN ('analyze', 'explain', 'recommend')", name="ck_ai_analyses_kind"
        ),
    )
    op.create_index("ix_ai_analyses_incident_id", "ai_analyses", ["incident_id"])
    op.create_index("ix_ai_analyses_created_at", "ai_analyses", ["created_at"])
    op.create_index(
        "ix_ai_analyses_incident_created", "ai_analyses", ["incident_id", "created_at"]
    )

    # ------------------------------------------------- columns on V2 tables
    # Added NOT NULL with a server default in one statement. SQLite cannot
    # ALTER a column's nullability, so adding-then-tightening would make this
    # migration PostgreSQL-only and stop the test suite from exercising it.
    op.add_column(
        "events",
        sa.Column("risk_signals", JSONType, nullable=False, server_default="[]"),
    )
    op.add_column(
        "events",
        sa.Column(
            "risk_level", sa.String(length=16), nullable=False, server_default="Low"
        ),
    )
    op.add_column(
        "incidents",
        sa.Column("risk_signals", JSONType, nullable=False, server_default="[]"),
    )

    # Backfill so V2 rows render sensibly in the V3 UI. `risk_level` mirrors the
    # severity the rules already assigned. `risk_signals` stays an empty list
    # rather than being reconstructed from the stored detections: a V2 event was
    # never scored by the V3 strategy, and inventing a breakdown for it would be
    # a fabricated explanation of a number nothing produced that way.
    op.execute("UPDATE events SET risk_level = severity")

    # The correlation window queries scan one entity column ordered by time.
    op.create_index("ix_events_username_timestamp", "events", ["username", "timestamp"])
    op.create_index("ix_events_sourceip_timestamp", "events", ["source_ip", "timestamp"])


def downgrade() -> None:
    op.drop_index("ix_events_sourceip_timestamp", table_name="events")
    op.drop_index("ix_events_username_timestamp", table_name="events")

    op.drop_column("incidents", "risk_signals")
    op.drop_column("events", "risk_level")
    op.drop_column("events", "risk_signals")

    op.drop_index("ix_ai_analyses_incident_created", table_name="ai_analyses")
    op.drop_index("ix_ai_analyses_created_at", table_name="ai_analyses")
    op.drop_index("ix_ai_analyses_incident_id", table_name="ai_analyses")
    op.drop_table("ai_analyses")

    op.drop_table("sequence_events")
    for index in (
        "ix_sequences_pattern_key",
        "ix_sequences_status_created",
        "ix_sequences_created_at",
        "ix_sequences_incident_id",
        "ix_sequences_status",
        "ix_sequences_severity",
        "ix_sequences_pattern",
        "ix_sequences_sequence_id",
    ):
        op.drop_index(index, table_name="security_sequences")
    op.drop_table("security_sequences")

    for index in (
        "ix_ti_created_at",
        "ix_ti_expires",
        "ix_ti_reputation_checked",
        "ix_ti_looked_up_at",
        "ix_ti_reputation",
        "ix_ti_provider",
        "ix_ti_ioc_value",
        "ix_ti_ioc_id",
    ):
        op.drop_index(index, table_name="threat_intel_results")
    op.drop_table("threat_intel_results")

    for index in (
        "ix_ml_inferences_model",
        "ix_ml_inferences_anomaly_time",
        "ix_ml_inferences_inferred_at",
        "ix_ml_inferences_is_anomaly",
        "ix_ml_inferences_event_id",
    ):
        op.drop_index(index, table_name="ml_inferences")
    op.drop_table("ml_inferences")

    for index in (
        "ix_ml_models_created_at",
        "ix_ml_models_name_status",
        "ix_ml_models_status",
        "ix_ml_models_name",
    ):
        op.drop_index(index, table_name="ml_models")
    op.drop_table("ml_models")
