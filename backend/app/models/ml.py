"""Machine learning model registry and inference records.

Two tables, two purposes:

``MLModel``
    What was trained, from what, with which hyperparameters, and how it scored.
    One row per (name, version). Versions are never overwritten - activating a
    new one archives the old, which is what makes a rollback possible.

``MLInference``
    What the active model said about one specific event. Every row names the
    model version and feature schema version that produced it, so a stored
    score stays interpretable after the model has moved on. This is the table
    V4 experiments read from.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, JSONType, TimestampMixin, utcnow
from app.models.enums import MLModelStatus


class MLModel(Base, TimestampMixin):
    """A trained model artifact and everything needed to reproduce it."""

    __tablename__ = "ml_models"
    __table_args__ = (
        UniqueConstraint("name", "version", name="uq_ml_model_name_version"),
        Index("ix_ml_models_name_status", "name", "status"),
        CheckConstraint(
            "status IN ('active', 'archived', 'failed', 'candidate', "
            "'evaluating', 'approved', 'rejected', 'rolled_back')",
            name="ck_ml_models_status"
        ),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    version: Mapped[str] = mapped_column(String(32), nullable=False)
    model_type: Mapped[str] = mapped_column(String(64), nullable=False)

    # --- Reproducibility ---------------------------------------------------
    # Together these answer "what exactly produced this artifact". A score
    # recorded against a feature schema version that no longer exists is a
    # score you must not compare against today's numbers.
    feature_schema_version: Mapped[str] = mapped_column(String(16), nullable=False)
    dataset_version: Mapped[str] = mapped_column(String(32), nullable=False)
    dataset_fingerprint: Mapped[str | None] = mapped_column(String(64), nullable=True)
    training_samples: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    parameters: Mapped[dict] = mapped_column(JSONType, default=dict, nullable=False)
    #: Measured on held-out data by the training run. Empty when the run could
    #: not measure anything meaningful - never filled with a plausible number.
    metrics: Mapped[dict] = mapped_column(JSONType, default=dict, nullable=False)
    feature_names: Mapped[list] = mapped_column(JSONType, default=list, nullable=False)

    artifact_path: Mapped[str] = mapped_column(String(512), nullable=False)
    artifact_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)

    status: Mapped[str] = mapped_column(
        String(16), default=MLModelStatus.ARCHIVED.value, nullable=False, index=True
    )
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_by: Mapped[str] = mapped_column(String(120), default="system", nullable=False)
    trained_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )
    activated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    @property
    def identity(self) -> str:
        return f"{self.name}@{self.version}"

    def __repr__(self) -> str:  # pragma: no cover
        return f"<MLModel {self.identity} {self.status}>"


class MLInference(Base):
    """One model's verdict on one event."""

    __tablename__ = "ml_inferences"
    __table_args__ = (
        # An event is scored once per model version; re-scoring with the same
        # version would be a duplicate, not new information.
        UniqueConstraint("event_id", "model_name", "model_version", name="uq_ml_inference_event"),
        Index("ix_ml_inferences_anomaly_time", "is_anomaly", "inferred_at"),
        Index("ix_ml_inferences_model", "model_name", "model_version"),
        CheckConstraint(
            "anomaly_score >= 0 AND anomaly_score <= 1", name="ck_ml_inferences_score"
        ),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    event_id: Mapped[int] = mapped_column(
        ForeignKey("events.id", ondelete="CASCADE"), nullable=False, index=True
    )

    model_name: Mapped[str] = mapped_column(String(64), nullable=False)
    model_version: Mapped[str] = mapped_column(String(32), nullable=False)
    feature_schema_version: Mapped[str] = mapped_column(String(16), nullable=False)

    #: Normalized 0..1, higher means more anomalous. This is an ANOMALY SCORE,
    #: not a probability and not a confidence - see docs/ml-architecture.md.
    anomaly_score: Mapped[float] = mapped_column(Float, nullable=False)
    is_anomaly: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False, index=True)
    #: The threshold in force when this row was written, so a later threshold
    #: change does not silently rewrite history.
    threshold: Mapped[float] = mapped_column(Float, nullable=False)

    features: Mapped[dict] = mapped_column(JSONType, default=dict, nullable=False)
    #: The features that pushed this event furthest from the norm, with the
    #: direction of the deviation. This is what the UI shows an analyst.
    top_contributors: Mapped[list] = mapped_column(JSONType, default=list, nullable=False)

    latency_ms: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    inferred_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False, index=True
    )

    event = relationship("Event", back_populates="ml_inferences")

    def __repr__(self) -> str:  # pragma: no cover
        return f"<MLInference event={self.event_id} score={self.anomaly_score:.3f}>"
