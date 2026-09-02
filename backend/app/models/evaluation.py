"""Persisted evaluation results (V4).

V3 kept evaluation output as JSON files on disk. That is fine for one report
read by one endpoint, and it stops being fine as soon as results must be
*compared*: "is this hybrid better than last week's, on the same data, at the
same threshold" is a query, and answering it by parsing a directory of files is
how provenance quietly gets lost.

Three tables, and deliberately only three:

``EvaluationDataset``
    One row per (name, version, fingerprint). The fingerprint is part of the
    identity because two loads of "unsw-nb15 v1.0" that hash differently are
    not the same data and results across them must never be pooled.

``Experiment``
    One configuration: dataset + split + detector + threshold policy. Its
    ``experiment_id`` is a hash of that configuration, so re-running the same
    setup lands on the same row and a changed setup cannot silently overwrite
    an earlier result.

``ExperimentRun``
    One execution of an experiment, with its metrics. Separate from
    ``Experiment`` because repeated seeds are the basis of every variance and
    confidence-interval claim, and collapsing them would throw that away.

**What is deliberately NOT in the database.** Threshold sweeps, per-class
breakdowns, confusion matrices and the full result document stay as JSON
columns on the run rather than becoming their own tables. They are read as
whole documents, never queried field by field, and normalising them would add
four tables and a join for no query anyone makes. The file report remains the
archival artifact; these rows are the index over it.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import (
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


class EvaluationDatasetRecord(Base, TimestampMixin):
    """A dataset version actually used to produce a result."""

    __tablename__ = "evaluation_datasets"
    __table_args__ = (
        UniqueConstraint(
            "name", "version", "fingerprint", name="uq_evaluation_dataset_identity"
        ),
        Index("ix_evaluation_datasets_name", "name"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(64), nullable=False)
    version: Mapped[str] = mapped_column(String(32), nullable=False)
    #: Hash over sample identity, label and grouping. Part of the identity.
    fingerprint: Mapped[str] = mapped_column(String(32), nullable=False)

    source: Mapped[str | None] = mapped_column(String(512))
    license: Mapped[str | None] = mapped_column(Text)
    citation: Mapped[str | None] = mapped_column(Text)
    description: Mapped[str | None] = mapped_column(Text)

    total_samples: Mapped[int] = mapped_column(Integer, nullable=False)
    malicious_samples: Mapped[int] = mapped_column(Integer, nullable=False)
    benign_samples: Mapped[int] = mapped_column(Integer, nullable=False)
    distinct_groups: Mapped[int | None] = mapped_column(Integer)

    #: Full dataset card fragment: class counts, provenance, label schema,
    #: sampling. Read whole, never filtered on.
    card: Mapped[dict] = mapped_column(JSONType, default=dict, nullable=False)

    experiments: Mapped[list[Experiment]] = relationship(
        back_populates="dataset", cascade="all, delete-orphan"
    )

    @property
    def identity(self) -> str:
        return f"{self.name}@{self.version}[{self.fingerprint}]"


class Experiment(Base, TimestampMixin):
    """One evaluation configuration, identified by a hash of itself."""

    __tablename__ = "evaluation_experiments"
    __table_args__ = (
        UniqueConstraint("experiment_id", name="uq_evaluation_experiment_id"),
        Index("ix_evaluation_experiments_detector", "detector_name"),
        Index("ix_evaluation_experiments_dataset", "dataset_id"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    #: ``EXP-<16 hex>``: a hash of dataset, split, detector and objective. The
    #: same configuration always produces the same value.
    experiment_id: Mapped[str] = mapped_column(String(32), nullable=False)

    dataset_id: Mapped[int] = mapped_column(
        ForeignKey("evaluation_datasets.id", ondelete="CASCADE"), nullable=False
    )

    detector_name: Mapped[str] = mapped_column(String(64), nullable=False)
    detector_kind: Mapped[str] = mapped_column(String(64), nullable=False)
    #: "anomaly_score (ranking, NOT a probability)" and friends. Stored so a
    #: consumer can never mistake one kind of number for another.
    score_kind: Mapped[str] = mapped_column(String(128), nullable=False)

    split_strategy: Mapped[str] = mapped_column(String(32), nullable=False)
    split_fingerprint: Mapped[str] = mapped_column(String(32), nullable=False)
    split_seed: Mapped[int] = mapped_column(Integer, nullable=False)

    #: Provenance of everything that could change a number.
    feature_schema_version: Mapped[str] = mapped_column(String(16), nullable=False)
    ruleset_fingerprint: Mapped[str | None] = mapped_column(String(32))
    model_name: Mapped[str | None] = mapped_column(String(64))
    model_version: Mapped[str | None] = mapped_column(String(32))
    model_artifact_sha256: Mapped[str | None] = mapped_column(String(64))

    objective: Mapped[str | None] = mapped_column(String(32))
    detector_config: Mapped[dict] = mapped_column(JSONType, default=dict, nullable=False)

    dataset: Mapped[EvaluationDatasetRecord] = relationship(back_populates="experiments")
    runs: Mapped[list[ExperimentRun]] = relationship(
        back_populates="experiment",
        cascade="all, delete-orphan",
        order_by="ExperimentRun.executed_at.desc()",
    )


class ExperimentRun(Base, TimestampMixin):
    """One execution of one experiment, with its measured results."""

    __tablename__ = "evaluation_runs"
    __table_args__ = (
        Index("ix_evaluation_runs_experiment", "experiment_id", "executed_at"),
        CheckConstraint(
            "true_positives >= 0 AND true_negatives >= 0 "
            "AND false_positives >= 0 AND false_negatives >= 0",
            name="ck_evaluation_runs_counts_non_negative",
        ),
        CheckConstraint(
            "precision IS NULL OR (precision >= 0 AND precision <= 1)",
            name="ck_evaluation_runs_precision_range",
        ),
        CheckConstraint(
            "recall IS NULL OR (recall >= 0 AND recall <= 1)",
            name="ck_evaluation_runs_recall_range",
        ),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    experiment_id: Mapped[int] = mapped_column(
        ForeignKey("evaluation_experiments.id", ondelete="CASCADE"), nullable=False
    )

    seed: Mapped[int] = mapped_column(Integer, nullable=False)
    executed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )

    #: The threshold in force for the reported metrics, and how it was chosen.
    threshold: Mapped[float] = mapped_column(Float, nullable=False)
    threshold_selection: Mapped[dict] = mapped_column(
        JSONType, default=dict, nullable=False
    )

    # --- Test-split confusion matrix -------------------------------------
    # Columnar rather than JSON-only because these four numbers are what
    # experiment comparison actually sorts and filters on.
    true_positives: Mapped[int] = mapped_column(Integer, nullable=False)
    true_negatives: Mapped[int] = mapped_column(Integer, nullable=False)
    false_positives: Mapped[int] = mapped_column(Integer, nullable=False)
    false_negatives: Mapped[int] = mapped_column(Integer, nullable=False)

    # Nullable on purpose: an undefined metric (precision with no predictions)
    # is NULL, never 0. A zero here would be a measurement that was never made.
    precision: Mapped[float | None] = mapped_column(Float)
    recall: Mapped[float | None] = mapped_column(Float)
    f1: Mapped[float | None] = mapped_column(Float)
    specificity: Mapped[float | None] = mapped_column(Float)
    accuracy: Mapped[float | None] = mapped_column(Float)
    false_positive_rate: Mapped[float | None] = mapped_column(Float)
    false_negative_rate: Mapped[float | None] = mapped_column(Float)
    mcc: Mapped[float | None] = mapped_column(Float)
    balanced_accuracy: Mapped[float | None] = mapped_column(Float)
    roc_auc: Mapped[float | None] = mapped_column(Float)
    pr_auc: Mapped[float | None] = mapped_column(Float)

    alerts: Mapped[int | None] = mapped_column(Integer)
    alerts_per_thousand: Mapped[float | None] = mapped_column(Float)
    latency_mean_ms: Mapped[float | None] = mapped_column(Float)
    latency_p95_ms: Mapped[float | None] = mapped_column(Float)

    #: Read-whole documents. See the module docstring for why these are not
    #: their own tables.
    confusion_normalized: Mapped[dict] = mapped_column(
        JSONType, default=dict, nullable=False
    )
    per_class: Mapped[dict] = mapped_column(JSONType, default=dict, nullable=False)
    threshold_sweep: Mapped[list] = mapped_column(JSONType, default=list, nullable=False)
    validation_metrics: Mapped[dict | None] = mapped_column(JSONType)
    leakage_audit: Mapped[dict | None] = mapped_column(JSONType)
    environment: Mapped[dict] = mapped_column(JSONType, default=dict, nullable=False)
    notes: Mapped[list] = mapped_column(JSONType, default=list, nullable=False)

    #: Path of the archival JSON report this run was ingested from, when there
    #: is one. The file is the artifact; this row is the index.
    report_path: Mapped[str | None] = mapped_column(String(512))

    experiment: Mapped[Experiment] = relationship(back_populates="runs")
