"""Queries over persisted evaluation results."""

from __future__ import annotations

from sqlalchemy import func, select
from sqlalchemy.orm import Session, selectinload

from app.models.evaluation import EvaluationDatasetRecord, Experiment, ExperimentRun
from app.repositories.base import BaseRepository


class EvaluationDatasetRepository(BaseRepository[EvaluationDatasetRecord]):
    def __init__(self) -> None:
        super().__init__(EvaluationDatasetRecord)

    def get_by_identity(
        self, db: Session, *, name: str, version: str, fingerprint: str
    ) -> EvaluationDatasetRecord | None:
        """Look up by full identity - fingerprint included.

        Two datasets sharing a name and version but not a fingerprint are
        different data, and must not resolve to the same row.
        """
        return db.scalar(
            select(EvaluationDatasetRecord).where(
                EvaluationDatasetRecord.name == name,
                EvaluationDatasetRecord.version == version,
                EvaluationDatasetRecord.fingerprint == fingerprint,
            )
        )

    def list_all(self, db: Session, *, limit: int = 100) -> list[EvaluationDatasetRecord]:
        return list(
            db.scalars(
                select(EvaluationDatasetRecord)
                .order_by(EvaluationDatasetRecord.created_at.desc())
                .limit(limit)
            )
        )


class ExperimentRepository(BaseRepository[Experiment]):
    def __init__(self) -> None:
        super().__init__(Experiment)

    def get_by_experiment_id(self, db: Session, experiment_id: str) -> Experiment | None:
        return db.scalar(
            select(Experiment)
            .where(Experiment.experiment_id == experiment_id)
            .options(selectinload(Experiment.runs), selectinload(Experiment.dataset))
        )

    def list_paginated(
        self,
        db: Session,
        *,
        dataset_name: str | None = None,
        detector_name: str | None = None,
        split_strategy: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> tuple[list[Experiment], int]:
        stmt = select(Experiment).join(Experiment.dataset)
        count_stmt = select(func.count()).select_from(Experiment).join(Experiment.dataset)

        if dataset_name:
            stmt = stmt.where(EvaluationDatasetRecord.name == dataset_name)
            count_stmt = count_stmt.where(EvaluationDatasetRecord.name == dataset_name)
        if detector_name:
            stmt = stmt.where(Experiment.detector_name == detector_name)
            count_stmt = count_stmt.where(Experiment.detector_name == detector_name)
        if split_strategy:
            stmt = stmt.where(Experiment.split_strategy == split_strategy)
            count_stmt = count_stmt.where(Experiment.split_strategy == split_strategy)

        total = int(db.scalar(count_stmt) or 0)
        items = list(
            db.scalars(
                stmt.options(selectinload(Experiment.runs), selectinload(Experiment.dataset))
                .order_by(Experiment.created_at.desc())
                .limit(limit)
                .offset(offset)
            )
        )
        return items, total

    def detector_names(self, db: Session) -> list[str]:
        return sorted(set(db.scalars(select(Experiment.detector_name))))


class ExperimentRunRepository(BaseRepository[ExperimentRun]):
    def __init__(self) -> None:
        super().__init__(ExperimentRun)

    def latest_for(self, db: Session, experiment_pk: int) -> ExperimentRun | None:
        return db.scalar(
            select(ExperimentRun)
            .where(ExperimentRun.experiment_id == experiment_pk)
            .order_by(ExperimentRun.executed_at.desc())
            .limit(1)
        )

    def runs_for(self, db: Session, experiment_pk: int) -> list[ExperimentRun]:
        return list(
            db.scalars(
                select(ExperimentRun)
                .where(ExperimentRun.experiment_id == experiment_pk)
                .order_by(ExperimentRun.executed_at.desc())
            )
        )


evaluation_datasets = EvaluationDatasetRepository()
experiments = ExperimentRepository()
experiment_runs = ExperimentRunRepository()
