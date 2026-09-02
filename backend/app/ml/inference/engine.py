"""Inference engine.

The single entry point the ingestion pipeline uses to ask "is this event
unusual". Everything about it is built around one requirement: **the SOC keeps
working when the answer is 'I cannot tell you'.**

* No active model registered -> returns ``None``.
* Artifact missing, corrupt, or with a digest that no longer matches the
  registry -> logs it once, returns ``None``.
* Feature schema mismatch between the loaded model and the running code ->
  refuses to score, returns ``None``. Scoring a vector the model was never
  fitted on would produce a confident number that means nothing.
* Anything unexpected during scoring -> caught, counted, returns ``None``.

``None`` is a first-class answer here, not an error condition. Rule detection,
persistence, notification and the live stream all continue untouched.

The engine is a process-wide singleton because the behavioural context it
carries is a rolling picture of the estate: splitting it per request would
throw away exactly the history the features depend on.
"""

from __future__ import annotations

import logging
import threading
from datetime import datetime, timezone
from pathlib import Path
from time import perf_counter
from typing import Any

from sqlalchemy.orm import Session

from app.core.config import settings
from app.ml.features import FEATURE_NAMES, FeatureExtractor
from app.ml.models.isolation_forest import (
    MODEL_NAME,
    IsolationForestDetector,
    ModelUnavailable,
)
from app.ml.registry import registry
from app.ml.schemas import FEATURE_SCHEMA_VERSION, InferenceResult

logger = logging.getLogger(__name__)


class InferenceEngine:
    """Loads the active model lazily and scores normalized event candidates."""

    def __init__(self, model_name: str = MODEL_NAME) -> None:
        self.model_name = model_name
        self._lock = threading.RLock()
        self._detector: IsolationForestDetector | None = None
        self._loaded_version: str | None = None
        self._loaded_at: datetime | None = None
        self._extractor = FeatureExtractor()

        self._scored = 0
        self._anomalies = 0
        self._failures = 0
        #: Why the engine is not scoring, in plain words. Surfaced by /health
        #: and by the ML API so a blank ML panel always has an explanation.
        self._reason: str | None = None

    # ------------------------------------------------------------------ state
    @property
    def available(self) -> bool:
        return self._detector is not None

    @property
    def threshold(self) -> float:
        return settings.ml_anomaly_threshold

    @property
    def unavailable_reason(self) -> str | None:
        """Why the detector is not scoring, in plain words.

        Derived rather than only remembered: ``_reason`` is set by
        ``load_active``, which never runs when ML is disabled at startup. That
        left `available: false` with `reason: null` - precisely the blank panel
        with no explanation this layer exists to prevent. Caught by the
        degraded-mode verification, not by a unit test, which is the argument
        for running one.
        """
        if self.available:
            return None
        if not settings.ml_enabled:
            return "ML is disabled by configuration (ML_ENABLED=false)."
        if self._reason:
            return self._reason
        return (
            "No anomaly model has been loaded yet. Train one with "
            "`python -m app.ml.training.train_anomaly_model`."
        )

    def status(self) -> dict[str, Any]:
        return {
            "enabled": settings.ml_enabled,
            "available": self.available,
            "modelName": self.model_name,
            "modelVersion": self._loaded_version,
            "featureSchemaVersion": FEATURE_SCHEMA_VERSION,
            "featureCount": len(FEATURE_NAMES),
            "threshold": self.threshold,
            "loadedAt": self._loaded_at.isoformat() if self._loaded_at else None,
            "eventsScored": self._scored,
            "anomaliesFlagged": self._anomalies,
            "failures": self._failures,
            "reason": self.unavailable_reason,
            "context": self._extractor.context.stats(),
        }

    # ----------------------------------------------------------------- loading
    def load_active(self, db: Session) -> bool:
        """Load (or reload) the registry's active model. Never raises."""
        if not settings.ml_enabled:
            self._unload("ML is disabled by configuration (ML_ENABLED=false)")
            return False

        try:
            record = registry.get_active(db, self.model_name)
        except Exception as exc:  # noqa: BLE001 - a database blip must not break ingestion
            self._unload(f"Could not read the model registry: {type(exc).__name__}")
            return False

        if record is None:
            self._unload(
                "No active model is registered. Train one with "
                "`python -m app.ml.training.train_anomaly_model`."
            )
            return False

        with self._lock:
            if self._detector is not None and self._loaded_version == record.version:
                return True

            try:
                detector = IsolationForestDetector.load(
                    Path(record.artifact_path), expected_sha256=record.artifact_sha256
                )
            except ModelUnavailable as exc:
                self._unload(str(exc))
                logger.warning("ML model unavailable: %s", exc)
                return False

            if detector.feature_schema_version != FEATURE_SCHEMA_VERSION:
                self._unload(
                    f"{record.identity} speaks feature schema "
                    f"{detector.feature_schema_version}, this build produces "
                    f"{FEATURE_SCHEMA_VERSION}. Retrain before activating it."
                )
                logger.warning("ML model rejected: %s", self._reason)
                return False

            if tuple(detector.feature_names) != FEATURE_NAMES:
                self._unload(
                    f"{record.identity} was fitted on a different feature ordering. "
                    "Retrain before activating it."
                )
                return False

            self._detector = detector
            self._loaded_version = record.version
            self._loaded_at = datetime.now(timezone.utc)
            self._reason = None
            logger.info(
                "ML model loaded",
                extra={"model": record.identity, "operation": "ml.load"},
            )
            return True

    def _unload(self, reason: str) -> None:
        with self._lock:
            self._detector = None
            self._loaded_version = None
            self._reason = reason

    def reload(self, db: Session) -> bool:
        """Force a reload, e.g. after an administrator activates a version."""
        with self._lock:
            self._detector = None
            self._loaded_version = None
        return self.load_active(db)

    # ---------------------------------------------------------------- scoring
    def score(self, candidate: dict[str, Any]) -> InferenceResult | None:
        """Score one normalized candidate.

        Returns ``None`` when no verdict can be given. The rolling behavioural
        context is updated either way, so an outage does not leave a hole in the
        history that later features depend on.
        """
        if not settings.ml_enabled:
            self._extractor.observe(candidate)
            return None

        if self._detector is None:
            self._extractor.observe(candidate)
            return None

        started = perf_counter()
        try:
            # `observe=True` folds the event into the context after its own
            # features are read, exactly as training does.
            vector = self._extractor.extract(candidate, observe=True)
            score = self._detector.anomaly_score(vector.values)
            threshold = self.threshold
            is_anomaly = score >= threshold

            self._scored += 1
            if is_anomaly:
                self._anomalies += 1

            return InferenceResult(
                model_name=self.model_name,
                model_version=self._loaded_version or "unknown",
                feature_schema_version=FEATURE_SCHEMA_VERSION,
                anomaly_score=score,
                is_anomaly=is_anomaly,
                threshold=threshold,
                features=vector.as_dict(),
                top_contributors=(
                    self._detector.explain(vector.values) if is_anomaly else []
                ),
                latency_ms=(perf_counter() - started) * 1000.0,
            )
        except Exception:  # noqa: BLE001 - inference must never drop telemetry
            self._failures += 1
            logger.exception("ML inference failed; continuing without an ML signal")
            return None

    # ------------------------------------------------------------------ admin
    def reset_context(self) -> None:
        """Drop the rolling behavioural history (used by tests)."""
        self._extractor.reset()


#: Application-wide engine. Loaded at startup and after a model is activated.
engine = InferenceEngine()
