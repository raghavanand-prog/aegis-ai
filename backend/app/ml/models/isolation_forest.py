"""Isolation Forest anomaly detector.

Why this model first
--------------------
AEGISX has synthetic telemetry and a labelled *evaluation* dataset, but it does
not have a large, trustworthy, labelled corpus of real attacks. Training a
supervised classifier on synthetic labels would produce a model that has learnt
the generator, not the threat - and a headline accuracy number that means
nothing outside this repository.

Isolation Forest needs no labels. It learns what ordinary traffic looks like
and ranks how easy each new event is to isolate from it. That is an honest fit
for the data actually available, and it complements the rules rather than
duplicating them: rules catch what we already know to look for, this catches
what is merely *unusual*.

What the output is and is not
-----------------------------
scikit-learn's ``score_samples`` returns an unbounded log-scale isolation
score. This wrapper maps it onto 0..1 so it can be stored, compared and drawn.

That number is an **anomaly score**: a ranking. It is not a probability that
the event is malicious, and it is not a confidence. Isolation Forest offers no
calibrated probability, and presenting its output as one would be a fabricated
statistic. The mapping below is deliberately a fixed, documented affine
transform of the raw score around the model's own trained offset, so the same
event always produces the same number.
"""

from __future__ import annotations

import hashlib
import logging
import math
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from app.ml.schemas import FEATURE_SCHEMA_VERSION, FeatureContribution

logger = logging.getLogger(__name__)

MODEL_NAME = "isolation_forest"
MODEL_TYPE = "sklearn.ensemble.IsolationForest"

#: Raw isolation scores cluster tightly; this controls how much of that range
#: is spread across 0..1. Fixed and documented so a score recorded today is
#: comparable with one recorded next month.
SCORE_SPREAD = 0.20


class ModelUnavailable(RuntimeError):
    """Raised when an artifact cannot be loaded. Callers degrade, never crash."""


@dataclass
class TrainingReport:
    """What a fit actually measured. Empty fields stay empty."""

    samples: int
    features: int
    contamination: float
    random_state: int
    n_estimators: int
    #: Share of the *training* data the fitted model calls anomalous. This is a
    #: property of the fit, not an accuracy measurement - it is reported as
    #: "trainingAnomalyRate" and never as precision or recall.
    training_anomaly_rate: float
    score_mean: float
    score_std: float

    def to_dict(self) -> dict[str, Any]:
        return {
            "trainingSamples": self.samples,
            "featureCount": self.features,
            "contamination": self.contamination,
            "randomState": self.random_state,
            "nEstimators": self.n_estimators,
            "trainingAnomalyRate": round(self.training_anomaly_rate, 4),
            "rawScoreMean": round(self.score_mean, 5),
            "rawScoreStd": round(self.score_std, 5),
        }


class IsolationForestDetector:
    """Fit / score / persist wrapper around scikit-learn's IsolationForest."""

    name = MODEL_NAME
    model_type = MODEL_TYPE

    def __init__(
        self,
        *,
        feature_names: tuple[str, ...],
        contamination: float = 0.08,
        random_state: int = 1337,
        n_estimators: int = 200,
        max_samples: str | int = "auto",
    ) -> None:
        self.feature_names = tuple(feature_names)
        self.contamination = contamination
        self.random_state = random_state
        self.n_estimators = n_estimators
        self.max_samples = max_samples
        self.feature_schema_version = FEATURE_SCHEMA_VERSION

        self._pipeline: Any = None
        #: Per-feature training mean/std, used to explain *why* an event was
        #: isolated. Isolation Forest has no coefficients, so the honest
        #: explanation is "these features were furthest from normal".
        self._feature_mean: list[float] = []
        self._feature_std: list[float] = []
        self._raw_offset: float = 0.0

    # ---------------------------------------------------------------- fitting
    def fit(self, vectors: list[tuple[float, ...]]) -> TrainingReport:
        """Fit on a matrix of feature vectors. Raises on unusable input."""
        import numpy as np
        from sklearn.ensemble import IsolationForest
        from sklearn.pipeline import Pipeline
        from sklearn.preprocessing import StandardScaler

        if len(vectors) < 50:
            raise ValueError(
                f"Refusing to fit on {len(vectors)} samples: an anomaly model needs a "
                "meaningful picture of normal. Generate more training telemetry."
            )

        matrix = np.asarray(vectors, dtype=float)
        if matrix.shape[1] != len(self.feature_names):
            raise ValueError(
                f"Feature width mismatch: got {matrix.shape[1]}, "
                f"schema declares {len(self.feature_names)}"
            )

        # Scaling matters even for a tree ensemble here: the isolation split
        # points are drawn uniformly across each feature's observed range, so
        # an unscaled byte count would be split far more often than a 0/1 flag.
        self._pipeline = Pipeline(
            [
                ("scale", StandardScaler()),
                (
                    "forest",
                    IsolationForest(
                        n_estimators=self.n_estimators,
                        contamination=self.contamination,
                        random_state=self.random_state,
                        max_samples=self.max_samples,
                        bootstrap=False,
                        n_jobs=1,  # determinism over throughput
                    ),
                ),
            ]
        )
        self._pipeline.fit(matrix)

        self._feature_mean = matrix.mean(axis=0).tolist()
        # Zero variance would divide by zero when explaining a deviation.
        self._feature_std = [max(float(s), 1e-9) for s in matrix.std(axis=0).tolist()]

        raw = self._pipeline.named_steps["forest"].score_samples(
            self._pipeline.named_steps["scale"].transform(matrix)
        )
        self._raw_offset = float(np.median(raw))
        predictions = self._pipeline.predict(matrix)

        return TrainingReport(
            samples=int(matrix.shape[0]),
            features=int(matrix.shape[1]),
            contamination=self.contamination,
            random_state=self.random_state,
            n_estimators=self.n_estimators,
            training_anomaly_rate=float((predictions == -1).mean()),
            score_mean=float(raw.mean()),
            score_std=float(raw.std()),
        )

    # --------------------------------------------------------------- scoring
    @property
    def is_fitted(self) -> bool:
        return self._pipeline is not None

    def raw_score(self, values: tuple[float, ...]) -> float:
        if self._pipeline is None:
            raise ModelUnavailable("Model has not been fitted or loaded")
        import numpy as np

        return float(self._pipeline.score_samples(np.asarray([values], dtype=float))[0])

    def anomaly_score(self, values: tuple[float, ...]) -> float:
        """Normalized 0..1 anomaly score. Higher = more isolated = more unusual.

        A logistic squash of the raw score's distance below the training median.
        Monotonic in the raw score, so the ranking scikit-learn produces is
        preserved exactly; only the presentation changes.
        """
        raw = self.raw_score(values)
        deviation = (self._raw_offset - raw) / SCORE_SPREAD
        return 1.0 / (1.0 + math.exp(-deviation))

    def explain(
        self, values: tuple[float, ...], *, limit: int = 5
    ) -> list[FeatureContribution]:
        """The features that sat furthest from the training norm.

        This is an honest description of the input, not a causal attribution:
        Isolation Forest does not expose per-feature importance for a single
        prediction. The UI labels it "features furthest from normal" for exactly
        that reason.
        """
        if not self._feature_mean:
            return []

        contributions: list[FeatureContribution] = []
        for index, name in enumerate(self.feature_names):
            if index >= len(values):
                break
            value = values[index]
            deviation = (value - self._feature_mean[index]) / self._feature_std[index]
            if abs(deviation) < 0.5:  # within half a standard deviation is normal
                continue
            contributions.append(
                FeatureContribution(
                    name=name,
                    value=value,
                    deviation=deviation,
                    direction="above" if deviation > 0 else "below",
                )
            )

        contributions.sort(key=lambda c: abs(c.deviation), reverse=True)
        return contributions[:limit]

    # ------------------------------------------------------------ persistence
    def to_payload(self) -> dict[str, Any]:
        return {
            "format": 1,
            "name": self.name,
            "modelType": self.model_type,
            "featureSchemaVersion": self.feature_schema_version,
            "featureNames": list(self.feature_names),
            "contamination": self.contamination,
            "randomState": self.random_state,
            "nEstimators": self.n_estimators,
            "pipeline": self._pipeline,
            "featureMean": self._feature_mean,
            "featureStd": self._feature_std,
            "rawOffset": self._raw_offset,
        }

    def save(self, path: Path) -> str:
        """Write the artifact and return its SHA-256.

        The digest is stored in the registry: an artifact whose hash no longer
        matches has been altered on disk, and a tampered model is a detection
        engine that lies. The loader checks it before use.
        """
        import joblib

        path.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(self.to_payload(), path, compress=3)
        return sha256_file(path)

    @classmethod
    def load(cls, path: Path, *, expected_sha256: str | None = None) -> IsolationForestDetector:
        import joblib

        if not path.exists():
            raise ModelUnavailable(f"Model artifact not found: {path}")

        if expected_sha256:
            actual = sha256_file(path)
            if actual != expected_sha256:
                raise ModelUnavailable(
                    f"Model artifact digest mismatch for {path.name}: registry has "
                    f"{expected_sha256[:12]}, file is {actual[:12]}. Refusing to load."
                )

        try:
            payload = joblib.load(path)
        except Exception as exc:  # noqa: BLE001 - a bad artifact degrades, never crashes
            raise ModelUnavailable(f"Could not read model artifact {path.name}: {exc}") from exc

        if not isinstance(payload, dict) or payload.get("format") != 1:
            raise ModelUnavailable(f"Unrecognised artifact format in {path.name}")

        detector = cls(
            feature_names=tuple(payload["featureNames"]),
            contamination=float(payload.get("contamination", 0.08)),
            random_state=int(payload.get("randomState", 1337)),
            n_estimators=int(payload.get("nEstimators", 200)),
        )
        detector.feature_schema_version = str(payload.get("featureSchemaVersion", "unknown"))
        detector._pipeline = payload["pipeline"]
        detector._feature_mean = list(payload.get("featureMean") or [])
        detector._feature_std = list(payload.get("featureStd") or [])
        detector._raw_offset = float(payload.get("rawOffset", 0.0))
        return detector


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65_536), b""):
            digest.update(chunk)
    return digest.hexdigest()
