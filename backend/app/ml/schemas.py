"""Shared ML value types.

These are plain dataclasses on purpose: the ML layer must be usable from the
training CLI, from the evaluation runner and from the ingestion pipeline
without dragging in FastAPI or the ORM.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

#: Bumped whenever the feature set changes in any way that alters the meaning
#: of a stored vector - a feature added, removed, reordered or redefined.
#: A model trained under one schema version must never score features built
#: under another, and every stored inference records which version it used.
FEATURE_SCHEMA_VERSION = "1.0"


@dataclass(frozen=True)
class FeatureVector:
    """One event, expressed as numbers the model can consume."""

    names: tuple[str, ...]
    values: tuple[float, ...]
    schema_version: str = FEATURE_SCHEMA_VERSION

    def as_dict(self) -> dict[str, float]:
        return dict(zip(self.names, self.values, strict=True))

    def __len__(self) -> int:
        return len(self.values)


@dataclass
class FeatureContribution:
    """How far one feature sat from the training norm, and in which direction."""

    name: str
    value: float
    #: Standard deviations from the training mean. Signed: positive means the
    #: value was unusually high.
    deviation: float
    direction: str  # "above" | "below"

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "value": round(self.value, 6),
            "deviation": round(self.deviation, 3),
            "direction": self.direction,
        }


@dataclass
class InferenceResult:
    """What the anomaly detector concluded about one event.

    ``anomaly_score`` is a normalized 0..1 ranking score, NOT a probability and
    NOT a confidence. Isolation Forest produces an unbounded path-length score;
    mapping it into 0..1 makes it comparable and displayable, and changes
    nothing about what it means. See docs/ml-architecture.md.
    """

    model_name: str
    model_version: str
    feature_schema_version: str
    anomaly_score: float
    is_anomaly: bool
    threshold: float
    features: dict[str, float] = field(default_factory=dict)
    top_contributors: list[FeatureContribution] = field(default_factory=list)
    latency_ms: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "model": self.model_name,
            "modelVersion": self.model_version,
            "featureSchemaVersion": self.feature_schema_version,
            "anomalyScore": round(self.anomaly_score, 4),
            "isAnomaly": self.is_anomaly,
            "threshold": self.threshold,
            "topContributors": [c.to_dict() for c in self.top_contributors],
            "featuresUsed": sorted(self.features),
            "latencyMs": round(self.latency_ms, 3),
        }
