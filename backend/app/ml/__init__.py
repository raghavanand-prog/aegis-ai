"""Machine learning layer.

Isolated from the API by design: nothing in ``app/api`` imports a model, and
nothing here imports FastAPI. Route handlers ask the inference engine for a
verdict; they never build features or touch an artifact.

    features/   deterministic event -> vector, shared by training and inference
    models/     the detectors themselves
    registry/   what was trained, from what, and which version is serving
    inference/  the runtime entry point, which degrades to None on any failure
    training/   the explicit, operator-run training pipeline
    evaluation/ labelled measurement of rules vs ML vs hybrid
"""

from app.ml.schemas import (
    FEATURE_SCHEMA_VERSION,
    FeatureContribution,
    FeatureVector,
    InferenceResult,
)

__all__ = [
    "FEATURE_SCHEMA_VERSION",
    "FeatureContribution",
    "FeatureVector",
    "InferenceResult",
]
