"""Feature engineering for the anomaly detector.

One extractor, one context implementation, used identically by training,
evaluation and live inference.
"""

from app.ml.features.context import BehaviorContext
from app.ml.features.extractor import (
    FEATURE_COUNT,
    FEATURE_NAMES,
    FeatureExtractor,
)

__all__ = [
    "FEATURE_COUNT",
    "FEATURE_NAMES",
    "BehaviorContext",
    "FeatureExtractor",
]
