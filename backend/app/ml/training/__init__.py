"""Model training.

Training is an explicit operator action, never something the application does
on startup. See ``train_anomaly_model.py``.
"""

from app.ml.training.corpus import (
    TRAINING_DATASET_NAME,
    TRAINING_DATASET_VERSION,
    TrainingCorpus,
    build_corpus,
)

__all__ = [
    "TRAINING_DATASET_NAME",
    "TRAINING_DATASET_VERSION",
    "TrainingCorpus",
    "build_corpus",
]
