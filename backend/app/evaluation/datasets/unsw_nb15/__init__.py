"""UNSW-NB15 public intrusion-detection corpus (V4).

See ``docs/DATASET_CARD.md`` for selection rationale, limitations, and what
this dataset can and cannot fairly evaluate.
"""

from app.evaluation.datasets.unsw_nb15.labels import LABEL_SCHEMA
from app.evaluation.datasets.unsw_nb15.loader import (
    DATASET_NAME,
    DATASET_VERSION,
    DatasetUnavailable,
    available,
    load,
    unavailable_reason,
)

__all__ = [
    "DATASET_NAME",
    "DATASET_VERSION",
    "LABEL_SCHEMA",
    "DatasetUnavailable",
    "available",
    "load",
    "unavailable_reason",
]
