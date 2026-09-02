"""Reproducible experiment framework (V4).

    dataset -> split -> detector -> threshold policy -> metrics -> result

See ``docs/EVALUATION_METHODOLOGY.md`` for the protocol and its rationale.
"""

from app.evaluation.experiments.runner import (
    ExperimentError,
    ExperimentResult,
    extract_features,
    run_experiment,
)

__all__ = [
    "ExperimentError",
    "ExperimentResult",
    "extract_features",
    "run_experiment",
]
