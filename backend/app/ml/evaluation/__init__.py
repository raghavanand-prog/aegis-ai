"""Labelled measurement of the hybrid detection stack.

Extends the V2 detection evaluation rather than replacing it: the same dataset,
the same metrics, now computed for rules alone, ML alone, and both together, so
the contribution of each is visible.
"""

from app.ml.evaluation.hybrid_runner import (
    CAVEATS,
    ConfigurationResult,
    HybridReport,
    load_registered_model,
    run_hybrid_evaluation,
)

__all__ = [
    "CAVEATS",
    "ConfigurationResult",
    "HybridReport",
    "load_registered_model",
    "run_hybrid_evaluation",
]
