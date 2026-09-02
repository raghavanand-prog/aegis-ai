"""Inference runtime.

Deliberately does NOT re-export the ``engine`` singleton. Importing the
instance here would shadow the ``app.ml.inference.engine`` submodule, so
``from app.ml.inference import engine`` would silently give callers the object
instead of the module. Import the module and reach through it:

    from app.ml.inference import engine as inference_engine
    inference_engine.engine.score(candidate)
"""

from app.ml.inference.engine import InferenceEngine

__all__ = ["InferenceEngine"]
