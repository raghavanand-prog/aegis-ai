"""Model registry."""

from app.ml.registry import registry
from app.ml.registry.registry import RegistryError

__all__ = ["RegistryError", "registry"]
