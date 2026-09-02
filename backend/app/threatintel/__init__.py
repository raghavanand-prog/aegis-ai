"""Threat intelligence.

Provider-based by design: the platform depends on the abstraction in
``base.py``, never on any one vendor. Enrichment is optional, cached, budgeted
and incapable of breaking event ingestion.
"""

from app.threatintel.base import (
    SUPPORTED_IOC_TYPES,
    IntelLookup,
    ThreatIntelProvider,
)
from app.threatintel.validation import InvalidIndicator, is_valid, validate

__all__ = [
    "SUPPORTED_IOC_TYPES",
    "IntelLookup",
    "InvalidIndicator",
    "ThreatIntelProvider",
    "is_valid",
    "validate",
]
