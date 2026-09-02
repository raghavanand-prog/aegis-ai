"""Deterministic detection engine.

No machine learning is involved anywhere in this package: every detection comes
from a hand-written, versioned rule that states why it fired.
"""

from app.detection.rules import (
    COVERED_LABELS,
    LEGACY_RULE_IDS,
    RULES,
    RULES_BY_ID,
    Detection,
    DetectionResult,
    Rule,
    catalogue,
    evaluate,
)

__all__ = [
    "COVERED_LABELS",
    "LEGACY_RULE_IDS",
    "RULES",
    "RULES_BY_ID",
    "Detection",
    "DetectionResult",
    "Rule",
    "catalogue",
    "evaluate",
]
