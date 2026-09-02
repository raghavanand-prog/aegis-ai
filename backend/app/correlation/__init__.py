"""Event correlation.

Individually unremarkable events become a finding when they are related. This
package groups events by entity inside a time window, judges each group against
declarative patterns, and records the result as a ``SecuritySequence``.

    patterns.py  how events are grouped, and what makes a group notable
    mitre.py     technique provenance - mapped vs inferred vs contextual
    engine.py    the runtime: fetch window, evaluate, open or extend, score

Correlation runs on the enrichment path, after an event is already persisted
and broadcast, so it can never delay ingestion.
"""

from app.correlation.engine import (
    correlate_event,
    correlation_confidence_for,
    status,
    to_dict,
)
from app.correlation.patterns import PATTERNS, PATTERNS_BY_ID, catalogue

__all__ = [
    "PATTERNS",
    "PATTERNS_BY_ID",
    "catalogue",
    "correlate_event",
    "correlation_confidence_for",
    "status",
    "to_dict",
]
