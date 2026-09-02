"""Detection latency.

Measures how long the rule engine takes per event. This is the engine's own
processing time, not end-to-end pipeline latency - the report labels it as such
so the number cannot be quietly reused as an ingest-to-alert figure.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


def percentile(values: list[float], fraction: float) -> float:
    """Nearest-rank percentile. No numpy dependency for four lines of maths."""
    if not values:
        return 0.0
    ordered = sorted(values)
    index = max(0, min(len(ordered) - 1, int(round(fraction * (len(ordered) - 1)))))
    return ordered[index]


@dataclass
class LatencyStats:
    count: int
    mean_ms: float
    p50_ms: float
    p95_ms: float
    p99_ms: float
    max_ms: float
    min_ms: float
    total_ms: float

    @property
    def events_per_second(self) -> float:
        if self.total_ms <= 0:
            return 0.0
        return (self.count / self.total_ms) * 1000.0

    @classmethod
    def from_samples(cls, samples: list[float]) -> LatencyStats:
        if not samples:
            return cls(0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0)
        total = sum(samples)
        return cls(
            count=len(samples),
            mean_ms=total / len(samples),
            p50_ms=percentile(samples, 0.50),
            p95_ms=percentile(samples, 0.95),
            p99_ms=percentile(samples, 0.99),
            max_ms=max(samples),
            min_ms=min(samples),
            total_ms=total,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "measured": "detection engine only (excludes ingest, normalization and storage)",
            "samples": self.count,
            "meanMs": round(self.mean_ms, 4),
            "p50Ms": round(self.p50_ms, 4),
            "p95Ms": round(self.p95_ms, 4),
            "p99Ms": round(self.p99_ms, 4),
            "maxMs": round(self.max_ms, 4),
            "minMs": round(self.min_ms, 4),
            "totalMs": round(self.total_ms, 3),
            "eventsPerSecond": round(self.events_per_second, 1),
        }
