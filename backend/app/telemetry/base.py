"""Telemetry source abstraction.

    TelemetrySource -> TelemetryCollector -> Normalizer -> EventService -> DB -> WebSocket

A source is anything that can hand the collector raw vendor-shaped records.
Sources that reach outside this process are marked ``is_external`` and are
refused unless an operator explicitly enables them, so AEGISX can never start
talking to production systems by accident.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from app.models.enums import SourceType


@dataclass
class RawTelemetry:
    """One untouched record as produced by a source."""

    source: str
    source_type: SourceType
    raw: dict[str, Any]
    raw_log: str
    received_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    is_synthetic: bool = True
    #: For generated telemetry, the scenario that produced this record.
    #: **Provenance, never a label.** Normalization deliberately does not carry
    #: it onto the candidate: a detector able to read the generating scenario
    #: would be scoring the answer key. It exists so a labelled corpus can be
    #: built from the generator's own intent, which `event_type` cannot express -
    #: distinct scenarios collapse onto one type after normalization.
    scenario: str | None = None


class TelemetrySource(ABC):
    """Base class every collector plugs into."""

    #: Human readable vendor/product name shown in the UI.
    name: str = "unknown"
    #: Class of telemetry produced.
    source_type: SourceType = SourceType.APPLICATION
    #: True when the source communicates with something outside this process.
    is_external: bool = False

    @abstractmethod
    def collect(self, count: int = 1) -> Iterable[RawTelemetry]:
        """Return up to ``count`` raw records."""

    def health(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "sourceType": self.source_type.value,
            "isExternal": self.is_external,
        }
