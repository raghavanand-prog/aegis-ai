"""Telemetry ingestion pipeline."""

from app.telemetry.adapters import TelemetryAdapter
from app.telemetry.adapters import resolve as resolve_adapter
from app.telemetry.base import RawTelemetry, TelemetrySource
from app.telemetry.canonical import CanonicalEvent, TelemetryProvenance
from app.telemetry.collector import ExternalSourceRefused, TelemetryCollector, collector
from app.telemetry.normalizer import (
    NormalizationError,
    normalize,
    normalize_with_provenance,
)
from app.telemetry.sources.cloudtrail_file import CloudTrailFileSource
from app.telemetry.sources.synthetic import SyntheticTelemetrySource

__all__ = [
    "CanonicalEvent",
    "CloudTrailFileSource",
    "ExternalSourceRefused",
    "NormalizationError",
    "RawTelemetry",
    "SyntheticTelemetrySource",
    "TelemetryCollector",
    "TelemetryAdapter",
    "TelemetryProvenance",
    "TelemetrySource",
    "collector",
    "normalize",
    "normalize_with_provenance",
    "resolve_adapter",
]
