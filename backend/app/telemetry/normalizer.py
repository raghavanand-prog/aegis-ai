"""Normalization: raw vendor record -> canonical event.

    TelemetrySource -> RawTelemetry -> adapter -> CanonicalEvent -> candidate dict

**What V7 changed here.** Through V6 this module *was* the vendor knowledge: seven
mapping functions inline, a dict keyed on source display name, and a fallback
table that silently handed an unrecognised source to a foreign vendor's parser.
The V6 handoff named it - ``telemetry/normalizer.py`` hard-codes vendor schemas,
"that leak is documented and unfixed" - and noted that adding a source by
appending another branch would deepen it.

The mappings now live in ``app/telemetry/adapters/``, one module per vendor,
behind a registry. This module resolves an adapter, calls it, and attaches
provenance. Adding a source is adding a file and a registry entry; it is no
longer an edit to the code path every event in the system passes through.

**Behaviour is unchanged.** The seven mappings were moved rather than rewritten,
and ``test_telemetry_normalizer_characterization.py`` pins the canonical output
of every source by digest, recorded at the V6 checkpoint before any of this
existed. Nothing in V4, V5 or V6 moves.

**One thing is genuinely new**: ``normalize_with_provenance`` reports which
adapter ran and whether it was the one registered for the source or a fallback.
V6 fell back too; it just never said so, and "which parser produced this event"
is the first question to ask when a detection looks wrong.
"""

from __future__ import annotations

from typing import Any

from app.telemetry import adapters
from app.telemetry.adapters.base import AdapterError
from app.telemetry.base import RawTelemetry
from app.telemetry.canonical import CanonicalEvent, TelemetryProvenance


class NormalizationError(ValueError):
    """Raised when a record cannot be mapped onto the canonical schema."""


def normalize_with_provenance(
    record: RawTelemetry,
) -> tuple[CanonicalEvent, TelemetryProvenance]:
    """Map one raw record, returning the event and how it was parsed."""
    try:
        adapter, resolution = adapters.resolve(record.source, record.source_type)
    except LookupError as exc:
        raise NormalizationError(str(exc)) from exc

    try:
        event = adapter.parse(record.raw)
    except AdapterError as exc:
        raise NormalizationError(
            f"Adapter {adapter.name!r} could not map a record from "
            f"{record.source!r}: {exc}"
        ) from exc

    provenance = TelemetryProvenance(
        source=record.source,
        source_type=record.source_type,
        adapter=adapter.name,
        resolution=resolution,
        received_at=record.received_at,
        raw_log=record.raw_log,
        is_synthetic=record.is_synthetic,
    )
    return event, provenance


def normalize(record: RawTelemetry) -> dict[str, Any]:
    """Map one raw record onto the canonical event structure.

    The signature and the returned dict are exactly what V4-V6 produced, so
    every caller and every stored event is unaffected. ``record.scenario`` is
    still deliberately not carried onto the candidate - a detector able to read
    the generating scenario would be scoring the answer key, asserted by test
    since V6.
    """
    event, provenance = normalize_with_provenance(record)
    candidate = event.to_candidate()
    candidate.update(provenance.as_candidate_fields())
    return candidate


#: Kept for callers and tests that inspect which sources are mapped. Derived
#: from the registry rather than being the registry, so it cannot fall out of
#: step with what actually parses a record.
NORMALIZERS = adapters.BY_SOURCE_NAME
FALLBACK_BY_TYPE = adapters.BY_SOURCE_TYPE
