"""Dataset abstraction for reproducible evaluation (V4).

V3 had exactly one evaluation dataset - a synthetic generator whose samples
were typed against the AEGISX :class:`~app.evaluation.labels.Label` enum. That
was sufficient while the only corpus was one AEGISX built itself. It does not
generalise: a public corpus arrives with its *own* taxonomy, its own licence,
its own duplicate structure, and its own idea of what a "sample" is.

This module defines the shape every V4 dataset presents to the experiment
runner, and nothing else. It contains no dataset-specific logic.

Three properties are non-negotiable, because every downstream number depends on
them:

**Traceability.** A dataset states where it came from, under what licence, at
what version, and what the bytes hashed to. A metric whose dataset cannot be
identified is not a result.

**Determinism.** ``fingerprint()`` covers the sample identities, labels and
group keys actually loaded. Two runs that report the same fingerprint saw the
same data; two runs that do not are not comparable, and the report says so
rather than quietly averaging them.

**Honest labels.** ``LabelSchema`` records the original label, the normalized
label, and every transformation between them - including exclusions and their
reasons. Samples are never silently dropped and labels are never silently
collapsed. If a dataset's taxonomy does not fit AEGISX's, the dataset keeps its
own and says so; manufacturing a mapping would fabricate a result.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

# ---------------------------------------------------------------- provenance


@dataclass(frozen=True)
class DatasetProvenance:
    """Where a dataset came from, and what exactly was read."""

    source: str
    #: Licence of the *dataset*, as published by whoever released it.
    license: str
    #: Citation the dataset's authors ask for.
    citation: str
    description: str
    #: SHA-256 of each file actually read, keyed by filename. This is the
    #: strongest reproducibility claim available: the file either hashes to the
    #: recorded value or the run refuses to proceed.
    file_digests: dict[str, str] = field(default_factory=dict)
    retrieved_at: str | None = None
    notes: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "license": self.license,
            "citation": self.citation,
            "description": self.description,
            "fileDigests": dict(sorted(self.file_digests.items())),
            "retrievedAt": self.retrieved_at,
            "notes": list(self.notes),
        }


# -------------------------------------------------------------- label schema


@dataclass(frozen=True)
class LabelSchema:
    """Ground truth, and every transformation applied to reach it.

    ``binary`` is the axis every detector is scored on: a sample is malicious or
    it is not. ``categories`` preserves the dataset's own attack taxonomy where
    it has one, because collapsing "Worms" and "Fuzzers" into "malicious" for
    reporting would hide which classes a detector cannot see.

    ``mapping`` is the full original -> normalized record. ``excluded`` names
    every original label that was dropped **and why**. An empty ``excluded`` is
    a claim that nothing was thrown away.
    """

    name: str
    version: str
    #: original label (verbatim) -> normalized category
    mapping: dict[str, str]
    #: normalized categories treated as malicious
    malicious_categories: tuple[str, ...]
    #: the normalized category meaning "not an attack"
    benign_category: str
    #: original label -> reason it was excluded from evaluation entirely
    excluded: dict[str, str] = field(default_factory=dict)
    notes: tuple[str, ...] = ()

    def normalize(self, original: str | None) -> str | None:
        """Return the normalized category, or ``None`` if excluded/unknown."""
        key = "" if original is None else str(original)
        if key in self.excluded:
            return None
        return self.mapping.get(key)

    def is_malicious(self, category: str) -> bool:
        return category in self.malicious_categories

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "version": self.version,
            "benignCategory": self.benign_category,
            "maliciousCategories": list(self.malicious_categories),
            "mapping": dict(sorted(self.mapping.items())),
            "excluded": dict(sorted(self.excluded.items())),
            "notes": list(self.notes),
        }


# ------------------------------------------------------------------- samples


@dataclass
class EvaluationSample:
    """One labelled record, already normalized into an AEGISX event.

    ``candidate`` is the output of the *production* normalizer. The evaluation
    path and the ingestion path therefore see the same dict shape, which is what
    makes it legitimate to run the production feature extractor over it.
    """

    id: str
    #: Normalized ground-truth category (from :class:`LabelSchema`).
    category: str
    is_malicious: bool
    #: Normalized event, exactly as ``app.telemetry.normalizer.normalize`` emits.
    candidate: dict[str, Any]
    #: Event time, used by temporal splits and latency ordering.
    timestamp: datetime
    #: Samples sharing a group key must never be split apart. Exact duplicates
    #: get the same key, so a copy of a training row cannot surface in test and
    #: inflate every metric. ``None`` means "this sample is its own group".
    group_key: str | None = None
    #: The dataset's own label, verbatim, before normalization.
    original_label: str | None = None

    @property
    def grouping(self) -> str:
        return self.group_key if self.group_key is not None else self.id


@dataclass
class EvaluationDataset:
    """A loaded, labelled, normalized corpus ready for an experiment."""

    name: str
    version: str
    provenance: DatasetProvenance
    label_schema: LabelSchema
    samples: list[EvaluationSample]
    #: How the corpus was reduced from the source, if it was. ``None`` means the
    #: whole source was used.
    sampling: dict[str, Any] | None = None
    #: Schema version of this abstraction, so a stored result can be read back
    #: by a later build that knows what changed.
    schema_version: str = "1.0"

    def __len__(self) -> int:
        return len(self.samples)

    @property
    def malicious_count(self) -> int:
        return sum(1 for sample in self.samples if sample.is_malicious)

    @property
    def benign_count(self) -> int:
        return len(self.samples) - self.malicious_count

    def class_counts(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for sample in self.samples:
            counts[sample.category] = counts.get(sample.category, 0) + 1
        return dict(sorted(counts.items()))

    def group_count(self) -> int:
        return len({sample.grouping for sample in self.samples})

    def fingerprint(self) -> str:
        """Stable hash over identity, label and grouping of every sample.

        Deliberately covers the *grouping* too: two loads that agree on samples
        but disagree on how duplicates are grouped will produce different
        splits, and must not claim to be the same dataset.
        """
        digest = hashlib.sha256()
        digest.update(f"{self.name}:{self.version}:{self.schema_version}".encode())
        for sample in self.samples:
            digest.update(sample.id.encode())
            digest.update(b"\x00")
            digest.update(sample.category.encode())
            digest.update(b"\x00")
            digest.update(sample.grouping.encode())
            digest.update(b"\x01")
        return digest.hexdigest()[:16]

    def describe(self) -> dict[str, Any]:
        """Machine-readable dataset card fragment. Goes into every report."""
        return {
            "name": self.name,
            "version": self.version,
            "schemaVersion": self.schema_version,
            "fingerprint": self.fingerprint(),
            "totalSamples": len(self.samples),
            "maliciousSamples": self.malicious_count,
            "benignSamples": self.benign_count,
            "maliciousRate": (
                round(self.malicious_count / len(self.samples), 6) if self.samples else None
            ),
            "distinctGroups": self.group_count(),
            "classCounts": self.class_counts(),
            "provenance": self.provenance.to_dict(),
            "labelSchema": self.label_schema.to_dict(),
            "sampling": self.sampling,
        }


def config_digest(payload: dict[str, Any]) -> str:
    """Stable short hash of a JSON-serialisable configuration.

    Used for experiment identity: the same configuration must hash to the same
    value across processes and machines, so ``sort_keys`` is not optional.
    """
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(encoded.encode()).hexdigest()[:16]
