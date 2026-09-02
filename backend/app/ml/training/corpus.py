"""Training corpus construction.

Isolation Forest learns what *ordinary* looks like, so the corpus is built from
the same synthetic telemetry generator that feeds the live pipeline, pushed
through the same normalizer and the same feature extractor. Using a different
generator for training would teach the model a distribution the running system
never produces.

Two deliberate choices:

**Timestamps are spread across real days.** The generator stamps everything
"now", which would leave every temporal feature constant and the model blind to
off-hours activity. The corpus assigns each record a deterministic timestamp
across a configurable span, walking forward in time so the rolling behavioural
context builds up the way it does in production.

**Nothing is labelled.** This is unsupervised training: the corpus carries the
generator's scenario name purely so the training report can describe the mix,
and that name is never used as a target. Any label leaking into a fit would be
supervised learning wearing an anomaly detector's clothes.
"""

from __future__ import annotations

import random
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

from app.ml.features import FeatureExtractor
from app.telemetry.normalizer import NormalizationError, normalize
from app.telemetry.sources.synthetic import SyntheticTelemetrySource

TRAINING_DATASET_NAME = "aegisx-ml-training"
#: Bumped when the corpus construction changes in a way that alters the data a
#: model sees. Recorded on every registered model.
TRAINING_DATASET_VERSION = "1.0"

DEFAULT_SEED = 4242
DEFAULT_SAMPLES = 6_000
DEFAULT_SPAN_DAYS = 14

#: Business hours get more traffic than nights and weekends, which is what
#: makes "unusual hour" a meaningful feature rather than noise.
_HOUR_WEIGHTS = [
    1, 1, 1, 1, 1, 2, 4, 8, 14, 18, 20, 20, 18, 19, 20, 18, 14, 10, 7, 5, 4, 3, 2, 1,
]


@dataclass
class TrainingCorpus:
    """Feature matrix plus the provenance needed to reproduce it."""

    vectors: list[tuple[float, ...]]
    feature_names: tuple[str, ...]
    schema_version: str
    seed: int
    span_days: int
    scenario_mix: dict[str, int] = field(default_factory=dict)
    skipped: int = 0

    @property
    def size(self) -> int:
        return len(self.vectors)

    def fingerprint(self) -> str:
        """Identifies this exact corpus. Same inputs -> same fingerprint."""
        import hashlib

        digest = hashlib.sha256()
        digest.update(
            f"{TRAINING_DATASET_NAME}:{TRAINING_DATASET_VERSION}:{self.seed}:"
            f"{self.span_days}:{self.size}:{self.schema_version}".encode()
        )
        for vector in self.vectors[:200]:  # a stable sample keeps this cheap
            digest.update(",".join(f"{value:.6f}" for value in vector).encode())
        return digest.hexdigest()[:16]

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": TRAINING_DATASET_NAME,
            "version": TRAINING_DATASET_VERSION,
            "seed": self.seed,
            "spanDays": self.span_days,
            "samples": self.size,
            "skipped": self.skipped,
            "featureSchemaVersion": self.schema_version,
            "fingerprint": self.fingerprint(),
            "scenarioMix": dict(sorted(self.scenario_mix.items())),
            "generator": "app.telemetry.sources.synthetic.SyntheticTelemetrySource",
            "labelled": False,
            "synthetic": True,
        }


def _timestamps(count: int, span_days: int, rng: random.Random) -> list[datetime]:
    """Deterministic, chronologically ordered timestamps with a daily rhythm."""
    # Anchored to a fixed epoch rather than "now" so two runs with the same seed
    # produce byte-identical corpora.
    start = datetime(2026, 1, 5, 0, 0, tzinfo=timezone.utc)  # a Monday
    stamps: list[datetime] = []
    for _ in range(count):
        day = rng.randrange(span_days)
        hour = rng.choices(range(24), weights=_HOUR_WEIGHTS, k=1)[0]
        stamps.append(
            start
            + timedelta(
                days=day,
                hours=hour,
                minutes=rng.randrange(60),
                seconds=rng.randrange(60),
            )
        )
    stamps.sort()
    return stamps


def build_corpus(
    *,
    seed: int = DEFAULT_SEED,
    samples: int = DEFAULT_SAMPLES,
    span_days: int = DEFAULT_SPAN_DAYS,
) -> TrainingCorpus:
    """Generate, normalize and vectorise a training corpus."""
    if samples < 200:
        raise ValueError("A training corpus needs at least 200 samples to be meaningful")

    rng = random.Random(seed)  # noqa: S311 - simulation data, not a secret
    source = SyntheticTelemetrySource(seed=seed)
    extractor = FeatureExtractor()
    stamps = _timestamps(samples, span_days, rng)

    vectors: list[tuple[float, ...]] = []
    mix: dict[str, int] = {}
    skipped = 0

    for record in source.collect(samples):
        record.received_at = stamps[len(vectors) + skipped]
        try:
            candidate = normalize(record)
        except NormalizationError:
            skipped += 1
            continue

        vector = extractor.extract(candidate, observe=True)
        vectors.append(vector.values)
        key = str(candidate.get("event_type", "unknown"))
        mix[key] = mix.get(key, 0) + 1

    return TrainingCorpus(
        vectors=vectors,
        feature_names=extractor.names,
        schema_version=extractor.schema_version,
        seed=seed,
        span_days=span_days,
        scenario_mix=mix,
        skipped=skipped,
    )
