"""Load UNSW-NB15 from disk into an :class:`EvaluationDataset`.

The corpus is not committed - it is 230 MB of third-party licensed data - so
the loader's first job is to say clearly what is missing and how to obtain it,
rather than failing with a stack trace or, worse, quietly evaluating on
nothing.

Determinism
-----------

Two loads with the same parameters must produce the same dataset fingerprint.
That requires more than a seed: rows are read in file order, subsampling is
driven by a hash of the *group key* rather than by a shuffled index, and every
file's SHA-256 is recorded. Hash-based subsampling means the selected subset is
a deterministic function of the data itself - it does not depend on row order,
pandas version, or how many workers read the file.
"""

from __future__ import annotations

import hashlib
import logging
from pathlib import Path
from typing import Any

from app.core.config import get_settings
from app.evaluation.datasets.base import (
    DatasetProvenance,
    EvaluationDataset,
    EvaluationSample,
)
from app.evaluation.datasets.unsw_nb15 import adapter
from app.evaluation.datasets.unsw_nb15.labels import LABEL_SCHEMA, RAW_LABEL_MAP

logger = logging.getLogger("aegisx.evaluation.dataset")

DATASET_NAME = "unsw-nb15"
DATASET_VERSION = "1.0-full"
DIRECTORY_NAME = "unsw-nb15"

SOURCE_URL = "https://huggingface.co/datasets/Mouwiya/UNSW-NB15"
FETCH_COMMAND = "python -m app.evaluation.datasets.unsw_nb15.fetch"

#: SHA-256 of the parquet shards this project was developed against. A file
#: that does not match is refused: silently evaluating on different bytes than
#: the ones a published result names is the exact failure this guards.
EXPECTED_DIGESTS: dict[str, str] = {
    "train-00000-of-00002.parquet": (
        "2aada2a26d061111f4e8fb84e716f5f11264fee71abe04697d42cb89e488d047"
    ),
    "train-00001-of-00002.parquet": (
        "7c6699ae967567977dee9e9193543b515255f4e1671ca79bf9ae65e7866ffef1"
    ),
}

PROVENANCE_NOTES: tuple[str, ...] = (
    "Captured by the Australian Centre for Cyber Security at UNSW Canberra "
    "using the IXIA PerfectStorm traffic generator (2015).",
    "Passive flow capture from a testbed of 45 addresses. Entity-novelty "
    "features are therefore near-degenerate on this corpus.",
    "Two capture periods with very different attack density: 2015-01-22 is "
    "2.1% malicious, 2015-02-18 is 19.3%.",
    "46% of records (1,053,500) belong to an exact-duplicate group. No group "
    "carries conflicting labels; splits are group-aware so copies cannot "
    "cross the train/test boundary.",
)


class DatasetUnavailable(RuntimeError):
    """The corpus is not on disk, or does not hash to the expected value."""


def dataset_dir() -> Path:
    return get_settings().evaluation_dataset_dir / DIRECTORY_NAME


def file_digest(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def available() -> bool:
    directory = dataset_dir()
    return all((directory / name).exists() for name in EXPECTED_DIGESTS)


def unavailable_reason() -> str | None:
    """Why the dataset cannot be loaded, phrased for a human. ``None`` if fine."""
    directory = dataset_dir()
    missing = [name for name in EXPECTED_DIGESTS if not (directory / name).exists()]
    if missing:
        return (
            f"UNSW-NB15 is not present in {directory}. Missing: {', '.join(sorted(missing))}. "
            f"Fetch it with `{FETCH_COMMAND}` (230 MB, from {SOURCE_URL})."
        )
    return None


def verify_digests() -> dict[str, str]:
    """Hash every shard and refuse any that does not match the recorded value."""
    directory = dataset_dir()
    digests: dict[str, str] = {}
    for name, expected in sorted(EXPECTED_DIGESTS.items()):
        path = directory / name
        actual = file_digest(path)
        if actual != expected:
            raise DatasetUnavailable(
                f"{name} hashes to {actual}, expected {expected}. The file on disk is not "
                "the one this project's published results were computed from; refusing to "
                "evaluate against unidentified data."
            )
        digests[name] = actual
    return digests


def _selected(key: str, fraction: float, salt: str) -> bool:
    """Deterministic hash-based membership test.

    Subsampling by hash rather than by shuffling keeps the subset a pure
    function of the data: the same rows are chosen regardless of read order,
    and every copy of a duplicated flow is chosen or rejected together.
    """
    digest = hashlib.sha256(f"{salt}:{key}".encode()).digest()
    # First 8 bytes as a fraction of the 64-bit space.
    value = int.from_bytes(digest[:8], "big") / float(1 << 64)
    return value < fraction


def load(
    *,
    max_samples: int | None = 200_000,
    salt: str = "aegisx-v4",
    verify: bool = True,
) -> EvaluationDataset:
    """Load, label, adapt and normalize the corpus.

    ``max_samples`` is an approximate ceiling: the hash-based subsample cannot
    hit an exact count without breaking either determinism or group integrity,
    and inventing a truncation to reach a round number would bias the tail of
    the capture. The realised count is recorded in ``sampling``.
    """
    reason = unavailable_reason()
    if reason:
        raise DatasetUnavailable(reason)

    try:
        import pandas as pd
    except ImportError as exc:  # pragma: no cover - dependency is pinned
        raise DatasetUnavailable(
            "pandas is required to read the UNSW-NB15 parquet shards. "
            "Install the backend requirements."
        ) from exc

    digests = verify_digests() if verify else {}
    directory = dataset_dir()

    frames = [
        pd.read_parquet(directory / name, columns=list(adapter.REQUIRED_COLUMNS))
        for name in sorted(EXPECTED_DIGESTS)
    ]
    frame = pd.concat(frames, ignore_index=True)
    source_rows = len(frame)

    fraction = 1.0
    if max_samples is not None and max_samples < source_rows:
        fraction = max_samples / source_rows

    samples: list[EvaluationSample] = []
    unknown_labels: dict[str, int] = {}
    inconsistent = 0
    unmappable = 0

    for index, row in enumerate(frame.to_dict("records")):
        raw_label = row.get("attack_cat")
        # pandas reads the benign NULL as NaN or None depending on the dtype.
        original = "" if raw_label is None or raw_label != raw_label else str(raw_label)

        category = RAW_LABEL_MAP.get(original)
        if category is None:
            unknown_labels[original] = unknown_labels.get(original, 0) + 1
            continue

        is_malicious = category != LABEL_SCHEMA.benign_category
        if bool(int(row.get("label") or 0)) != is_malicious:
            inconsistent += 1
            continue

        key = adapter.group_key(row)
        if fraction < 1.0 and not _selected(key, fraction, salt):
            continue

        try:
            samples.append(
                adapter.to_sample(
                    row, index=index, category=category, is_malicious=is_malicious
                )
            )
        except adapter.AdapterError:
            unmappable += 1

    if unknown_labels:
        raise DatasetUnavailable(
            "Unrecognised attack_cat values in the source: "
            f"{sorted(unknown_labels)}. Add them to RAW_LABEL_MAP with a documented "
            "meaning rather than letting them be coerced into an existing class."
        )
    if inconsistent:
        raise DatasetUnavailable(
            f"{inconsistent} records disagree between `label` and `attack_cat`. "
            "The source is expected to be internally consistent; refusing to guess "
            "which column is right."
        )

    samples.sort(key=lambda sample: (sample.timestamp, sample.id))

    provenance = DatasetProvenance(
        source=SOURCE_URL,
        license=(
            "Free for academic research use with attribution; released by UNSW "
            "Canberra. Redistribution terms are the publisher's, not AEGISX's - "
            "the corpus is fetched by the operator and never committed."
        ),
        citation=(
            "Moustafa, N. & Slay, J. (2015). UNSW-NB15: a comprehensive data set for "
            "network intrusion detection systems. MilCIS 2015."
        ),
        description=(
            "2,280,090 labelled network flows captured by the Australian Centre for "
            "Cyber Security, spanning normal traffic and nine attack families."
        ),
        file_digests=digests,
        notes=PROVENANCE_NOTES,
    )

    sampling = {
        "strategy": "deterministic hash of the duplicate group key",
        "salt": salt,
        "requestedMax": max_samples,
        "sourceRows": source_rows,
        "selectedRows": len(samples),
        "targetFraction": round(fraction, 8),
        "unmappableRows": unmappable,
        "note": (
            "Group-keyed so every copy of a duplicated flow is selected or rejected "
            "together. The realised count is not exactly the requested maximum; "
            "forcing it would either break determinism or truncate the capture tail."
        ),
    }

    dataset = EvaluationDataset(
        name=DATASET_NAME,
        version=DATASET_VERSION,
        provenance=provenance,
        label_schema=LABEL_SCHEMA,
        samples=samples,
        sampling=sampling,
    )
    logger.info(
        "Loaded %s v%s: %d samples (%d malicious) from %d source rows, fingerprint %s",
        dataset.name,
        dataset.version,
        len(dataset),
        dataset.malicious_count,
        source_rows,
        dataset.fingerprint(),
    )
    return dataset


def describe_unavailable() -> dict[str, Any]:
    """Dataset card fragment for when the corpus is absent.

    An empty research panel must still say *why* it is empty - the same rule the
    rest of AEGISX follows for ML, AI and threat intelligence.
    """
    return {
        "name": DATASET_NAME,
        "version": DATASET_VERSION,
        "available": False,
        "reason": unavailable_reason(),
        "source": SOURCE_URL,
        "fetchCommand": FETCH_COMMAND,
    }
