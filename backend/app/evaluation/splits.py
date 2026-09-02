"""Reproducible, leakage-safe train/validation/test splits.

Two strategies, both deterministic and both group-aware:

``stratified_group``
    Groups are assigned by a hash of the group key, stratified within each
    ground-truth category so a rare class does not land entirely in one split.
    This is the like-for-like comparison: train and test are drawn from the
    same distribution.

``temporal``
    Groups are ordered by their earliest observation and cut chronologically.
    This answers a different question - how a detector fitted on the past
    behaves on the future - and on a non-stationary corpus it will produce
    materially worse numbers than the random split.

**Neither is "the right one".** They measure different things, and which is
appropriate depends on the claim being made. The rule this module exists to
enforce is that the choice is declared in the split plan, recorded in the
experiment, and made *before* the metrics are seen - never selected afterwards
because it produced a nicer table.

Group integrity is the non-negotiable part. Every sample sharing a group key
lands in exactly one split. On UNSW-NB15, 46% of rows are exact duplicates of
another row; without this, a model would be tested on flows it had already
memorised and every metric would be inflated.
"""

from __future__ import annotations

import hashlib
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from app.evaluation.datasets.base import EvaluationDataset, EvaluationSample

TRAIN = "train"
VALIDATION = "validation"
TEST = "test"
SPLIT_NAMES = (TRAIN, VALIDATION, TEST)

STRATIFIED_GROUP = "stratified_group"
TEMPORAL = "temporal"


class SplitError(ValueError):
    """Raised when a split cannot be produced without violating an invariant."""


@dataclass
class Split:
    """One partition of a dataset."""

    name: str
    samples: list[EvaluationSample] = field(default_factory=list)

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

    def time_range(self) -> tuple[datetime | None, datetime | None]:
        if not self.samples:
            return None, None
        stamps = [sample.timestamp for sample in self.samples]
        return min(stamps), max(stamps)

    def group_keys(self) -> set[str]:
        return {sample.grouping for sample in self.samples}

    def to_dict(self) -> dict[str, Any]:
        start, end = self.time_range()
        return {
            "name": self.name,
            "samples": len(self.samples),
            "malicious": self.malicious_count,
            "benign": self.benign_count,
            "maliciousRate": (
                round(self.malicious_count / len(self.samples), 6) if self.samples else None
            ),
            "distinctGroups": len(self.group_keys()),
            "classCounts": self.class_counts(),
            "firstEvent": start.isoformat() if start else None,
            "lastEvent": end.isoformat() if end else None,
        }


@dataclass
class SplitPlan:
    """A realised split, with everything needed to reproduce and audit it."""

    strategy: str
    seed: int
    fractions: dict[str, float]
    dataset_name: str
    dataset_version: str
    dataset_fingerprint: str
    train: Split
    validation: Split
    test: Split
    rationale: str
    warnings: tuple[str, ...] = ()

    def splits(self) -> dict[str, Split]:
        return {TRAIN: self.train, VALIDATION: self.validation, TEST: self.test}

    def fingerprint(self) -> str:
        """Hash of the exact membership, so a stored result proves its split.

        The seed is deliberately *not* part of this. Two plans that place the
        same samples in the same splits are the same split, whatever knob
        produced them - which is why a temporal split, being chronological,
        fingerprints identically across seeds. The seed is recorded separately
        in ``to_dict`` for reproduction.
        """
        digest = hashlib.sha256()
        digest.update(f"{self.strategy}:{self.dataset_fingerprint}".encode())
        for name in SPLIT_NAMES:
            digest.update(name.encode())
            for sample in self.splits()[name].samples:
                digest.update(sample.id.encode())
                digest.update(b"\x00")
        return digest.hexdigest()[:16]

    def to_dict(self) -> dict[str, Any]:
        return {
            "strategy": self.strategy,
            "seed": self.seed,
            "fractions": self.fractions,
            "fingerprint": self.fingerprint(),
            "dataset": {
                "name": self.dataset_name,
                "version": self.dataset_version,
                "fingerprint": self.dataset_fingerprint,
            },
            "rationale": self.rationale,
            "warnings": list(self.warnings),
            "splits": {name: split.to_dict() for name, split in self.splits().items()},
        }


def _group_value(key: str, seed: int) -> float:
    """Deterministic uniform value in [0, 1) for a group key."""
    digest = hashlib.sha256(f"{seed}:{key}".encode()).digest()
    return int.from_bytes(digest[:8], "big") / float(1 << 64)


def _validate_fractions(fractions: dict[str, float]) -> None:
    missing = [name for name in SPLIT_NAMES if name not in fractions]
    if missing:
        raise SplitError(f"missing split fractions: {missing}")
    total = sum(fractions[name] for name in SPLIT_NAMES)
    if abs(total - 1.0) > 1e-9:
        raise SplitError(f"split fractions must sum to 1.0, got {total}")
    if any(fractions[name] < 0 for name in SPLIT_NAMES):
        raise SplitError("split fractions must be non-negative")


def _groups(dataset: EvaluationDataset) -> dict[str, list[EvaluationSample]]:
    groups: dict[str, list[EvaluationSample]] = defaultdict(list)
    for sample in dataset.samples:
        groups[sample.grouping].append(sample)
    return groups


def _group_label(members: list[EvaluationSample]) -> bool:
    """The binary ground truth of a group.

    Stratification keys on the binary label rather than the attack category,
    because the binary label is the axis every detector is scored on and the
    only one duplicates are guaranteed to agree about. A group whose members
    disagree about *whether* they are malicious is a contradiction in the data
    and the split refuses rather than picking a winner.

    Category is deliberately allowed to vary within a group. On UNSW-NB15, 117
    duplicate groups (0.09%, 3,055 rows) of byte-identical malicious flows
    carry up to seven different attack families - the same observation labelled
    differently by the capture's own taxonomy. That ambiguity is real, is
    measured by :func:`category_ambiguity`, and is reported next to the
    per-class metrics it limits. Splitting those groups apart to make the
    categories tidy would let a memorised flow cross into test, trading a
    reporting inconvenience for an inflated metric.
    """
    labels = {member.is_malicious for member in members}
    if len(labels) > 1:
        raise SplitError(
            "duplicate group carries conflicting labels "
            f"{sorted({m.category for m in members})}; identical observations "
            "disagree about whether they are malicious, and the dataset must resolve "
            "this before it can be split"
        )
    return labels.pop()


def category_ambiguity(groups: dict[str, list[EvaluationSample]]) -> dict[str, Any]:
    """How much of the corpus carries an ambiguous attack category."""
    ambiguous = {
        key: members
        for key, members in groups.items()
        if len({member.category for member in members}) > 1
    }
    rows = sum(len(members) for members in ambiguous.values())
    total_rows = sum(len(members) for members in groups.values())
    return {
        "ambiguousGroups": len(ambiguous),
        "totalGroups": len(groups),
        "affectedSamples": rows,
        "share": round(rows / total_rows, 6) if total_rows else None,
        "note": (
            "Groups of identical observations whose members carry different attack "
            "categories. The binary label is unaffected; only per-class breakdowns are."
        ),
    }


def _assemble(assignment: dict[str, str], groups: dict[str, list[EvaluationSample]]) -> dict[str, Split]:
    splits = {name: Split(name=name) for name in SPLIT_NAMES}
    for key, members in groups.items():
        splits[assignment[key]].samples.extend(members)
    for split in splits.values():
        split.samples.sort(key=lambda sample: (sample.timestamp, sample.id))
    return splits


def _ambiguity_warnings(groups: dict[str, list[EvaluationSample]]) -> list[str]:
    ambiguity = category_ambiguity(groups)
    if not ambiguity["ambiguousGroups"]:
        return []
    return [
        f"{ambiguity['ambiguousGroups']} duplicate group(s) covering "
        f"{ambiguity['affectedSamples']} sample(s) carry more than one attack category. "
        "The binary metrics are unaffected; per-class detection rates for those "
        "families are correspondingly uncertain."
    ]


def stratified_group_split(
    dataset: EvaluationDataset,
    *,
    seed: int = 1337,
    fractions: dict[str, float] | None = None,
) -> SplitPlan:
    """Random split, group-aware and stratified by ground-truth category."""
    fractions = fractions or {TRAIN: 0.6, VALIDATION: 0.2, TEST: 0.2}
    _validate_fractions(fractions)

    groups = _groups(dataset)
    by_label: dict[bool, list[str]] = defaultdict(list)
    for key, members in groups.items():
        by_label[_group_label(members)].append(key)

    assignment: dict[str, str] = {}
    for _label, keys in sorted(by_label.items()):
        # Order by hash, not by insertion: a deterministic shuffle that does not
        # depend on how the loader happened to iterate the source.
        ordered = sorted(keys, key=lambda key: (_group_value(key, seed), key))
        total = len(ordered)
        train_end = int(round(total * fractions[TRAIN]))
        val_end = train_end + int(round(total * fractions[VALIDATION]))
        for index, key in enumerate(ordered):
            if index < train_end:
                assignment[key] = TRAIN
            elif index < val_end:
                assignment[key] = VALIDATION
            else:
                assignment[key] = TEST

    splits = _assemble(assignment, groups)

    warnings: list[str] = []
    for label, keys in sorted(by_label.items()):
        if len(keys) < len(SPLIT_NAMES):
            warnings.append(
                f"the {'malicious' if label else 'benign'} class has only {len(keys)} "
                "distinct group(s); it cannot be represented in every split"
            )
    warnings.extend(_ambiguity_warnings(groups))

    return SplitPlan(
        strategy=STRATIFIED_GROUP,
        seed=seed,
        fractions=dict(fractions),
        dataset_name=dataset.name,
        dataset_version=dataset.version,
        dataset_fingerprint=dataset.fingerprint(),
        train=splits[TRAIN],
        validation=splits[VALIDATION],
        test=splits[TEST],
        rationale=(
            "Random split, stratified by ground-truth category and keyed on duplicate "
            "groups. Measures performance on traffic drawn from the same distribution "
            "as training. Chosen as the primary comparison because it isolates the "
            "detector from distribution shift; the temporal split reports the shifted "
            "case separately."
        ),
        warnings=tuple(warnings),
    )


def temporal_split(
    dataset: EvaluationDataset,
    *,
    seed: int = 1337,
    fractions: dict[str, float] | None = None,
) -> SplitPlan:
    """Chronological split: fit on the past, evaluate on the future."""
    fractions = fractions or {TRAIN: 0.6, VALIDATION: 0.2, TEST: 0.2}
    _validate_fractions(fractions)

    groups = _groups(dataset)
    # A group is placed by its earliest observation, and travels whole. Cutting
    # a duplicate group at the boundary would leak a memorised flow forward.
    ordered = sorted(
        groups.items(), key=lambda item: (min(m.timestamp for m in item[1]), item[0])
    )
    total = len(ordered)
    train_end = int(round(total * fractions[TRAIN]))
    val_end = train_end + int(round(total * fractions[VALIDATION]))

    assignment: dict[str, str] = {}
    for index, (key, _members) in enumerate(ordered):
        if index < train_end:
            assignment[key] = TRAIN
        elif index < val_end:
            assignment[key] = VALIDATION
        else:
            assignment[key] = TEST

    splits = _assemble(assignment, groups)

    warnings: list[str] = list(_ambiguity_warnings(groups))
    train_end_time = splits[TRAIN].time_range()[1]
    test_start_time = splits[TEST].time_range()[0]
    if train_end_time and test_start_time and train_end_time > test_start_time:
        warnings.append(
            "Group boundaries overlap in time: some training rows are timestamped after "
            "the first test row because a duplicate group spans the cut and is kept "
            "whole. Group integrity was preferred over an exact chronological line."
        )

    rates = {
        name: (split.malicious_count / len(split) if len(split) else None)
        for name, split in splits.items()
    }
    known = [rate for rate in rates.values() if rate is not None]
    if known and (max(known) - min(known)) > 0.05:
        warnings.append(
            "Attack density differs sharply between splits "
            f"({ {k: (round(v, 4) if v is not None else None) for k, v in rates.items()} }). "
            "This is a property of the capture, not a defect of the split, but it means "
            "temporal results measure distribution shift as much as detector quality."
        )

    return SplitPlan(
        strategy=TEMPORAL,
        seed=seed,
        fractions=dict(fractions),
        dataset_name=dataset.name,
        dataset_version=dataset.version,
        dataset_fingerprint=dataset.fingerprint(),
        train=splits[TRAIN],
        validation=splits[VALIDATION],
        test=splits[TEST],
        rationale=(
            "Chronological split on the earliest observation of each duplicate group. "
            "Measures the operationally honest question - a detector fitted on past "
            "traffic meeting future traffic - and on a non-stationary capture it is "
            "expected to score worse than the random split. Reported alongside it, "
            "never instead of it."
        ),
        warnings=tuple(warnings),
    )


STRATEGIES = {
    STRATIFIED_GROUP: stratified_group_split,
    TEMPORAL: temporal_split,
}


def build_split(
    dataset: EvaluationDataset,
    *,
    strategy: str = STRATIFIED_GROUP,
    seed: int = 1337,
    fractions: dict[str, float] | None = None,
) -> SplitPlan:
    builder = STRATEGIES.get(strategy)
    if builder is None:
        raise SplitError(f"unknown split strategy {strategy!r}; known: {sorted(STRATEGIES)}")
    return builder(dataset, seed=seed, fractions=fractions)
