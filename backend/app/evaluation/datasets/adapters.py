"""Bring the V3 synthetic corpus into the V4 dataset abstraction.

The V3 labelled dataset is not replaced. It remains the only corpus that can
exercise AEGISX's endpoint, identity and process rules, and therefore the only
one on which "rules vs ML vs hybrid" is a meaningful comparison. This adapter
lets it run through the same experiment machinery as the public corpus, so the
two are measured by identical code.

The V3 ``Label`` enum is preserved as the category axis rather than flattened,
because which attack classes a detector cannot see is the most useful thing the
per-class breakdown reports.
"""

from __future__ import annotations

from app.evaluation.datasets.base import (
    DatasetProvenance,
    EvaluationDataset,
    EvaluationSample,
    LabelSchema,
)
from app.evaluation.datasets.labeled_dataset import (
    DATASET_NAME,
    DATASET_VERSION,
    DEFAULT_SEED,
    build_dataset,
)
from app.evaluation.labels import Label

BENIGN = Label.BENIGN.value

SYNTHETIC_LABEL_SCHEMA = LabelSchema(
    name="aegisx-detection-eval-labels",
    version="1.0",
    mapping={label.value: label.value for label in Label},
    malicious_categories=tuple(
        label.value for label in Label if label is not Label.BENIGN
    ),
    benign_category=BENIGN,
    excluded={},
    notes=(
        "Labels are assigned at generation time and never inferred from detector "
        "output, so the measurement is not circular.",
        "LATERAL_MOVEMENT is included deliberately with no corresponding rule. It "
        "measures what the rule set cannot see, and excluding it would flatter recall.",
        "This taxonomy is NOT merged with UNSW-NB15's. They describe different "
        "telemetry classes.",
    ),
)


def synthetic_dataset(*, seed: int = DEFAULT_SEED, samples_per_class: int | None = None) -> EvaluationDataset:
    """Build the V3 labelled corpus and present it as a V4 dataset."""
    kwargs = {"seed": seed}
    if samples_per_class is not None:
        kwargs["samples_per_class"] = samples_per_class
    dataset = build_dataset(**kwargs)
    dataset.normalize_all()

    samples = [
        EvaluationSample(
            id=sample.id,
            category=sample.label.value,
            is_malicious=sample.is_malicious,
            candidate=sample.candidate,
            timestamp=sample.candidate["timestamp"],
            # Each generated sample is independent; there are no duplicates to
            # group, so a sample is its own group.
            group_key=None,
            original_label=sample.label.value,
        )
        for sample in dataset.samples
    ]

    provenance = DatasetProvenance(
        source="app.evaluation.datasets.labeled_dataset (generated in-process)",
        license="Part of AEGISX; no third-party terms apply.",
        citation="AEGISX synthetic detection-evaluation corpus, V2/V3.",
        description=(
            "Deterministically generated vendor-shaped records covering thirteen attack "
            "classes plus benign traffic, including deliberate near-miss benign samples "
            "just under each rule threshold."
        ),
        notes=(
            "Synthetic. Nothing here is evidence about real-world attack traffic.",
            "Built to exercise rule thresholds, which makes it out of distribution for "
            "the anomaly model trained on the runtime telemetry generator - ML metrics "
            "on this corpus are a lower bound.",
            "Benign samples include activity that legitimately looks suspicious (an "
            "administrator running certutil, a backup job moving large volumes), so the "
            "false-positive rate is not flattered.",
        ),
    )

    return EvaluationDataset(
        name=DATASET_NAME,
        version=DATASET_VERSION,
        provenance=provenance,
        label_schema=SYNTHETIC_LABEL_SCHEMA,
        samples=samples,
        sampling={
            "strategy": "generated",
            "seed": seed,
            "note": "Fully generated; no subsampling of a larger source.",
        },
    )
