"""Turning a feedback dataset into rows a candidate may be fitted on.

**Why this exists.** V5's Arm 2 purified the fit set, which assumed the fit set
and the observed event stream were the same collection. V6 §5.5 measured that in
production they are not: ``train_anomaly_model`` fits unlabelled runtime
telemetry, so analyst labels had nothing there to purify, and
``train_candidate`` recorded ``feedbackDatasetId`` as **metadata only** -
feedback had never influenced production training at all.

§6 redesigned the arm to *add* analyst-verified benign observed events to the
telemetry corpus, and measured a 23% relative reduction in false positives. §8
then measured that the addition is a poisoning surface a global volume cap
cannot bound, and §9 measured a per-group cap that does. This module is where
all three reach the real pipeline.

**Admission is positive-listed.** A member enters only if its stored
``binary_label`` is ``False`` - the verified-benign projection. ``true_positive``
and ``confirmed_malicious`` are refused; ``suspicious`` and ``uncertain`` never
became dataset members in the first place.

**Vectors come from the stored inference, not from the event's columns.** The
``MLInference`` row holds the vector the model actually scored. Re-deriving one
from ``Event`` would risk training on a vector that was never the one the
analyst's verdict referred to, and the mismatch would be silent.

**Nothing here trains or activates anything.** It returns rows and a count of
what it refused. ``registry.activate_model`` behind an approved proposal remains
the only write into production detection state.
"""

from __future__ import annotations

import logging
from collections import Counter
from dataclasses import dataclass, field

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.adaptation.feedback import caps
from app.models.adaptation import FeedbackDataset, FeedbackDatasetMember
from app.models.event import Event
from app.models.ml import MLInference

logger = logging.getLogger("aegisx.adaptation.augmentation")

#: The production detector. Only its inferences carry vectors comparable with
#: the corpus a candidate is fitted on.
MODEL_NAME = "isolation_forest"

#: Ceiling on the share of a fit set that may come from analyst feedback,
#: matching the bound V6 §6 measured. A volume bound, which §8 established is
#: necessary but not sufficient - see ``cap_policy``.
DEFAULT_MAX_FEEDBACK_FRACTION = 0.20


@dataclass(frozen=True)
class AugmentationResult:
    """Rows admitted, and an account of everything refused.

    The skip counters are not diagnostics. A dataset that silently contributed
    a third of what its sample count implies would make a candidate's training
    provenance wrong, so each refusal is counted and recorded on the model.
    """

    vectors: list[tuple[float, ...]] = field(default_factory=list)
    group_counts: dict[str, int] = field(default_factory=dict)
    cap_policy: str = caps.POLICY_GLOBAL
    skipped_not_benign: int = 0
    skipped_non_event: int = 0
    skipped_no_inference: int = 0
    skipped_incomplete_vector: int = 0
    skipped_by_cap: int = 0

    @property
    def admitted(self) -> int:
        return len(self.vectors)

    def as_dict(self) -> dict:
        return {
            "admitted": self.admitted,
            "groupCounts": dict(self.group_counts),
            "capPolicy": self.cap_policy,
            "skipped": {
                "notBenign": self.skipped_not_benign,
                "nonEvent": self.skipped_non_event,
                "noInference": self.skipped_no_inference,
                "incompleteVector": self.skipped_incomplete_vector,
                "byCap": self.skipped_by_cap,
            },
        }


def baseline_rates(
    db: Session,
    *,
    exclude_dataset_id: int | None = None,
    model_name: str = MODEL_NAME,
) -> dict[str, float]:
    """Mean admitted-benign rows per event type, from **other** datasets.

    §9 learned its baseline from held-out honest seeds. The production analogue
    is excluding the batch currently being admitted: a baseline computed over
    the dataset under review would learn that batch's own spike as normal, which
    is the obvious way to get this wrong.

    **[LIMITATION]** This is still only as trustworthy as the history it reads.
    An adversary patient enough to raise the baseline across several datasets
    would defeat it, exactly as §9.3 recorded.
    """
    statement = (
        select(FeedbackDatasetMember.dataset_id, Event.event_type)
        .join(Event, Event.id == FeedbackDatasetMember.target_id)
        .where(
            FeedbackDatasetMember.binary_label.is_(False),
            FeedbackDatasetMember.target_type == "event",
        )
    )
    if exclude_dataset_id is not None:
        statement = statement.where(FeedbackDatasetMember.dataset_id != exclude_dataset_id)

    rows = list(db.execute(statement))
    if not rows:
        return {}

    datasets_seen = {dataset_id for dataset_id, _ in rows}
    totals = Counter(event_type for _, event_type in rows)
    return {group: count / len(datasets_seen) for group, count in totals.items()}


def build(
    db: Session,
    *,
    dataset: FeedbackDataset,
    feature_names: tuple[str, ...],
    telemetry_rows: int | None = None,
    model_name: str = MODEL_NAME,
    cap_policy: str = caps.POLICY_GLOBAL,
    baseline_rates: dict[str, float] | None = None,
    per_group_ceiling: int | None = None,
    tolerance: float = caps.DEFAULT_TOLERANCE,
    floor: int = caps.DEFAULT_FLOOR,
    max_feedback_fraction: float = DEFAULT_MAX_FEEDBACK_FRACTION,
) -> AugmentationResult:
    """Vectors this dataset contributes to a candidate's fit set."""
    members = list(
        db.scalars(
            select(FeedbackDatasetMember)
            .where(FeedbackDatasetMember.dataset_id == dataset.id)
            .order_by(FeedbackDatasetMember.id.asc())
        )
    )

    skipped_not_benign = 0
    skipped_non_event = 0
    skipped_no_inference = 0
    skipped_incomplete = 0

    #: (member id, event type, vector), before the cap is applied.
    resolved: list[tuple[int, str, tuple[float, ...]]] = []

    for member in members:
        if member.binary_label is not False:
            skipped_not_benign += 1
            continue
        if member.target_type != "event":
            skipped_non_event += 1
            continue

        event = db.get(Event, member.target_id)
        if event is None:
            skipped_no_inference += 1
            continue

        inference = db.scalar(
            select(MLInference)
            .where(
                MLInference.event_id == event.id,
                MLInference.model_name == model_name,
                MLInference.feature_schema_version == dataset.feature_schema_version,
            )
            .order_by(MLInference.id.desc())
        )
        if inference is None or not inference.features:
            skipped_no_inference += 1
            continue

        stored = inference.features
        # Built in `feature_names` order. `features` is JSON and its key order
        # is not a contract; a permuted vector would train silently wrong.
        try:
            vector = tuple(float(stored[name]) for name in feature_names)
        except (KeyError, TypeError, ValueError):
            skipped_incomplete += 1
            continue

        resolved.append((member.id, str(event.event_type), vector))

    # The volume bound, expressed against the fit set this will join.
    if telemetry_rows is not None and max_feedback_fraction > 0:
        global_ceiling = int(
            telemetry_rows * max_feedback_fraction / (1 - max_feedback_fraction)
        )
    else:
        global_ceiling = len(resolved)

    kept = caps.apply(
        [caps.CapCandidate(index=index, group=group) for index, group, _ in resolved],
        policy=cap_policy,
        global_ceiling=global_ceiling,
        per_group_ceiling=per_group_ceiling,
        baseline_rates=baseline_rates,
        tolerance=tolerance,
        floor=floor,
    )
    allowed = {candidate.index for candidate in kept}

    vectors = [vector for index, _, vector in resolved if index in allowed]
    group_counts = dict(
        Counter(group for index, group, _ in resolved if index in allowed)
    )

    result = AugmentationResult(
        vectors=vectors,
        group_counts=group_counts,
        cap_policy=cap_policy,
        skipped_not_benign=skipped_not_benign,
        skipped_non_event=skipped_non_event,
        skipped_no_inference=skipped_no_inference,
        skipped_incomplete_vector=skipped_incomplete,
        skipped_by_cap=len(resolved) - len(allowed),
    )

    logger.info(
        "Feedback augmentation built",
        extra={
            "operation": "adaptation.augmentation_built",
            "dataset": f"{dataset.name}@{dataset.version}",
            "admitted": result.admitted,
            "capPolicy": cap_policy,
        },
    )
    return result
