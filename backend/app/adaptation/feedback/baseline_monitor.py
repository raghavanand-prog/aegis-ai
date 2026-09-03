"""Detecting a patient baseline-poisoning campaign.

V6 §11 lowered ``caps.DEFAULT_TOLERANCE`` to 1.5, which **bounds** the ratchet an
adversary can achieve. It does not **detect** one, and §11.5.4 was explicit about
why: every batch in such a campaign is within policy by construction, so there is
nothing for a policy check to fire on. The ratchet was only visible in the
experiment because an honest control was run alongside it.

**The signal is not what gets admitted.** Measured while building this module: at
the default tolerance an adversary's *admitted* counts are **flatter than
honest** - a growth ratio of 1.03 against honest 1.34 - because the cap clamps
precisely the quantity a naive monitor would watch. A working cap erases its own
evidence, and a monitor built on admitted volume would go quiet exactly when it
mattered.

**What the cap does not touch is what an analyst submits.** A group whose
benign-labelled submissions persistently dwarf its own historical rate is the
signature. Over 12 seeds and 10 cycles:

===================  ==========  ==========
arm                  mean ratio  range
===================  ==========  ==========
honest               1.22        0.60-1.85
patient adversary    15.79       9.34-20.70
===================  ==========  ==========

The bands below sit in the empty gap between 1.85 and 9.34.

**This is advisory.** V5 decision 25 - drift is a signal, not a verdict - applies
here. The cap does the blocking; this makes an otherwise invisible campaign
visible to a person. It writes nothing and refuses nothing.
"""

from __future__ import annotations

import statistics
from collections import Counter, defaultdict
from dataclasses import dataclass, field

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.adaptation.drift.metrics import DriftStatus, classify
from app.models.adaptation import FeedbackDataset, FeedbackDatasetMember
from app.models.event import Event

#: Suppression ratio bands. Chosen from the measured gap between honest
#: campaigns (max 1.85) and adversarial ones (min 9.34), not from a standard.
MODERATE_RATIO = 3.0
SIGNIFICANT_RATIO = 6.0

#: A baseline this small makes the ratio meaningless - one extra verdict on a
#: rare event type would read as a tenfold spike. Ratios are computed against
#: at least this, so a rare group needs real volume to flag.
MIN_BASELINE = 1.0

#: Below this many prior datasets there is no baseline worth the name.
MIN_HISTORY = 2


@dataclass(frozen=True)
class GroupFinding:
    """One event type, its history, and what this batch did."""

    group: str
    submitted: int
    baseline_rate: float
    suppression_ratio: float
    status: DriftStatus
    datasets_in_baseline: int
    #: True where the group has no history at all. A new event type is not
    #: evidence of an attack; it is reported so a person can look.
    unbaselined: bool = False

    def as_dict(self) -> dict:
        return {
            "group": self.group,
            "submitted": self.submitted,
            "baselineRate": round(self.baseline_rate, 4),
            "suppressionRatio": round(self.suppression_ratio, 4),
            "status": self.status.value,
            "datasetsInBaseline": self.datasets_in_baseline,
            "unbaselined": self.unbaselined,
        }


@dataclass(frozen=True)
class BaselineReport:
    dataset_id: int
    findings: dict[str, GroupFinding] = field(default_factory=dict)
    flagged: list[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "datasetId": self.dataset_id,
            "findings": {
                group: finding.as_dict() for group, finding in sorted(self.findings.items())
            },
            "flagged": list(self.flagged),
            "thresholds": {
                "moderateRatio": MODERATE_RATIO,
                "significantRatio": SIGNIFICANT_RATIO,
                "minBaseline": MIN_BASELINE,
                "minHistory": MIN_HISTORY,
            },
            "interpretation": (
                "Advisory. This blocks nothing and refuses nothing - the "
                "per-group cap does the bounding. A flagged group is one whose "
                "benign-labelled submissions far exceed its own history, which "
                "is the signature of a campaign feeding the baseline rather "
                "than fighting the cap. Investigate the analysts contributing "
                "to it; do not treat the flag as a finding of fact."
            ),
        }


def _submissions_by_dataset(db: Session) -> dict[int, Counter[str]]:
    """Benign-labelled submissions per group, per dataset.

    Reads membership rather than admissions: the cap clamps what is admitted, so
    admissions cannot show a campaign the cap is suppressing.

    **A feedback dataset is a cumulative snapshot**, not an incremental batch -
    ``datasets.build`` selects every current non-superseded training-eligible
    row. Counts therefore grow across snapshots even under honest use, which is
    why the comparison is a *ratio against the mean of prior snapshots* rather
    than a difference: steady honest accumulation keeps the ratio near 1, while
    a campaign appears as a step.
    """
    rows = db.execute(
        select(FeedbackDatasetMember.dataset_id, Event.event_type)
        .join(Event, Event.id == FeedbackDatasetMember.target_id)
        .where(
            FeedbackDatasetMember.binary_label.is_(False),
            FeedbackDatasetMember.target_type == "event",
        )
    )
    counts: dict[int, Counter[str]] = defaultdict(Counter)
    for dataset_id, event_type in rows:
        counts[dataset_id][event_type] += 1
    return counts


def assess(db: Session, *, dataset_id: int) -> BaselineReport:
    """Compare one dataset's submissions against the history before it."""
    dataset = db.get(FeedbackDataset, dataset_id)
    if dataset is None:
        raise ValueError(f"No feedback dataset with id {dataset_id}")

    by_dataset = _submissions_by_dataset(db)
    current = by_dataset.get(dataset_id, Counter())

    # Strictly prior datasets. Including the batch under review would let it
    # sanction itself - the same error the cap's baseline avoids.
    prior_ids = [
        other.id
        for other in db.scalars(
            select(FeedbackDataset)
            .where(FeedbackDataset.id != dataset_id)
            .order_by(FeedbackDataset.id.asc())
        )
        if other.id in by_dataset
    ]
    if len(prior_ids) < MIN_HISTORY:
        raise ValueError(
            f"Only {len(prior_ids)} prior feedback datasets; at least "
            f"{MIN_HISTORY} are needed before a group's history means anything. "
            "Reporting a ratio against one batch would be noise with a status "
            "attached."
        )

    findings: dict[str, GroupFinding] = {}
    flagged: list[str] = []

    for group, submitted in current.items():
        history = [by_dataset[i].get(group, 0) for i in prior_ids]
        seen_in = sum(1 for value in history if value > 0)
        baseline = statistics.fmean(history) if history else 0.0

        if seen_in == 0:
            findings[group] = GroupFinding(
                group=group,
                submitted=submitted,
                baseline_rate=0.0,
                suppression_ratio=0.0,
                status=DriftStatus.STABLE,
                datasets_in_baseline=0,
                unbaselined=True,
            )
            continue

        ratio = submitted / max(baseline, MIN_BASELINE)
        status = classify(
            ratio, moderate=MODERATE_RATIO, significant=SIGNIFICANT_RATIO
        )
        findings[group] = GroupFinding(
            group=group,
            submitted=submitted,
            baseline_rate=baseline,
            suppression_ratio=ratio,
            status=status,
            datasets_in_baseline=len(prior_ids),
        )
        if status is not DriftStatus.STABLE:
            flagged.append(group)

    return BaselineReport(
        dataset_id=dataset_id, findings=findings, flagged=sorted(flagged)
    )
