"""Turning many analyst claims about one detection into a validated verdict.

**Why this exists.** Until V7 there was nothing between a feedback row and a
training set. ``datasets.build`` selected every current training-eligible row
and materialised each one as a member, so if two analysts disagreed about the
same event and neither had been superseded, **both rows became members with
opposite ``binary_label``**. The disagreement did not raise anything, did not
exclude anything, and did not appear in the snapshot's provenance. A model was
simply fitted on both answers.

That is the gap this module closes. The pipeline V7 wants is

    telemetry -> analyst review -> feedback record -> *validated feedback* -> candidate

and not

    telemetry -> automatic truth

**A claim is evidence. A verdict is a conclusion drawn from evidence.** The two
are separate types here on purpose, and the conclusion is allowed to be "these
analysts do not agree, so this target has no verdict".

Four rules, each of which exists because the obvious alternative is wrong:

**One analyst has one voice.** An analyst who wrote three rows about a target
votes once, with their latest active row. Counting all three would let a single
person outvote a colleague by being verbose.

**Abstentions are counted as abstentions.** ``suspicious`` and ``uncertain``
carry no position on the malicious/benign axis - ``FeedbackLabel.binary_label``
returns ``None`` for both - so they are recorded as abstaining and never as
agreement. This is the same doctrine ``labels.py`` states; adjudication is where
it would have been quietly lost.

**Disagreement fails closed.** Under the default policy any dissent produces
``CONFLICTED``, which is *not* training-eligible. A conflicted target is not a
problem to be resolved by arithmetic; it is a signal that the target needs a
human, and a training set that silently picked a side would bury it.

**Confidence is reported, never used to break a tie.** ``agreeing_weight`` and
``dissenting_weight`` are on the result so a reviewer can see the strength
behind each side. They deliberately do not decide anything: letting a stated
confidence settle a disagreement would let one over-confident analyst overrule
two careful ones, and confidence is self-reported.

**Nothing here writes.** It reads rows and returns dataclasses.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from enum import Enum

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.adaptation.feedback.labels import FeedbackLabel, FeedbackTargetType
from app.models.adaptation import AnalystFeedback


class ConsensusStatus(str, Enum):
    """What the analysts collectively said about one target."""

    #: Every analyst who took a position took the same one.
    UNANIMOUS = "unanimous"
    #: A strict majority took one position. Only reachable under
    #: ``POLICY_MAJORITY``; never produced by the default policy.
    MAJORITY = "majority"
    #: Analysts disagree, and the policy in force does not resolve it.
    CONFLICTED = "conflicted"
    #: Nobody took a position: no feedback, or only abstentions.
    INSUFFICIENT = "insufficient"


#: Any dissent leaves the target without a verdict. The default, because a
#: training set is the wrong place to discover that a SOC disagrees with itself.
POLICY_UNANIMOUS = "unanimous"
#: A strict majority carries. A tie is still ``CONFLICTED``. Opt-in, for
#: deployments with enough reviewers per target for a majority to mean something.
POLICY_MAJORITY = "majority"
POLICIES = (POLICY_UNANIMOUS, POLICY_MAJORITY)

#: Statuses whose verdict may become a training example.
_ELIGIBLE_STATUSES = frozenset({ConsensusStatus.UNANIMOUS, ConsensusStatus.MAJORITY})


@dataclass(frozen=True)
class AnalystVote:
    """One analyst's current position on one target."""

    analyst: str
    feedback_id: int
    label: str
    #: ``None`` for an abstention - the label carries no malicious/benign
    #: position. Never coerced to a side.
    binary_label: bool | None
    confidence: float | None
    analyst_role: str | None = None

    @property
    def abstains(self) -> bool:
        return self.binary_label is None


@dataclass(frozen=True)
class AdjudicatedVerdict:
    """The conclusion drawn from every current claim about one target.

    ``binary_label`` is ``None`` unless the verdict is training-eligible. A
    consumer that needs a label and finds ``None`` must exclude the target
    rather than default it - the same contract ``FeedbackLabel.binary_label``
    holds, carried up one level.
    """

    target_type: str
    target_id: int
    status: ConsensusStatus
    binary_label: bool | None
    votes: tuple[AnalystVote, ...]
    agreeing: int
    dissenting: int
    abstaining: int
    #: Summed stated confidence behind each side. Evidence for a reviewer, not
    #: an input to the decision - see the module docstring.
    agreeing_weight: float
    dissenting_weight: float
    policy: str

    @property
    def is_training_eligible(self) -> bool:
        """Whether this verdict may become a training example.

        False for ``CONFLICTED`` and ``INSUFFICIENT``. This is the property
        that stops feedback becoming ground truth by default.
        """
        return self.status in _ELIGIBLE_STATUSES and self.binary_label is not None

    @property
    def analysts(self) -> tuple[str, ...]:
        return tuple(vote.analyst for vote in self.votes)

    def as_dict(self) -> dict:
        """Provenance shape, for storing beside a snapshot or showing a reviewer."""
        return {
            "targetType": self.target_type,
            "targetId": self.target_id,
            "status": self.status.value,
            "binaryLabel": self.binary_label,
            "trainingEligible": self.is_training_eligible,
            "policy": self.policy,
            "agreeing": self.agreeing,
            "dissenting": self.dissenting,
            "abstaining": self.abstaining,
            "agreeingWeight": round(self.agreeing_weight, 4),
            "dissentingWeight": round(self.dissenting_weight, 4),
            "analysts": sorted(set(self.analysts)),
        }


def _binary(label: str) -> bool | None:
    try:
        return FeedbackLabel(label).binary_label
    except ValueError:
        # An unrecognised label is not a position. Refusing to guess is the
        # whole contract; a stored label this enum does not know about is a
        # schema problem, not a vote.
        return None


def votes_from(rows: Iterable[AnalystFeedback]) -> tuple[AnalystVote, ...]:
    """Collapse feedback rows to one current vote per analyst.

    Rows are expected to be *active* (not superseded). Where an analyst has
    several, the highest ``id`` wins - the latest thing they said. Order of the
    result is by analyst name, so a verdict is deterministic regardless of the
    order rows arrive in.
    """
    latest: dict[str, AnalystFeedback] = {}
    for row in rows:
        current = latest.get(row.analyst)
        if current is None or (row.id or 0) >= (current.id or 0):
            latest[row.analyst] = row

    return tuple(
        AnalystVote(
            analyst=row.analyst,
            feedback_id=row.id,
            label=row.label,
            binary_label=_binary(row.label),
            confidence=row.confidence,
            analyst_role=row.analyst_role,
        )
        for _, row in sorted(latest.items())
    )


def adjudicate(
    votes: Sequence[AnalystVote],
    *,
    target_type: str,
    target_id: int,
    policy: str = POLICY_UNANIMOUS,
) -> AdjudicatedVerdict:
    """Draw a verdict from a set of votes. Pure: no database, no writes."""
    if policy not in POLICIES:
        raise ValueError(f"unknown adjudication policy {policy!r}; known: {list(POLICIES)}")

    positioned = [vote for vote in votes if not vote.abstains]
    abstaining = len(votes) - len(positioned)

    def _weight(side: bool) -> float:
        return sum(
            vote.confidence for vote in positioned
            if vote.binary_label is side and vote.confidence is not None
        )

    malicious = [vote for vote in positioned if vote.binary_label is True]
    benign = [vote for vote in positioned if vote.binary_label is False]

    def _verdict(
        status: ConsensusStatus, binary: bool | None, agreeing: int, dissenting: int
    ) -> AdjudicatedVerdict:
        return AdjudicatedVerdict(
            target_type=target_type,
            target_id=int(target_id),
            status=status,
            binary_label=binary,
            votes=tuple(votes),
            agreeing=agreeing,
            dissenting=dissenting,
            abstaining=abstaining,
            agreeing_weight=_weight(True) if binary is True else _weight(False),
            dissenting_weight=_weight(False) if binary is True else _weight(True),
            policy=policy,
        )

    if not positioned:
        # No feedback at all, or only `suspicious` / `uncertain`. Both mean the
        # same thing here: nobody has concluded anything.
        return _verdict(ConsensusStatus.INSUFFICIENT, None, 0, 0)

    if not benign:
        return _verdict(ConsensusStatus.UNANIMOUS, True, len(malicious), 0)
    if not malicious:
        return _verdict(ConsensusStatus.UNANIMOUS, False, len(benign), 0)

    # Genuine disagreement from here on.
    if policy == POLICY_MAJORITY and len(malicious) != len(benign):
        wins_malicious = len(malicious) > len(benign)
        winning, losing = (
            (malicious, benign) if wins_malicious else (benign, malicious)
        )
        return _verdict(
            ConsensusStatus.MAJORITY, wins_malicious, len(winning), len(losing)
        )

    # Fail closed: a tie, or any dissent under the unanimous policy. The larger
    # side is reported as `agreeing` so a reviewer sees the shape of the split,
    # but `binary_label` stays None and nothing downstream may train on it.
    larger, smaller = (
        (malicious, benign) if len(malicious) >= len(benign) else (benign, malicious)
    )
    return _verdict(ConsensusStatus.CONFLICTED, None, len(larger), len(smaller))


def for_target(
    db: Session,
    *,
    target_type: FeedbackTargetType | str,
    target_id: int,
    policy: str = POLICY_UNANIMOUS,
) -> AdjudicatedVerdict:
    """Adjudicate one target from its current (non-superseded) feedback."""
    resolved = (
        target_type.value
        if isinstance(target_type, FeedbackTargetType)
        else str(target_type)
    )
    rows = list(
        db.scalars(
            select(AnalystFeedback).where(
                AnalystFeedback.target_type == resolved,
                AnalystFeedback.target_id == int(target_id),
                AnalystFeedback.superseded_by_id.is_(None),
            )
        )
    )
    return adjudicate(
        votes_from(rows), target_type=resolved, target_id=target_id, policy=policy
    )


def adjudicate_rows(
    rows: Iterable[AnalystFeedback], *, policy: str = POLICY_UNANIMOUS
) -> dict[tuple[str, int], AdjudicatedVerdict]:
    """Adjudicate a batch of feedback rows, grouped by target.

    This is the form ``datasets.build`` needs: it already holds the selected
    rows, and re-querying per target would both cost a query per row and read a
    *different* set than the one being snapshotted.
    """
    grouped: dict[tuple[str, int], list[AnalystFeedback]] = {}
    for row in rows:
        grouped.setdefault((row.target_type, row.target_id), []).append(row)

    return {
        key: adjudicate(
            votes_from(group), target_type=key[0], target_id=key[1], policy=policy
        )
        for key, group in grouped.items()
    }
