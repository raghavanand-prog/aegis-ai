"""The analyst feedback vocabulary.

Six labels, and the distinctions between them are the point. A SOC analyst
closing an alert is answering more than one question - *was the detector right*
and *was this actually an attack* are different questions, and a vocabulary that
collapses them produces a training set that cannot tell the difference either.

Two properties carry that distinction into every downstream consumer:

``is_verdict``
    Whether the label expresses an opinion about the detector at all.
    ``uncertain`` does not. Counting it as agreement or disagreement records the
    analyst's hesitation as ground truth.

``is_training_eligible``
    Whether the label is confident enough to become a training example.
    ``suspicious`` and ``uncertain`` describe a state of investigation, not a
    class, and neither belongs in a label column.
"""

from __future__ import annotations

from enum import Enum


class FeedbackTargetType(str, Enum):
    """What an analyst is giving feedback about."""

    EVENT = "event"
    INCIDENT = "incident"
    SEQUENCE = "sequence"


class FeedbackLabel(str, Enum):
    """An analyst's claim about one detection."""

    #: The detector fired and was right.
    TRUE_POSITIVE = "true_positive"
    #: The detector fired and was wrong.
    FALSE_POSITIVE = "false_positive"
    #: Reviewed and found to be ordinary activity.
    BENIGN = "benign"
    #: Worth watching, not concluded. Deliberately not trainable.
    SUSPICIOUS = "suspicious"
    #: Established as malicious, usually with evidence beyond the alert.
    CONFIRMED_MALICIOUS = "confirmed_malicious"
    #: The analyst could not decide. Recorded, never counted.
    UNCERTAIN = "uncertain"

    @property
    def is_verdict(self) -> bool:
        """Whether this label expresses an opinion about the detector."""
        return self is not FeedbackLabel.UNCERTAIN

    @property
    def is_training_eligible(self) -> bool:
        """Whether this label may become a training example."""
        return self in _TRAINING_ELIGIBLE

    @property
    def binary_label(self) -> bool | None:
        """Projection onto the malicious/benign axis, or ``None``.

        ``None`` is not "unknown, assume benign". It means the label carries no
        position on this axis, and a consumer that needs one must exclude the
        row rather than default it.
        """
        return _BINARY_PROJECTION[self]


_TRAINING_ELIGIBLE: frozenset[FeedbackLabel] = frozenset(
    {
        FeedbackLabel.TRUE_POSITIVE,
        FeedbackLabel.FALSE_POSITIVE,
        FeedbackLabel.BENIGN,
        FeedbackLabel.CONFIRMED_MALICIOUS,
    }
)

_BINARY_PROJECTION: dict[FeedbackLabel, bool | None] = {
    FeedbackLabel.TRUE_POSITIVE: True,
    FeedbackLabel.CONFIRMED_MALICIOUS: True,
    FeedbackLabel.FALSE_POSITIVE: False,
    FeedbackLabel.BENIGN: False,
    FeedbackLabel.SUSPICIOUS: None,
    FeedbackLabel.UNCERTAIN: None,
}
