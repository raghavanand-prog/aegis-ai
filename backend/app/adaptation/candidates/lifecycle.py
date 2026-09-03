"""Which model states may serve inference.

One function, deliberately. "Can this model serve?" is asked by the registry,
the inference engine and the deployment path, and three copies of the answer is
how a candidate eventually slips into production because one of them was updated
and the others were not.
"""

from __future__ import annotations

from app.models.enums import MLModelStatus

#: The only states from which a model may serve traffic.
#:
#: ACTIVE is the incumbent. APPROVED is a candidate a human has signed off.
#: ARCHIVED is a version that served before and was displaced - it is the
#: rollback target, so excluding it would make rollback impossible, which is
#: the opposite of a safety property.
#:
#: Everything else is inert by construction: a candidate has not been
#: evaluated, an evaluating model is mid-comparison, a rejected one was refused,
#: a rolled_back one failed in production, and a failed one never loaded. None
#: of them may return to serving without going through approval again.
SERVABLE_STATUSES: frozenset[str] = frozenset(
    {
        MLModelStatus.ACTIVE.value,
        MLModelStatus.APPROVED.value,
        MLModelStatus.ARCHIVED.value,
    }
)

#: States that mean "this was tried and refused". Never deleted: a rejection is
#: a measured result, and losing it means repeating the experiment.
TERMINAL_STATUSES: frozenset[str] = frozenset(
    {
        MLModelStatus.REJECTED.value,
        MLModelStatus.ROLLED_BACK.value,
        MLModelStatus.FAILED.value,
    }
)


def may_serve(status: MLModelStatus | str) -> bool:
    """Whether a model in this state is allowed to serve inference."""
    value = status.value if isinstance(status, MLModelStatus) else str(status)
    return value in SERVABLE_STATUSES
