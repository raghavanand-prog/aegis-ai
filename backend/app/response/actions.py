"""What a response action is, before anyone decides anything about it.

Pure: an enum of names, a status, and a digest over parameters. There is no
executor here and no dispatch table, deliberately - V9 declares what a
containment action is *called* and says nothing about how it would be carried
out, so an approved request cannot begin doing something by accident. The
provider interface, the execution record and the risk taxonomy are later work.

``parameters_digest`` is the load-bearing part. An approval is for what was
asked: isolate *this* host for *this* long. Recording the digest at request
time and re-checking it at approval time is what stops the stored parameters
being edited between the two, which would otherwise let an approver sign off
one action and a different one be the thing that was approved.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from enum import Enum
from typing import Any


class ResponseActionType(str, Enum):
    """Containment actions AEGISX can be asked to perform.

    Names only. Nothing dispatches on these values; they exist so a request
    says what was wanted in a checkable vocabulary rather than free text.
    """

    ISOLATE_ENDPOINT = "isolate_endpoint"
    DISABLE_ACCOUNT = "disable_account"
    BLOCK_INDICATOR = "block_indicator"
    REVOKE_SESSION = "revoke_session"
    QUARANTINE_FILE = "quarantine_file"


class ResponseActionConsequence(str, Enum):
    """How hard an action is to undo, said out loud for the approver.

    Every declared action is consequential - none of them is a read-only
    recommendation - so "is this consequential?" is not the useful question and
    there is deliberately **no harmless tier**. An empty tier would be
    decoration, and worse: a tier that exists invites a later action to be
    filed under it to avoid the approval.

    The useful question is how hard the thing is to reverse. An approver who
    isolates a host can un-isolate it in a minute; one who quarantines a file
    may be facing a restore. Both need the same approval, and the approver
    deserves to know which one they are signing.

    **This is description, not policy.** Nothing in ``app.response.approval``
    reads it, and a test asserts that module never even mentions the word, so
    no later edit can make a check conditional on the tier without failing
    first. If a policy layer ever wants to key on this, it can - but it will be
    a new thing that has to argue for itself, not a quiet weakening of the
    checks that exist.
    """

    #: Undone by the operator who applied it, on the same system, in minutes.
    REVERSIBLE = "reversible"
    #: Undone only by going somewhere else - a helpdesk ticket, a restore.
    DISRUPTIVE = "disruptive"


class ResponseActionStatus(str, Enum):
    """Where a request has got to.

        requested -> approved
                  -> rejected
                  -> withdrawn

    All three outcomes are terminal. A decision is not revisited in place -
    V5's rule for a rejected proposal, applied here: raise a new request rather
    than reversing a recorded refusal.
    """

    REQUESTED = "requested"
    APPROVED = "approved"
    REJECTED = "rejected"
    WITHDRAWN = "withdrawn"


#: Statuses from which nothing further may be decided.
TERMINAL_STATUSES: frozenset[ResponseActionStatus] = frozenset(
    {
        ResponseActionStatus.APPROVED,
        ResponseActionStatus.REJECTED,
        ResponseActionStatus.WITHDRAWN,
    }
)


def parameters_digest(parameters: Mapping[str, Any] | None) -> str:
    """SHA-256 over the canonical form of an action's parameters.

    Sorted keys and no incidental whitespace, so re-ordering the same facts is
    not a change - otherwise a harmless round trip through JSON would look like
    tampering and the check would be abandoned as noise.
    """
    canonical = json.dumps(
        dict(parameters or {}), sort_keys=True, separators=(",", ":"), default=str
    )
    return hashlib.sha256(canonical.encode()).hexdigest()


#: Every action, classified. Exhaustive by construction - see below.
_CONSEQUENCE: dict[ResponseActionType, ResponseActionConsequence] = {
    # Reversible: the operator who applied it takes it back, on the same
    # system, without involving anybody else.
    ResponseActionType.ISOLATE_ENDPOINT: ResponseActionConsequence.REVERSIBLE,
    ResponseActionType.REVOKE_SESSION: ResponseActionConsequence.REVERSIBLE,
    ResponseActionType.BLOCK_INDICATOR: ResponseActionConsequence.REVERSIBLE,
    # Disruptive: undoing it means going somewhere else. Disabling an account
    # locks a person out of their work until somebody re-enables it;
    # quarantining a file can mean a restore.
    ResponseActionType.DISABLE_ACCOUNT: ResponseActionConsequence.DISRUPTIVE,
    ResponseActionType.QUARANTINE_FILE: ResponseActionConsequence.DISRUPTIVE,
}

_unclassified = set(ResponseActionType) - set(_CONSEQUENCE)
if _unclassified:  # pragma: no cover - a wiring error, caught at import
    raise RuntimeError(
        "Every response action must be classified: "
        f"{sorted(item.value for item in _unclassified)} are not. Failing at "
        "import rather than at the moment somebody approves one, and rather "
        "than defaulting to the milder tier - which would understate exactly "
        "the case worth overstating."
    )


def consequence_of(
    action_type: ResponseActionType | str,
) -> ResponseActionConsequence:
    """How hard this action is to undo.

    Takes the stored string form as well as the enum, because the column holds
    a string. An action the taxonomy has never seen raises rather than
    resolving to the milder tier.
    """
    return _CONSEQUENCE[ResponseActionType(action_type)]
