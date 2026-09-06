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
