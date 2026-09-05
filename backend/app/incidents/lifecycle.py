"""The incident lifecycle: which states follow which, and who may say so.

Everything here is a pure function over enums. No session, no ORM, no request.
That is deliberate and it is the whole point of the module existing separately
from ``incident_service``: through V8 an incident's status was whatever the last
``PATCH`` said it was. ``update_incident`` compared the new status to the old
one, appended a timeline entry and assigned it. Any status could follow any
other, so ``Resolved -> Open`` was legal, so was ``Open -> Contained``, and the
only thing standing between the database and a nonsense value was a ``CHECK``
constraint on the spelling.

    Open ─┬─▶ Triaged ─┬─▶ Investigating ─┬─▶ Containment Pending ──▶ Contained
          │            │         ▲        │                              │
          │            │         │        └─▶ Contained                  │
          │            │         │                  │                    │
          │            │         └──────────────────┴────────────────────┘
          │            │              (reopen, with a reason)
          │            │
          └────────────┴──▶ Resolved ──▶ Closed
                               ▲   │
                               └───┘ reopen ─▶ Investigating

Three rules, and each one refuses more than it permits:

1. **The edge must exist.** ``TRANSITIONS`` is the whole map. A pair not in it
   is refused, including a state to itself - that is not a transition, and
   accepting it would write an audit row claiming something happened.
2. **The actor must hold the permission the edge requires.** Checked here
   against the same matrix the API dependency uses, because the API is one
   caller. A worker, a CLI command or a future assistant reaching this function
   gets the same answer.
3. **Some edges must carry a reason.** Every edge that ends work
   (``-> Resolved``, ``-> Closed``) and every edge that undoes it (a reopen).
   These are the transitions somebody reads back six months later.

Closing is administrator-only and terminal. Nothing leaves ``Closed``, which
follows V5's rule for a rejected proposal: a recorded decision is not reversed
in place, it is superseded by a new record.
"""

from __future__ import annotations

from app.core import actors
from app.core.rbac import Permission, has_permission
from app.models.enums import IncidentStatus

# --- Errors ---------------------------------------------------------------
#
# Three distinct types rather than one, because the caller has to turn these
# into different HTTP statuses (409, 403, 400) and an operator has to know
# whether to change what they asked for, ask for a permission, or write a
# sentence. A single LifecycleError would collapse all three into "no".


class LifecycleError(ValueError):
    """Base class for every refusal in this module."""


class InvalidTransition(LifecycleError):
    """The edge does not exist, or one of the states is not a real state."""


class UnauthorizedTransition(LifecycleError):
    """The edge exists; this actor may not take it."""


class TransitionReasonRequired(LifecycleError):
    """The edge exists and the actor may take it, but not silently."""


# --- The map --------------------------------------------------------------

#: Every legal edge. A state's absence from another's set is a refusal, so the
#: empty set for ``CLOSED`` is a statement, not an omission.
TRANSITIONS: dict[IncidentStatus, frozenset[IncidentStatus]] = {
    IncidentStatus.OPEN: frozenset(
        {
            IncidentStatus.TRIAGED,
            # An analyst picking up a critical alert starts working it. Making
            # them click "triage" first would be paperwork, not control.
            IncidentStatus.INVESTIGATING,
            # Dismissal: triaged as benign or duplicate. Needs a reason, and
            # still has to be closed by somebody else afterwards.
            IncidentStatus.RESOLVED,
        }
    ),
    IncidentStatus.TRIAGED: frozenset(
        {IncidentStatus.INVESTIGATING, IncidentStatus.RESOLVED}
    ),
    IncidentStatus.INVESTIGATING: frozenset(
        {
            IncidentStatus.CONTAINMENT_PENDING,
            # Containment that already happened out of band - somebody pulled a
            # cable. Recording what is true beats forcing a fictional pending
            # step through the system.
            IncidentStatus.CONTAINED,
            IncidentStatus.RESOLVED,
        }
    ),
    IncidentStatus.CONTAINMENT_PENDING: frozenset(
        {
            IncidentStatus.CONTAINED,
            # Containment was refused, failed, or turned out to be unnecessary.
            IncidentStatus.INVESTIGATING,
        }
    ),
    IncidentStatus.CONTAINED: frozenset(
        {
            IncidentStatus.RESOLVED,
            # Containment was not enough; more scope turned up.
            IncidentStatus.INVESTIGATING,
        }
    ),
    IncidentStatus.RESOLVED: frozenset(
        {
            IncidentStatus.CLOSED,
            # New evidence. Reopening a resolved incident is normal; reopening
            # a closed one is not possible.
            IncidentStatus.INVESTIGATING,
        }
    ),
    IncidentStatus.CLOSED: frozenset(),
}

#: Edges that put an incident back into active work. Kept explicit rather than
#: derived from an ordering, because the lifecycle is a graph and not a line -
#: any rule that says "target is earlier than current" needs a total order that
#: does not exist here.
_REOPEN_EDGES: frozenset[tuple[IncidentStatus, IncidentStatus]] = frozenset(
    {
        (IncidentStatus.CONTAINMENT_PENDING, IncidentStatus.INVESTIGATING),
        (IncidentStatus.CONTAINED, IncidentStatus.INVESTIGATING),
        (IncidentStatus.RESOLVED, IncidentStatus.INVESTIGATING),
    }
)

#: Declaring or requesting containment asserts something about the state of the
#: estate, so it needs the responder authority rather than the editor one.
_CONTAINMENT_TARGETS: frozenset[IncidentStatus] = frozenset(
    {IncidentStatus.CONTAINMENT_PENDING, IncidentStatus.CONTAINED}
)

# The non-human actor rule lives in `app.core.actors`. It was defined here at
# Phase B and separately in `adaptation/proposals/service.py` at V7, and the two
# had drifted - see that module. One definition now, three consumers.


# --- Queries --------------------------------------------------------------


def parse(status: IncidentStatus | str) -> IncidentStatus:
    """Coerce a stored string to a state, or refuse it as a domain error.

    Rows are read back as strings and a value the enum does not know must not
    escape as a ``ValueError`` from deep inside the enum machinery - that
    reaches the API as a 500, and an incident whose status is unreadable is the
    row an operator most needs a clear message about.
    """
    if isinstance(status, IncidentStatus):
        return status
    try:
        return IncidentStatus(status)
    except ValueError as exc:
        known = ", ".join(state.value for state in IncidentStatus)
        raise InvalidTransition(
            f"{status!r} is not an incident status. Known statuses: {known}."
        ) from exc


def allowed_transitions(status: IncidentStatus | str) -> frozenset[IncidentStatus]:
    """The states that may follow this one. Empty for a terminal state."""
    return TRANSITIONS[parse(status)]


def is_terminal(status: IncidentStatus | str) -> bool:
    return not TRANSITIONS[parse(status)]


def required_permission(
    current: IncidentStatus | str, target: IncidentStatus | str
) -> Permission:
    """The permission an actor must hold to take this edge.

    Defined for legal edges. Asking about an illegal one is a caller error, and
    answering it would invite a check that passes on a transition that can never
    happen.
    """
    current, target = parse(current), parse(target)
    if target not in TRANSITIONS[current]:
        raise InvalidTransition(
            f"There is no transition from {current.value!r} to {target.value!r}."
        )
    if target is IncidentStatus.CLOSED:
        return Permission.INCIDENTS_CLOSE
    if target in _CONTAINMENT_TARGETS:
        return Permission.INCIDENTS_RESPOND
    return Permission.INCIDENTS_UPDATE


def requires_reason(
    current: IncidentStatus | str, target: IncidentStatus | str
) -> bool:
    """Whether this edge must carry an explanation."""
    current, target = parse(current), parse(target)
    if target in (IncidentStatus.RESOLVED, IncidentStatus.CLOSED):
        return True
    return (current, target) in _REOPEN_EDGES


def is_human_actor(actor: str) -> bool:
    """Whether the actor string names a person rather than a process.

    Re-exported from :mod:`app.core.actors` so existing callers keep working;
    the rule itself is defined once, there.
    """
    return actors.is_human_actor(actor)


# --- The gate -------------------------------------------------------------


def validate_transition(
    current: IncidentStatus | str,
    target: IncidentStatus | str,
    *,
    actor: str,
    actor_role: str,
    reason: str | None = None,
) -> tuple[IncidentStatus, IncidentStatus]:
    """Refuse the transition, or return the parsed pair.

    The order of the checks is part of the contract and is asserted by test.
    Existence first, then authority, then the reason: telling somebody they lack
    a permission for an edge that does not exist sends them to ask an
    administrator for something that would not have helped, and asking for a
    justification before checking whether they may act at all invites them to
    write one for nothing.

    Returns the pair so callers do not parse twice, and so the parsed target is
    the value they persist - a caller that validated ``"Resolved"`` and then
    wrote whatever string arrived in the request body would have validated one
    thing and stored another.
    """
    current, target = parse(current), parse(target)

    # 1. Does the edge exist?
    if target not in TRANSITIONS[current]:
        if current is target:
            raise InvalidTransition(
                f"Incident is already {current.value!r}. A status cannot "
                "transition to itself."
            )
        if is_terminal(current):
            raise InvalidTransition(
                f"Incident is {current.value!r}, which is terminal. A closed "
                "incident is a signed record and is not reopened; raise a new "
                "incident that references it instead."
            )
        options = ", ".join(sorted(state.value for state in TRANSITIONS[current]))
        raise InvalidTransition(
            f"{current.value!r} cannot become {target.value!r}. "
            f"Allowed from {current.value!r}: {options}."
        )

    # 2. May this actor take it?
    permission = required_permission(current, target)
    if not has_permission(actor_role, permission):
        raise UnauthorizedTransition(
            f"Role {actor_role!r} does not hold {permission.value} and cannot "
            f"move an incident from {current.value!r} to {target.value!r}."
        )

    consequential = target is IncidentStatus.CLOSED or target in _CONTAINMENT_TARGETS
    if consequential and not is_human_actor(actor):
        raise UnauthorizedTransition(
            f"{actor!r} is not a human actor and cannot move an incident to "
            f"{target.value!r}. A detection or an assistant may recommend "
            "containment or closure; a person decides it."
        )

    # 3. Does it need to say why?
    if requires_reason(current, target) and not (reason or "").strip():
        raise TransitionReasonRequired(
            f"Moving an incident from {current.value!r} to {target.value!r} "
            "requires a reason. This transition ends or undoes recorded work, "
            "and the next person to read it needs to know why."
        )

    return current, target
