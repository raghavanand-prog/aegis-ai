"""Whether a proposed containment action may be signed off.

Pure preconditions over strings and enums. No session, no ORM, no request - so
every caller gets the same answer, which is the point: the API is one caller,
and V7 established that a boundary living in a FastAPI dependency is a boundary
only for traffic that happens to arrive over HTTP.

Five things must hold before an approval is recorded, and the **order** they
are checked in is part of the contract because the message decides what the
operator does next:

1. **Decidable.** Only a pending request. Telling somebody they lack a
   permission for a request that was decided last week sends them to ask an
   administrator for something that would not have helped.
2. **Four eyes.** The approver is not the requester, compared case- and
   whitespace-folded via the one shared rule in :mod:`app.core.actors`.
3. **Human.** A detection or an assistant may *propose* containment. Only a
   person decides it.
4. **Authority.** The acting role must hold ``incidents:respond_approve``,
   checked against the permission matrix here rather than only at the edge.
5. **Faithful to what was asked.** The parameters must be the ones the request
   carried, and the approver must state which evidence they were shown.

Freshness is **mandatory** here, unlike a lifecycle transition where the
evidence digest is optional for compatibility with clients that predate it.
These endpoints are new, so there are no such clients, and an approval that
does not say which evidence it was given would be unprotected for no reason.

There are three decisions, and their asymmetries are the design rather than
oversights:

===========  ==========  ===========  =========  ==================
Decision     Decidable?  Who          Freshness  Permission
===========  ==========  ===========  =========  ==================
approve      yes         *not* the    required   respond_approve
                         requester,
                         and human
reject       yes         anyone with  no         respond_approve
                         authority
withdraw     yes         *only* the   n/a        respond
                         requester
===========  ==========  ===========  =========  ==================

Both refusing directions skip freshness on purpose. Blocking a rejection or a
withdrawal because the evidence moved would trap the request pending forever,
and ending a containment request is the fail-safe direction - the failure mode
of getting it wrong is that nothing is contained.

Approval and withdrawal look symmetric and are not. Approval *forbids* one
actor; withdrawal *requires* one. An administrator who disagrees with a pending
request rejects it under their own name, rather than retracting it under the
requester's.
"""

from __future__ import annotations

from app.core import actors
from app.core.rbac import Permission, has_permission
from app.response.actions import TERMINAL_STATUSES, ResponseActionStatus


class ApprovalError(ValueError):
    """Base class for every refusal in this module."""


class NotDecidable(ApprovalError):
    """The request has already been decided, or withdrawn."""


class SelfApprovalRefused(ApprovalError):
    """The approver raised this request."""


class UnauthorizedApproval(ApprovalError):
    """This actor may not decide a response action."""


class NotTheRequester(ApprovalError):
    """Only the actor who raised a request may retract it."""


class ParametersChanged(ApprovalError):
    """The stored parameters are not the ones the request was raised with."""


class FreshnessRequired(ApprovalError):
    """The approver did not state which evidence they were shown."""


def check_decidable(status: ResponseActionStatus | str) -> None:
    parsed = ResponseActionStatus(status)
    if parsed in TERMINAL_STATUSES:
        raise NotDecidable(
            f"This request is {parsed.value!r} and cannot be decided again. A "
            "recorded decision is not reversed in place; raise a new request "
            "that references it."
        )


def check_authority(approver: str | None, approver_role: str | None) -> None:
    """Human, and holding the approval permission.

    Both checks live together because they answer the same question - may this
    actor decide? - and separating them invites a caller to remember one.
    """
    if not actors.is_human_actor(approver):
        raise UnauthorizedApproval(
            f"{approver!r} is not a human actor and cannot decide a response "
            "action. A detection or an assistant may propose containment; a "
            "person decides it."
        )
    if not approver_role:
        raise UnauthorizedApproval(
            "A decision must state the role it was made under. Recording one "
            "whose authority cannot be checked defeats the point of recording "
            "who made it."
        )
    if not has_permission(approver_role, Permission.INCIDENTS_RESPOND_APPROVE):
        raise UnauthorizedApproval(
            f"Role {approver_role!r} does not hold "
            f"{Permission.INCIDENTS_RESPOND_APPROVE.value} and cannot decide a "
            "response action. Requesting containment and signing it off are "
            "separate authorities."
        )


def check_requester(requested_by: str, actor: str | None) -> None:
    """Four-eyes inverted: only the person who asked may take it back.

    An administrator who disagrees with a pending request has ``reject``,
    which records a refusal against their own name. Letting them *withdraw* it
    instead would file a retraction under the requester's, and the record
    would say somebody changed their mind when they did not.
    """
    if not actors.same_actor(actor, requested_by):
        raise NotTheRequester(
            f"{actor!r} did not raise this request and cannot withdraw it. "
            "Only the requester retracts their own request; anyone else with "
            "the authority to end it rejects it, under their own name."
        )


def check_request_authority(actor_role: str | None) -> None:
    """The authority that raises a request is the authority that retracts one.

    Re-checked at the decision rather than inferred from the row's existence:
    a role can be reduced between raising a request and ending it, and the
    permission a caller holds *now* is the one that governs what they may do
    now.
    """
    if not actor_role:
        raise UnauthorizedApproval(
            "A withdrawal must state the role it was made under, for the same "
            "reason an approval must: a decision whose authority cannot be "
            "checked is not one the record can stand behind."
        )
    if not has_permission(actor_role, Permission.INCIDENTS_RESPOND):
        raise UnauthorizedApproval(
            f"Role {actor_role!r} does not hold "
            f"{Permission.INCIDENTS_RESPOND.value} and cannot withdraw a "
            "response action."
        )


def check_four_eyes(requested_by: str, approver: str) -> None:
    if actors.same_actor(approver, requested_by):
        raise SelfApprovalRefused(
            f"{approver!r} raised this request and cannot also approve it. A "
            "containment action needs a second person; one actor doing both is "
            "not review, it is paperwork."
        )


def check_parameters_unchanged(recorded: str, current: str) -> None:
    if recorded != current:
        raise ParametersChanged(
            "The action's parameters have changed since the request was "
            "raised, so this approval would sign off something other than what "
            "was asked for. Raise a new request with the parameters you intend."
        )


def check_freshness_stated(expected_evidence_digest: str | None) -> None:
    if not (expected_evidence_digest or "").strip():
        raise FreshnessRequired(
            "An approval must state the evidence manifest it was given. "
            "Without it there is no way to tell later whether the approver saw "
            "what the incident actually held at the time."
        )


def check_approval(
    *,
    requested_by: str,
    approver: str,
    approver_role: str | None,
    status: ResponseActionStatus | str,
    recorded_parameters_digest: str,
    current_parameters_digest: str,
    expected_evidence_digest: str | None,
) -> None:
    """Every precondition for signing off a response action, in order."""
    check_decidable(status)
    check_four_eyes(requested_by, approver)
    check_authority(approver, approver_role)
    check_parameters_unchanged(recorded_parameters_digest, current_parameters_digest)
    check_freshness_stated(expected_evidence_digest)


def check_withdrawal(
    *,
    requested_by: str,
    actor: str | None,
    actor_role: str | None,
    status: ResponseActionStatus | str,
    reason: str | None,
) -> None:
    """Preconditions for retracting a response action.

    **There is deliberately no ``expected_evidence_digest`` parameter.** Not
    optional - absent. A withdrawal cannot be blocked by evidence moving, so a
    parameter that existed and was ignored would advertise a check nobody
    could rely on. Retraction only ever reduces what gets contained, which is
    the fail-safe direction, exactly as for rejection.

    No four-eyes either, and for the opposite reason to rejection's: this
    check *requires* one specific actor rather than forbidding one.
    """
    check_decidable(status)
    check_requester(requested_by, actor)
    check_request_authority(actor_role)
    if not (reason or "").strip():
        raise ApprovalError(
            "A withdrawal needs a reason. The request carried a justification; "
            "retracting it without one leaves a record the next person cannot "
            "read."
        )


def check_rejection(
    *,
    requested_by: str,
    approver: str,
    approver_role: str | None,
    status: ResponseActionStatus | str,
    reason: str | None,
) -> None:
    """Preconditions for refusing a response action.

    No four-eyes and no freshness. ``requested_by`` is accepted so the two
    functions have the same shape for callers, and so this docstring is where
    the asymmetry is written down rather than left to be inferred.
    """
    check_decidable(status)
    check_authority(approver, approver_role)
    if not (reason or "").strip():
        raise ApprovalError(
            "A rejection needs a reason. A refusal that says nothing is a "
            "record that the next person cannot act on."
        )
