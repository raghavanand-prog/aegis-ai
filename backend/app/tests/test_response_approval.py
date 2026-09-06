"""Response-action approval rules, tested as pure logic.

No database, no session, no HTTP. These are the checks that decide whether a
proposed containment action may be signed off, and they must hold for every
caller - the API is one, a CLI is another, and a future assistant is a third.

The consolidation tests at the bottom matter as much as the rest: V7's
four-eyes rule and V9's lifecycle rule had drifted into two implementations
that disagreed, and this phase would have made a third.
"""

from __future__ import annotations

import pytest

from app.core import actors
from app.models.enums import UserRole
from app.response import approval
from app.response.actions import (
    ResponseActionStatus,
    ResponseActionType,
    parameters_digest,
)

ANALYST = UserRole.ANALYST.value
ADMIN = UserRole.ADMIN.value
VIEWER = UserRole.VIEWER.value

REQUESTER = "analyst@aegisx.dev"
APPROVER = "admin@aegisx.dev"
DIGEST = "a" * 64
PARAMS = {"hostname": "SYN-WIN-001", "durationMinutes": 60}


def approve(**overrides) -> None:
    kwargs = {
        "requested_by": REQUESTER,
        "approver": APPROVER,
        "approver_role": ADMIN,
        "status": ResponseActionStatus.REQUESTED,
        "recorded_parameters_digest": parameters_digest(PARAMS),
        "current_parameters_digest": parameters_digest(PARAMS),
        "expected_evidence_digest": DIGEST,
    }
    kwargs.update(overrides)
    return approval.check_approval(**kwargs)


def reject(**overrides) -> None:
    kwargs = {
        "requested_by": REQUESTER,
        "approver": APPROVER,
        "approver_role": ADMIN,
        "status": ResponseActionStatus.REQUESTED,
        "reason": "not warranted",
    }
    kwargs.update(overrides)
    return approval.check_rejection(**kwargs)


def withdraw(**overrides) -> None:
    kwargs = {
        "requested_by": REQUESTER,
        "actor": REQUESTER,
        "actor_role": ANALYST,
        "status": ResponseActionStatus.REQUESTED,
        "reason": "contained by hand before this was decided",
    }
    kwargs.update(overrides)
    return approval.check_withdrawal(**kwargs)


# --- Four eyes ------------------------------------------------------------


class TestFourEyes:
    def test_a_second_person_may_approve(self) -> None:
        approve()

    def test_the_requester_may_not_approve_their_own_request(self) -> None:
        with pytest.raises(approval.SelfApprovalRefused):
            approve(approver=REQUESTER)

    @pytest.mark.parametrize(
        "spelling",
        ["ANALYST@AEGISX.DEV", "  analyst@aegisx.dev  ", "Analyst@Aegisx.Dev"],
    )
    def test_four_eyes_is_not_defeated_by_case_or_whitespace(self, spelling) -> None:
        """A separation-of-duties check a shift key defeats is not a check."""
        with pytest.raises(approval.SelfApprovalRefused):
            approve(approver=spelling)

    def test_the_requester_may_still_reject_their_own_request(self) -> None:
        """Withdrawing a request you no longer believe in is not a privilege
        escalation, and refusing it would leave stale requests lying around."""
        reject(approver=REQUESTER)


class TestAuthority:
    def test_approval_requires_the_approval_permission(self) -> None:
        """Checked against the permission matrix here, not only in the router.

        Requesting is an analyst act; signing one off is not, exactly as V5
        separated proposing an adaptation from approving one.
        """
        with pytest.raises(approval.UnauthorizedApproval):
            approve(approver_role=ANALYST)
        with pytest.raises(approval.UnauthorizedApproval):
            approve(approver_role=VIEWER)

    def test_an_unstated_role_is_refused(self) -> None:
        with pytest.raises(approval.UnauthorizedApproval):
            approve(approver_role=None)

    def test_an_unknown_role_grants_nothing(self) -> None:
        with pytest.raises(approval.UnauthorizedApproval):
            approve(approver_role="root")

    def test_rejection_also_needs_authority(self) -> None:
        """Otherwise a viewer could dispose of a pending containment request."""
        with pytest.raises(approval.UnauthorizedApproval):
            reject(approver_role=VIEWER, approver="viewer@aegisx.dev")


class TestNonHumanActors:
    @pytest.mark.parametrize(
        "machine", ["ai:analyst", "AI:Analyst", "  system:worker ", "automation:soar"]
    )
    def test_a_machine_may_never_approve(self, machine) -> None:
        with pytest.raises(approval.UnauthorizedApproval):
            approve(approver=machine)

    def test_a_machine_may_request(self) -> None:
        """A detection or an assistant may propose containment. Proposing is
        not deciding, and the whole point of this phase is that the second is
        a person's act."""
        approve(requested_by="ai:analyst")


# --- What may be decided --------------------------------------------------


class TestDecidability:
    @pytest.mark.parametrize(
        "status",
        [
            ResponseActionStatus.APPROVED,
            ResponseActionStatus.REJECTED,
            ResponseActionStatus.WITHDRAWN,
        ],
    )
    def test_only_a_pending_request_can_be_decided(self, status) -> None:
        """Append-only: a decision is not revisited in place. Raise a new
        request rather than reversing a recorded one."""
        with pytest.raises(approval.NotDecidable):
            approve(status=status)
        with pytest.raises(approval.NotDecidable):
            reject(status=status)

    def test_a_requested_action_is_decidable(self) -> None:
        approve(status=ResponseActionStatus.REQUESTED)


# --- Parameter tampering --------------------------------------------------


class TestParameterBinding:
    def test_unchanged_parameters_are_accepted(self) -> None:
        approve()

    def test_parameters_changed_after_the_request_are_refused(self) -> None:
        """The approval is for what was asked, not for what the record says
        now. Without this, an approver signs off isolating one host and the
        stored request can name another."""
        with pytest.raises(approval.ParametersChanged):
            approve(
                current_parameters_digest=parameters_digest(
                    {"hostname": "SOMETHING-ELSE", "durationMinutes": 60}
                )
            )

    def test_key_order_is_not_a_change(self) -> None:
        reordered = parameters_digest({"durationMinutes": 60, "hostname": "SYN-WIN-001"})
        approve(current_parameters_digest=reordered)

    def test_the_digest_is_stable(self) -> None:
        assert parameters_digest(PARAMS) == parameters_digest(dict(PARAMS))

    def test_different_parameters_digest_differently(self) -> None:
        assert parameters_digest(PARAMS) != parameters_digest({"hostname": "OTHER"})


# --- Freshness ------------------------------------------------------------


class TestFreshnessIsMandatory:
    """The difference from a lifecycle transition.

    There the evidence digest is optional, for compatibility with clients that
    predate it. Here there are no such clients - the endpoint is new - so an
    approval that does not state which evidence it was given is refused rather
    than silently unprotected.
    """

    def test_an_approval_must_state_the_evidence_it_was_given(self) -> None:
        with pytest.raises(approval.FreshnessRequired):
            approve(expected_evidence_digest=None)

    @pytest.mark.parametrize("blank", ["", "   ", "\t\n"])
    def test_a_blank_digest_is_not_a_statement(self, blank) -> None:
        with pytest.raises(approval.FreshnessRequired):
            approve(expected_evidence_digest=blank)

    def test_rejection_does_not_require_freshness(self) -> None:
        """Deliberate asymmetry, matching V7's approve/reject asymmetry.
        Refusing to let somebody reject a request because the evidence moved
        would trap it as pending forever."""
        reject()


class TestRefusalOrder:
    """Which refusal wins, because the message decides what the operator does.

    Telling somebody they lack a permission for a request that was already
    decided sends them to ask for something that would not have helped.
    """

    def test_a_decided_request_reports_that_before_anything_else(self) -> None:
        with pytest.raises(approval.NotDecidable):
            approve(
                status=ResponseActionStatus.APPROVED,
                approver=REQUESTER,
                approver_role=VIEWER,
                expected_evidence_digest=None,
            )

    def test_authority_is_checked_before_freshness(self) -> None:
        with pytest.raises(approval.UnauthorizedApproval):
            approve(approver_role=ANALYST, expected_evidence_digest=None)

    def test_self_approval_is_reported_before_freshness(self) -> None:
        with pytest.raises(approval.SelfApprovalRefused):
            approve(approver=REQUESTER, expected_evidence_digest=None)


# --- Withdrawal -----------------------------------------------------------


class TestWithdrawal:
    """Retracting a request, which is four-eyes read backwards.

    Approval asks *may somebody else sign this off*. Withdrawal asks the
    opposite: may the person who raised it take it back. So the identity check
    is inverted - only the requester may withdraw - and an administrator who
    disagrees has ``reject`` instead, which records a decision against their
    own name rather than retracting one under somebody else's.

    Like rejection it needs no freshness and no second person, for the same
    fail-safe reason: withdrawal only ever *reduces* what gets contained, and
    blocking it because the evidence moved would trap the request pending
    forever.
    """

    def test_the_requester_may_withdraw_their_own_pending_request(self) -> None:
        withdraw()

    def test_somebody_else_may_not_withdraw_it(self) -> None:
        """Not even an administrator, who holds every other authority here.

        Withdrawal is retraction, and retracting somebody else's request under
        their name puts words in their mouth. An administrator rejects it.
        """
        with pytest.raises(approval.NotTheRequester):
            withdraw(actor=APPROVER, actor_role=ADMIN)

    def test_withdrawal_is_not_defeated_by_case_or_whitespace(self) -> None:
        """The same shared rule four-eyes uses, applied in the other
        direction - so a requester cannot be locked out of retracting their
        own request by a stray capital."""
        withdraw(actor="  Analyst@AegisX.dev  ")

    def test_an_absent_actor_cannot_withdraw(self) -> None:
        with pytest.raises(approval.NotTheRequester):
            withdraw(actor=None)

    @pytest.mark.parametrize(
        "status",
        [
            ResponseActionStatus.APPROVED,
            ResponseActionStatus.REJECTED,
            ResponseActionStatus.WITHDRAWN,
        ],
    )
    def test_a_decided_request_cannot_be_withdrawn(self, status) -> None:
        """Terminal stays terminal, including withdrawal itself. Retracting an
        approved containment action would be an undo the platform does not
        have."""
        with pytest.raises(approval.NotDecidable):
            withdraw(status=status)

    def test_withdrawal_needs_the_authority_that_raised_it(self) -> None:
        """A viewer could never have raised this request, so a viewer cannot
        end one either - authority is re-checked at the decision rather than
        assumed from the fact that a row exists."""
        with pytest.raises(approval.UnauthorizedApproval):
            withdraw(actor_role=VIEWER)

    def test_an_unstated_role_is_refused(self) -> None:
        with pytest.raises(approval.UnauthorizedApproval):
            withdraw(actor_role=None)

    @pytest.mark.parametrize("blank", [None, "", "   ", "\t\n"])
    def test_withdrawal_needs_a_reason(self, blank) -> None:
        """The request carried a justification; retracting it without one
        leaves a record the next person cannot read."""
        with pytest.raises(approval.ApprovalError):
            withdraw(reason=blank)

    def test_a_machine_cannot_withdraw_its_own_request(self) -> None:
        """A stated limit rather than a hidden one.

        A machine may *request* containment (see ``TestNonHumanActors``) but
        holds no role, and withdrawal checks authority like every other
        decision. This does not trap the request: an administrator can still
        reject it, which is the path that ends it.
        """
        with pytest.raises(approval.UnauthorizedApproval):
            withdraw(requested_by="ai:analyst", actor="ai:analyst", actor_role=None)

    def test_withdrawal_cannot_state_an_evidence_digest_at_all(self) -> None:
        """Not merely optional - absent. A parameter that existed and was
        ignored would read as a check somebody could rely on."""
        with pytest.raises(TypeError):
            withdraw(expected_evidence_digest=DIGEST)


class TestWithdrawalRefusalOrder:
    """Same principle as ``TestRefusalOrder``: the first message is the one
    the operator acts on."""

    def test_a_decided_request_reports_that_before_anything_else(self) -> None:
        with pytest.raises(approval.NotDecidable):
            withdraw(
                status=ResponseActionStatus.WITHDRAWN,
                actor=APPROVER,
                actor_role=VIEWER,
                reason="",
            )

    def test_the_wrong_actor_is_reported_before_their_authority(self) -> None:
        """Telling an administrator they lack a permission would send them to
        ask for one that still would not let them withdraw it."""
        with pytest.raises(approval.NotTheRequester):
            withdraw(actor=APPROVER, actor_role=VIEWER, reason="")

    def test_authority_is_reported_before_the_missing_reason(self) -> None:
        with pytest.raises(approval.UnauthorizedApproval):
            withdraw(actor_role=VIEWER, reason="")


# --- The action vocabulary ------------------------------------------------


class TestActionTypesAreNamesOnly:
    def test_the_declared_types_exist(self) -> None:
        assert {
            ResponseActionType.ISOLATE_ENDPOINT,
            ResponseActionType.DISABLE_ACCOUNT,
            ResponseActionType.BLOCK_INDICATOR,
            ResponseActionType.REVOKE_SESSION,
            ResponseActionType.QUARANTINE_FILE,
        } <= set(ResponseActionType)

    def test_nothing_dispatches_on_an_action_type(self) -> None:
        """V9 declares what a containment action is *called* and nothing about
        how it would be carried out. No executor, no provider, no handler
        table - so an approved action cannot begin doing anything by accident.
        """
        import app.response.actions as actions_module
        import app.response.approval as approval_module

        for module in (actions_module, approval_module):
            names = dir(module)
            for forbidden in ("execute", "run", "dispatch", "perform", "HANDLERS"):
                assert not any(
                    forbidden in name.lower() for name in names
                ), f"{module.__name__} exposes {forbidden!r}"


# --- The consolidation ----------------------------------------------------


class TestOneActorRule:
    """V7's four-eyes check and V9's lifecycle check had drifted apart.

    ``proposals/service.py`` compared the raw string against the non-human
    prefixes while ``lifecycle.py`` folded case and whitespace first, so
    ``AI:analyst`` was refused by one and accepted by the other. Phase E would
    have added a third copy; instead there is now one.
    """

    MACHINES = ["ai:analyst", "AI:Analyst", "  ai:analyst  ", "System:worker", "AUTOMATION:x"]

    @pytest.mark.parametrize("machine", MACHINES)
    def test_the_shared_rule_recognises_a_machine_however_it_is_spelled(
        self, machine
    ) -> None:
        assert not actors.is_human_actor(machine)

    def test_a_person_is_a_person(self) -> None:
        assert actors.is_human_actor("alice@aegisx.dev")

    def test_an_absent_actor_is_not_a_human(self) -> None:
        """Fail closed: an unnamed actor must not inherit a person's rights."""
        assert not actors.is_human_actor(None)
        assert not actors.is_human_actor("")
        assert not actors.is_human_actor("   ")

    @pytest.mark.parametrize("machine", MACHINES)
    def test_every_consumer_agrees(self, machine) -> None:
        """The regression this consolidation exists to prevent."""
        from app.adaptation.proposals import service as proposals
        from app.incidents import lifecycle

        assert not lifecycle.is_human_actor(machine)
        assert not proposals.is_human_actor(machine)
        assert not actors.is_human_actor(machine)

    def test_same_actor_folds_case_and_whitespace(self) -> None:
        assert actors.same_actor("Admin@Aegisx.dev", "  admin@aegisx.dev ")
        assert not actors.same_actor("admin@aegisx.dev", "other@aegisx.dev")

    def test_same_actor_treats_an_absent_side_as_no_match(self) -> None:
        assert not actors.same_actor("admin@aegisx.dev", None)
        assert not actors.same_actor("", "")
