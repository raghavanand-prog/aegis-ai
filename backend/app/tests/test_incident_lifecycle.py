"""The incident lifecycle transition rules, tested as pure logic.

These tests never touch the database, a session or the API. That is the point:
the rules they check are the ones every caller must obey, and a rule that can
only be tested through an HTTP request is a rule the next caller will bypass.

The API-level and service-level enforcement tests live in
``test_incidents_lifecycle_api.py``; if these pass and those fail, the domain is
right and the wiring is wrong, which is a much faster thing to diagnose.
"""

from __future__ import annotations

import pytest

from app.incidents import lifecycle
from app.incidents.lifecycle import (
    InvalidTransition,
    TransitionReasonRequired,
    UnauthorizedTransition,
)
from app.models.enums import IncidentStatus, UserRole

ADMIN = UserRole.ADMIN.value
ANALYST = UserRole.ANALYST.value
VIEWER = UserRole.VIEWER.value

ANALYST_ACTOR = "analyst@aegisx.dev"
ADMIN_ACTOR = "admin@aegisx.dev"


def transition(current, target, **kwargs):
    """Call the validator with sensible defaults for whatever is not under test."""
    kwargs.setdefault("actor", ANALYST_ACTOR)
    kwargs.setdefault("actor_role", ANALYST)
    kwargs.setdefault("reason", "because")
    return lifecycle.validate_transition(current, target, **kwargs)


# --- The state set --------------------------------------------------------


class TestStates:
    def test_the_four_v1_statuses_are_still_legal_states(self) -> None:
        """Backwards compatibility, asserted rather than assumed.

        Every incident already in the database carries one of these four
        strings. If the lifecycle stopped recognising one, those rows would
        become unreadable by their own status field.
        """
        for legacy in ("Open", "Investigating", "Contained", "Resolved"):
            assert lifecycle.parse(legacy) is IncidentStatus(legacy)

    def test_every_state_is_reachable_from_open(self) -> None:
        """A state nothing can reach is a state that will never be observed."""
        seen = {IncidentStatus.OPEN}
        frontier = [IncidentStatus.OPEN]
        while frontier:
            for nxt in lifecycle.allowed_transitions(frontier.pop()):
                if nxt not in seen:
                    seen.add(nxt)
                    frontier.append(nxt)

        assert seen == set(IncidentStatus)

    def test_the_transition_table_is_total_and_closed(self) -> None:
        """Every state has an entry, and no entry names a state off the map."""
        states = set(IncidentStatus)
        assert set(lifecycle.TRANSITIONS) == states
        for targets in lifecycle.TRANSITIONS.values():
            assert targets <= states

    def test_closed_is_terminal(self) -> None:
        assert lifecycle.allowed_transitions(IncidentStatus.CLOSED) == frozenset()
        assert lifecycle.is_terminal(IncidentStatus.CLOSED)

    def test_no_other_state_is_terminal(self) -> None:
        for state in IncidentStatus:
            if state is not IncidentStatus.CLOSED:
                assert not lifecycle.is_terminal(state), state


# --- Valid and invalid edges ----------------------------------------------


class TestTransitionValidity:
    @pytest.mark.parametrize(
        ("current", "target"),
        [
            (IncidentStatus.OPEN, IncidentStatus.TRIAGED),
            (IncidentStatus.OPEN, IncidentStatus.INVESTIGATING),
            (IncidentStatus.TRIAGED, IncidentStatus.INVESTIGATING),
            (IncidentStatus.INVESTIGATING, IncidentStatus.CONTAINMENT_PENDING),
            (IncidentStatus.CONTAINMENT_PENDING, IncidentStatus.CONTAINED),
            (IncidentStatus.CONTAINED, IncidentStatus.RESOLVED),
        ],
    )
    def test_the_forward_path_is_permitted(self, current, target) -> None:
        transition(current, target, actor_role=ADMIN, actor=ADMIN_ACTOR)

    @pytest.mark.parametrize(
        ("current", "target"),
        [
            # Containment cannot be declared on an incident nobody has looked at.
            (IncidentStatus.OPEN, IncidentStatus.CONTAINED),
            (IncidentStatus.OPEN, IncidentStatus.CONTAINMENT_PENDING),
            # Closing skips the entire working record.
            (IncidentStatus.OPEN, IncidentStatus.CLOSED),
            (IncidentStatus.INVESTIGATING, IncidentStatus.CLOSED),
            (IncidentStatus.CONTAINED, IncidentStatus.CLOSED),
            # Going back to the entry state would erase that triage happened.
            (IncidentStatus.RESOLVED, IncidentStatus.OPEN),
            (IncidentStatus.INVESTIGATING, IncidentStatus.OPEN),
            (IncidentStatus.CONTAINED, IncidentStatus.TRIAGED),
        ],
    )
    def test_illegal_edges_are_refused(self, current, target) -> None:
        with pytest.raises(InvalidTransition):
            transition(current, target, actor_role=ADMIN, actor=ADMIN_ACTOR)

    def test_nothing_leaves_closed(self) -> None:
        for target in IncidentStatus:
            with pytest.raises(InvalidTransition):
                transition(
                    IncidentStatus.CLOSED, target, actor_role=ADMIN, actor=ADMIN_ACTOR
                )

    def test_a_status_cannot_transition_to_itself(self) -> None:
        """Not a transition. Accepting it would write an audit row saying
        something happened when nothing did."""
        with pytest.raises(InvalidTransition):
            transition(
                IncidentStatus.INVESTIGATING,
                IncidentStatus.INVESTIGATING,
                actor_role=ADMIN,
                actor=ADMIN_ACTOR,
            )

    def test_an_unknown_status_is_a_domain_error_not_a_crash(self) -> None:
        """A stored value the enum does not know must surface as a refusal.

        A KeyError or ValueError escaping from here would reach the API as a
        500, and an incident whose status is unreadable is exactly the row an
        operator most needs a clear message about.
        """
        with pytest.raises(InvalidTransition):
            transition("Quarantined", IncidentStatus.RESOLVED)
        with pytest.raises(InvalidTransition):
            transition(IncidentStatus.OPEN, "Quarantined")

    def test_statuses_may_be_passed_as_strings(self) -> None:
        """The database stores strings; callers should not have to convert."""
        transition("Open", "Triaged")


# --- Authority ------------------------------------------------------------


class TestAuthority:
    def test_a_viewer_can_make_no_transition_at_all(self) -> None:
        for current, targets in lifecycle.TRANSITIONS.items():
            for target in targets:
                with pytest.raises(UnauthorizedTransition):
                    transition(current, target, actor_role=VIEWER)

    def test_an_analyst_may_work_an_incident(self) -> None:
        transition(IncidentStatus.OPEN, IncidentStatus.TRIAGED, actor_role=ANALYST)
        transition(
            IncidentStatus.TRIAGED, IncidentStatus.INVESTIGATING, actor_role=ANALYST
        )
        transition(
            IncidentStatus.INVESTIGATING, IncidentStatus.RESOLVED, actor_role=ANALYST
        )

    @pytest.mark.parametrize(
        ("current", "target"),
        [
            (IncidentStatus.INVESTIGATING, IncidentStatus.CONTAINMENT_PENDING),
            (IncidentStatus.INVESTIGATING, IncidentStatus.CONTAINED),
            (IncidentStatus.CONTAINMENT_PENDING, IncidentStatus.CONTAINED),
        ],
    )
    def test_containment_needs_the_respond_permission(self, current, target) -> None:
        """An analyst holds it; a viewer does not. The point of asserting it
        here rather than only in the router is that the router is one caller."""
        transition(current, target, actor_role=ANALYST)
        with pytest.raises(UnauthorizedTransition):
            transition(current, target, actor_role=VIEWER)

    def test_closing_is_administrator_only(self) -> None:
        transition(
            IncidentStatus.RESOLVED,
            IncidentStatus.CLOSED,
            actor_role=ADMIN,
            actor=ADMIN_ACTOR,
        )
        with pytest.raises(UnauthorizedTransition):
            transition(
                IncidentStatus.RESOLVED, IncidentStatus.CLOSED, actor_role=ANALYST
            )

    def test_an_unknown_role_is_refused(self) -> None:
        """Roles come from a column. A value outside the matrix grants nothing,
        rather than falling through to a default."""
        with pytest.raises(UnauthorizedTransition):
            transition(IncidentStatus.OPEN, IncidentStatus.TRIAGED, actor_role="root")

    def test_every_legal_edge_names_a_required_permission(self) -> None:
        for current, targets in lifecycle.TRANSITIONS.items():
            for target in targets:
                assert lifecycle.required_permission(current, target) is not None


class TestNonHumanActors:
    """The V7 rule, applied to containment.

    ``ai:``, ``system:`` and ``automation:`` prefixed actors may not take a
    consequential step. V9 will let a detection or an assistant *recommend*
    containment; this is what stops a recommendation becoming the act.
    """

    @pytest.mark.parametrize("actor", ["ai:analyst", "system:enrichment", "automation:soar"])
    def test_a_machine_may_not_declare_containment(self, actor) -> None:
        with pytest.raises(UnauthorizedTransition):
            transition(
                IncidentStatus.INVESTIGATING,
                IncidentStatus.CONTAINED,
                actor=actor,
                actor_role=ADMIN,
            )

    @pytest.mark.parametrize("actor", ["ai:analyst", "system:enrichment", "automation:soar"])
    def test_a_machine_may_not_close_an_incident(self, actor) -> None:
        with pytest.raises(UnauthorizedTransition):
            transition(
                IncidentStatus.RESOLVED,
                IncidentStatus.CLOSED,
                actor=actor,
                actor_role=ADMIN,
            )

    def test_a_machine_may_still_triage(self) -> None:
        """Deliberately permitted. Automated triage is useful and reversible;
        refusing it would buy nothing and block a sensible future feature."""
        transition(
            IncidentStatus.OPEN,
            IncidentStatus.TRIAGED,
            actor="system:enrichment",
            actor_role=ADMIN,
        )

    def test_the_check_is_not_defeated_by_case_or_whitespace(self) -> None:
        with pytest.raises(UnauthorizedTransition):
            transition(
                IncidentStatus.RESOLVED,
                IncidentStatus.CLOSED,
                actor="  AI:Analyst  ",
                actor_role=ADMIN,
            )


# --- Reasons --------------------------------------------------------------


class TestReasons:
    @pytest.mark.parametrize(
        ("current", "target", "role", "actor"),
        [
            (IncidentStatus.INVESTIGATING, IncidentStatus.RESOLVED, ANALYST, ANALYST_ACTOR),
            (IncidentStatus.CONTAINED, IncidentStatus.RESOLVED, ANALYST, ANALYST_ACTOR),
            (IncidentStatus.RESOLVED, IncidentStatus.CLOSED, ADMIN, ADMIN_ACTOR),
            # Reopening is the "we were wrong" edge and is worth a sentence.
            (IncidentStatus.RESOLVED, IncidentStatus.INVESTIGATING, ANALYST, ANALYST_ACTOR),
            (IncidentStatus.CONTAINED, IncidentStatus.INVESTIGATING, ANALYST, ANALYST_ACTOR),
            (
                IncidentStatus.CONTAINMENT_PENDING,
                IncidentStatus.INVESTIGATING,
                ANALYST,
                ANALYST_ACTOR,
            ),
        ],
    )
    def test_these_transitions_require_a_reason(self, current, target, role, actor) -> None:
        assert lifecycle.requires_reason(current, target)
        with pytest.raises(TransitionReasonRequired):
            lifecycle.validate_transition(
                current, target, actor=actor, actor_role=role, reason=None
            )

    def test_a_blank_reason_is_not_a_reason(self) -> None:
        for blank in ("", "   ", "\t\n"):
            with pytest.raises(TransitionReasonRequired):
                lifecycle.validate_transition(
                    IncidentStatus.INVESTIGATING,
                    IncidentStatus.RESOLVED,
                    actor=ANALYST_ACTOR,
                    actor_role=ANALYST,
                    reason=blank,
                )

    def test_ordinary_forward_progress_needs_no_reason(self) -> None:
        for current, target in [
            (IncidentStatus.OPEN, IncidentStatus.TRIAGED),
            (IncidentStatus.OPEN, IncidentStatus.INVESTIGATING),
            (IncidentStatus.TRIAGED, IncidentStatus.INVESTIGATING),
            (IncidentStatus.INVESTIGATING, IncidentStatus.CONTAINMENT_PENDING),
            (IncidentStatus.CONTAINMENT_PENDING, IncidentStatus.CONTAINED),
        ]:
            assert not lifecycle.requires_reason(current, target)
            lifecycle.validate_transition(
                current, target, actor=ANALYST_ACTOR, actor_role=ANALYST, reason=None
            )


# --- Ordering of the checks ------------------------------------------------


class TestRefusalOrder:
    """Which refusal wins when several apply.

    This is not pedantry. The message an operator sees decides what they do
    next, and "you may not do that" sent to someone who was never going to be
    allowed teaches them to go and ask for a permission that would not have
    helped.
    """

    def test_an_illegal_edge_is_reported_as_illegal_even_without_authority(self) -> None:
        with pytest.raises(InvalidTransition):
            transition(IncidentStatus.OPEN, IncidentStatus.CLOSED, actor_role=VIEWER)

    def test_authority_is_checked_before_the_reason(self) -> None:
        with pytest.raises(UnauthorizedTransition):
            lifecycle.validate_transition(
                IncidentStatus.RESOLVED,
                IncidentStatus.CLOSED,
                actor=ANALYST_ACTOR,
                actor_role=ANALYST,
                reason=None,
            )
