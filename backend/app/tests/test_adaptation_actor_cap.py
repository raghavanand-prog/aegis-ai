"""The per-actor cap axis (V7 Phase 3).

V6 §19.2 measured the per-group cap removing 96% of poison where a scenario
owned its ``event_type`` and **40%** where it hid in a high-volume group; §20.3
found a hidden target facing an allowance of ~597 at cycle zero. The conclusion
the handoff drew - that the cap "is conditional on its grouping key" - is not a
tuning problem. Any single-axis cap is only as good as its key, and the fix is a
second axis an attacker cannot shed by moving.

These tests are adversarial rather than illustrative: each one is an evasion
that works against the group axis alone, and each asserts what the actor axis
does about it. No new experiment is run, because the property under test is an
invariant about allowance arithmetic rather than a magnitude about a corpus -
V6's rule 15, and rule 6's threshold-free discipline, both point the same way.
"""

from __future__ import annotations

from app.adaptation.feedback import caps


def _batch(spec: list[tuple[str, str]]) -> list[caps.CapCandidate]:
    """Build candidates from ``(group, actor)`` pairs, in order."""
    return [
        caps.CapCandidate(index=index, group=group, actor=actor)
        for index, (group, actor) in enumerate(spec)
    ]


def _actor_cap(ceiling: int) -> caps.DimensionPolicy:
    return caps.DimensionPolicy(policy=caps.POLICY_PER_GROUP_ABSOLUTE, ceiling=ceiling)


class TestV6BehaviourIsUnchangedByDefault:
    def test_the_actor_axis_is_off_unless_asked_for(self) -> None:
        """Every published V5/V6 result was produced without this axis. A call
        that does not pass it must admit exactly what it always did."""
        batch = _batch([("auth_success", f"a{i}@x") for i in range(50)])

        without = caps.apply(batch, policy=caps.POLICY_GLOBAL, global_ceiling=30)

        assert len(without) == 30
        assert [candidate.index for candidate in without] == list(range(30))

    def test_the_group_axis_still_behaves_as_it_did(self) -> None:
        batch = _batch(
            [("malware_detected", "a@x")] * 10 + [("auth_success", "a@x")] * 10
        )

        kept = caps.apply(
            batch,
            policy=caps.POLICY_BASELINE_RELATIVE,
            global_ceiling=1000,
            baseline_rates={"malware_detected": 1.4, "auth_success": 114.6},
            tolerance=1.5,
        )

        groups = caps.group_counts(kept)
        # 1.4 * 1.5 = 2.1 -> 2 rows; auth_success is nowhere near its ceiling.
        assert groups["malware_detected"] == 2
        assert groups["auth_success"] == 10


class TestHonestFeedbackSurvives:
    def test_a_normal_batch_is_not_materially_reduced(self) -> None:
        """A defence that stops honest feedback has not defended anything: V6
        decision 33 - report the defence that failed - applies to this one too."""
        honest = _batch(
            [("auth_success", "alice@x")] * 12
            + [("firewall_allow", "bob@x")] * 9
            + [("process_creation", "carol@x")] * 7
        )

        kept = caps.apply(
            honest,
            policy=caps.POLICY_GLOBAL,
            global_ceiling=1000,
            actor_policy=_actor_cap(20),
        )

        assert len(kept) == len(honest)

    def test_many_analysts_each_within_their_allowance_all_pass(self) -> None:
        batch = _batch([("auth_success", f"analyst{i}@x") for i in range(40)] * 3)

        kept = caps.apply(
            batch,
            policy=caps.POLICY_GLOBAL,
            global_ceiling=1000,
            actor_policy=_actor_cap(5),
        )

        assert len(kept) == len(batch)


class TestConcentratedAttack:
    def test_one_actor_flooding_one_group_is_bounded_by_both_axes(self) -> None:
        attack = _batch([("malware_detected", "compromised@x")] * 40)

        kept = caps.apply(
            attack,
            policy=caps.POLICY_BASELINE_RELATIVE,
            global_ceiling=1000,
            baseline_rates={"malware_detected": 1.4},
            tolerance=1.5,
            actor_policy=_actor_cap(10),
        )

        # The tighter axis wins, and it is the group cap here - as in V6 §19.2,
        # where a scenario owning its event_type was the case the group cap
        # already handled well.
        assert len(kept) == 2


class TestCrossGroupAttack:
    def test_spreading_across_groups_defeats_the_group_cap_alone(self) -> None:
        """The V6 weakness, reproduced as a test rather than asserted.

        Ten event types, four rows each: every group stays inside its own
        allowance, so the group axis admits the whole campaign.
        """
        attack = _batch(
            [(f"event_type_{g}", "compromised@x") for g in range(10) for _ in range(4)]
        )

        kept = caps.apply(
            attack,
            policy=caps.POLICY_BASELINE_RELATIVE,
            global_ceiling=1000,
            baseline_rates={f"event_type_{g}": 3.0 for g in range(10)},
            tolerance=1.5,
        )

        assert len(kept) == 40, "the group cap alone does not see a spread campaign"

    def test_the_actor_axis_bounds_the_same_campaign(self) -> None:
        attack = _batch(
            [(f"event_type_{g}", "compromised@x") for g in range(10) for _ in range(4)]
        )

        kept = caps.apply(
            attack,
            policy=caps.POLICY_BASELINE_RELATIVE,
            global_ceiling=1000,
            baseline_rates={f"event_type_{g}": 3.0 for g in range(10)},
            tolerance=1.5,
            actor_policy=_actor_cap(6),
        )

        assert len(kept) == 6
        assert caps.actor_counts(kept) == {"compromised@x": 6}

    def test_spreading_further_does_not_buy_more_allowance(self) -> None:
        """The structural property: the per-actor footprint is invariant under
        how widely the campaign is spread, which is exactly what the per-group
        footprint is not."""
        admitted = []
        for group_count in (1, 5, 20, 100):
            attack = _batch(
                [(f"g{g}", "compromised@x") for g in range(group_count) for _ in range(5)]
            )
            kept = caps.apply(
                attack,
                policy=caps.POLICY_GLOBAL,
                global_ceiling=100_000,
                actor_policy=_actor_cap(6),
            )
            admitted.append(len(kept))

        assert admitted == [5, 6, 6, 6]


class TestAttackerChangesTheGroupingKey:
    def test_inventing_new_groups_does_not_evade_the_actor_axis(self) -> None:
        """``event_type`` is partly attacker-influenced. A campaign that mints a
        fresh group per row faces the no-baseline floor on the group axis and
        the same actor allowance regardless."""
        attack = _batch([(f"novel_type_{i}", "compromised@x") for i in range(60)])

        kept = caps.apply(
            attack,
            policy=caps.POLICY_BASELINE_RELATIVE,
            global_ceiling=1000,
            baseline_rates={},
            floor=caps.DEFAULT_FLOOR,
            actor_policy=_actor_cap(8),
        )

        assert len(kept) == 8

    def test_hiding_in_a_high_volume_group_is_still_bounded(self) -> None:
        """V6 §20.3's worst case: a target hiding where the allowance is ~597.
        The group axis admits it; the actor axis does not."""
        attack = _batch([("auth_success", "compromised@x")] * 300)
        rates = {"auth_success": 400.0}

        group_only = caps.apply(
            attack,
            policy=caps.POLICY_BASELINE_RELATIVE,
            global_ceiling=10_000,
            baseline_rates=rates,
            tolerance=1.5,
        )
        assert len(group_only) == 300, "hiding in a busy group defeats the group cap"

        with_actor = caps.apply(
            attack,
            policy=caps.POLICY_BASELINE_RELATIVE,
            global_ceiling=10_000,
            baseline_rates=rates,
            tolerance=1.5,
            actor_policy=_actor_cap(12),
        )
        assert len(with_actor) == 12


class TestMultipleAnalystsAndConflict:
    def test_one_compromised_account_does_not_consume_everyone_else_s_budget(
        self,
    ) -> None:
        """Per-actor, not shared: an attacker must not be able to starve honest
        analysts by exhausting a common pool."""
        batch = _batch(
            [("auth_success", "compromised@x")] * 30
            + [("auth_success", "alice@x")] * 4
            + [("auth_success", "bob@x")] * 4
        )

        kept = caps.apply(
            batch,
            policy=caps.POLICY_GLOBAL,
            global_ceiling=1000,
            actor_policy=_actor_cap(5),
        )

        counts = caps.actor_counts(kept)
        assert counts == {"compromised@x": 5, "alice@x": 4, "bob@x": 4}

    def test_analysts_may_be_given_different_allowances(self) -> None:
        """A baseline-relative actor policy lets a busy analyst stay busy while
        a rarely-active account cannot suddenly submit hundreds of rows."""
        batch = _batch(
            [("auth_success", "busy@x")] * 30 + [("auth_success", "quiet@x")] * 30
        )

        kept = caps.apply(
            batch,
            policy=caps.POLICY_GLOBAL,
            global_ceiling=1000,
            actor_policy=caps.DimensionPolicy(
                policy=caps.POLICY_BASELINE_RELATIVE,
                baseline_rates={"busy@x": 20.0, "quiet@x": 1.0},
                tolerance=1.5,
                floor=2,
            ),
        )

        counts = caps.actor_counts(kept)
        assert counts["busy@x"] == 30
        assert counts["quiet@x"] == 2

    def test_a_refusal_on_one_axis_does_not_charge_the_other(self) -> None:
        """Otherwise turning on the actor cap would *weaken* the group cap: rows
        the actor axis rejected would still have eaten their group's budget."""
        batch = _batch(
            [("malware_detected", "compromised@x")] * 10
            + [("malware_detected", "alice@x")] * 3
        )

        kept = caps.apply(
            batch,
            policy=caps.POLICY_PER_GROUP_ABSOLUTE,
            global_ceiling=1000,
            per_group_ceiling=5,
            actor_policy=_actor_cap(2),
        )

        counts = caps.actor_counts(kept)
        # Each actor takes their own allowance of 2, so the group is charged 4
        # of its 5. Had the attacker's eight refusals been charged as they were
        # tested, the group ceiling would have been exhausted before alice was
        # reached and she would have got nothing - which is the failure mode
        # this ordering exists to prevent.
        assert counts == {"compromised@x": 2, "alice@x": 2}


class TestUnattributedFeedbackFailsClosed:
    def test_rows_without_an_actor_share_one_allowance(self) -> None:
        """Simulated and imported rows have no analyst. Exempting them would
        make enabling the actor cap a way to remove a limit."""
        batch = _batch([("auth_success", None)] * 20)  # type: ignore[list-item]

        kept = caps.apply(
            batch,
            policy=caps.POLICY_GLOBAL,
            global_ceiling=1000,
            actor_policy=_actor_cap(4),
        )

        assert len(kept) == 4
        assert caps.actor_counts(kept) == {caps.UNATTRIBUTED_ACTOR: 4}

    def test_an_unknown_dimension_policy_is_refused(self) -> None:
        import pytest

        with pytest.raises(ValueError, match="unknown dimension policy"):
            caps.apply(
                _batch([("auth_success", "a@x")]),
                policy=caps.POLICY_GLOBAL,
                global_ceiling=10,
                actor_policy=caps.DimensionPolicy(policy="whatever"),
            )
