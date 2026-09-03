"""Caps on what analyst feedback may put into the training corpus.

§8 measured that the global cap cannot stop targeted poisoning: it bounds
*volume*, and the attack is a *concentration* - 22 rows, 0.34% of the fit set,
far inside a 20% cap.

Measured honest behaviour is what makes a defence possible. Over 8 seeds the
event type `malware_detected` contributes **1.4** admitted-benign rows on
average; under attack it contributes **22**. The signal is not that a group is
large - `auth_success` legitimately contributes 114 - but that a group which is
almost never legitimately called benign suddenly is.

So a flat per-group ceiling cannot work: any value permitting auth_success's 114
also permits the attack's 22. These tests cover three policies and the
distinction between them.

Grouping is by `event_type`, which the normalizer produces before any detection
or labelling, so the defence is implementable in production. It is *not* the
ground-truth category.
"""

from __future__ import annotations

import pytest

from app.adaptation.experiments import feedback_caps as caps


def _candidates(**counts: int) -> list[caps.CapCandidate]:
    out: list[caps.CapCandidate] = []
    index = 0
    for group, count in counts.items():
        for _ in range(count):
            out.append(caps.CapCandidate(index=index, group=group))
            index += 1
    return out


class TestGlobalPolicy:
    def test_it_reproduces_the_existing_behaviour(self) -> None:
        kept = caps.apply(
            _candidates(a=50, b=50), policy=caps.POLICY_GLOBAL, global_ceiling=1000
        )
        assert len(kept) == 100

    def test_the_global_ceiling_still_binds(self) -> None:
        kept = caps.apply(
            _candidates(a=500), policy=caps.POLICY_GLOBAL, global_ceiling=100
        )
        assert len(kept) == 100


class TestAbsolutePerGroupPolicy:
    def test_it_caps_every_group_at_the_same_ceiling(self) -> None:
        kept = caps.apply(
            _candidates(malware_detected=22, auth_success=114),
            policy=caps.POLICY_PER_GROUP_ABSOLUTE,
            global_ceiling=1000,
            per_group_ceiling=10,
        )
        counts = caps.group_counts(kept)
        assert counts["malware_detected"] == 10
        assert counts["auth_success"] == 10

    def test_it_cannot_separate_the_attack_from_honest_volume(self) -> None:
        """The reason this policy is measured and then rejected: a ceiling loose
        enough to keep auth_success's honest 114 rows also admits the attack's 22
        in full."""
        kept = caps.apply(
            _candidates(malware_detected=22, auth_success=114),
            policy=caps.POLICY_PER_GROUP_ABSOLUTE,
            global_ceiling=1000,
            per_group_ceiling=120,
        )
        counts = caps.group_counts(kept)
        assert counts["auth_success"] == 114
        assert counts["malware_detected"] == 22, "the attack passes untouched"


class TestBaselineRelativePolicy:
    def test_a_group_at_its_baseline_is_untouched(self) -> None:
        kept = caps.apply(
            _candidates(auth_success=114),
            policy=caps.POLICY_BASELINE_RELATIVE,
            global_ceiling=1000,
            baseline_rates={"auth_success": 114.0, "malware_detected": 1.4},
            tolerance=3.0,
        )
        assert caps.group_counts(kept)["auth_success"] == 114

    def test_a_spike_above_the_baseline_is_clipped(self) -> None:
        """The attack: a group whose honest contribution is 1.4 rows suddenly
        supplying 22."""
        kept = caps.apply(
            _candidates(malware_detected=22),
            policy=caps.POLICY_BASELINE_RELATIVE,
            global_ceiling=1000,
            baseline_rates={"malware_detected": 1.4},
            tolerance=3.0,
            floor=2,
        )
        assert caps.group_counts(kept)["malware_detected"] <= 5

    def test_honest_volume_and_the_attack_are_separated_by_one_policy(self) -> None:
        """The property the absolute policy cannot achieve."""
        kept = caps.apply(
            _candidates(malware_detected=22, auth_success=114),
            policy=caps.POLICY_BASELINE_RELATIVE,
            global_ceiling=1000,
            baseline_rates={"auth_success": 114.0, "malware_detected": 1.4},
            tolerance=3.0,
            floor=2,
        )
        counts = caps.group_counts(kept)
        assert counts["auth_success"] == 114
        assert counts["malware_detected"] <= 5

    def test_an_unseen_group_gets_the_floor_not_unlimited_admission(self) -> None:
        """A group absent from the baseline must not default to trusted."""
        kept = caps.apply(
            _candidates(brand_new=40),
            policy=caps.POLICY_BASELINE_RELATIVE,
            global_ceiling=1000,
            baseline_rates={"auth_success": 114.0},
            tolerance=3.0,
            floor=2,
        )
        assert caps.group_counts(kept)["brand_new"] == 2


class TestCommonProperties:
    @pytest.mark.parametrize(
        "policy",
        [caps.POLICY_GLOBAL, caps.POLICY_PER_GROUP_ABSOLUTE, caps.POLICY_BASELINE_RELATIVE],
    )
    def test_every_policy_respects_the_global_ceiling(self, policy: str) -> None:
        kept = caps.apply(
            _candidates(a=400, b=400),
            policy=policy,
            global_ceiling=50,
            per_group_ceiling=1000,
            baseline_rates={"a": 400.0, "b": 400.0},
        )
        assert len(kept) <= 50

    def test_it_is_deterministic(self) -> None:
        args = {
            "policy": caps.POLICY_BASELINE_RELATIVE,
            "global_ceiling": 30,
            "baseline_rates": {"a": 5.0},
            "tolerance": 3.0,
        }
        first = caps.apply(_candidates(a=100), **args)
        second = caps.apply(_candidates(a=100), **args)
        assert [c.index for c in first] == [c.index for c in second]

    def test_an_unknown_policy_is_refused(self) -> None:
        with pytest.raises(ValueError, match="unknown cap policy"):
            caps.apply(_candidates(a=1), policy="nope", global_ceiling=10)
