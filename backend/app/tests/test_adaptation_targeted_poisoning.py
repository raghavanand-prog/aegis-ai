"""The targeted poisoning case, flagged untested since §6.4.

V6 §7 measured *diffuse* poisoning - randomly chosen malicious events labelled
benign - and found the cap bounded it. It also found that false-positive rate,
F1 and ROC-AUC all *improve* under benign bias while recall falls, so recall is
the only aggregate metric that exposes it.

A targeted adversary is different in kind. Rather than spreading errors across
the corpus, they label one attack category benign, so the damage concentrates in
that category's recall. Thirteen categories share the aggregate, so the
hypothesis under test is that **aggregate recall hides it too** - which would
make the recall floor §7.3 recommended insufficient on its own.
"""

from __future__ import annotations

import pytest

from app.adaptation.experiments import targeted_poisoning as tp


class TestAdversaryModel:
    def test_only_the_target_category_is_mislabelled(self) -> None:
        """Everything else is labelled nominally, so any measured damage is
        attributable to the attack and not to general noise."""
        result = tp.measure(seed=1337, target_category="RANSOMWARE")
        assert result["poisonedCategories"] == ["RANSOMWARE"]

    def test_the_poisoning_actually_lands(self) -> None:
        result = tp.measure(seed=1337, target_category="RANSOMWARE")
        assert result["poisonedRows"] > 0

    def test_a_smaller_adversary_budget_poisons_less(self) -> None:
        full = tp.measure(seed=1337, target_category="RANSOMWARE", adversary_reach=1.0)
        half = tp.measure(seed=1337, target_category="RANSOMWARE", adversary_reach=0.3)
        assert half["poisonedRows"] < full["poisonedRows"]

    def test_it_refuses_a_category_it_cannot_target(self) -> None:
        with pytest.raises(ValueError, match="no .*samples"):
            tp.measure(seed=1337, target_category="NOT_A_CATEGORY")


class TestDamageIsMeasuredWhereItLands:
    def test_it_reports_per_category_recall_not_only_aggregate(self) -> None:
        """The whole point. If this experiment reported only aggregate metrics it
        would reproduce the blind spot it exists to expose."""
        result = tp.measure(seed=1337, target_category="RANSOMWARE")
        assert result["targetRecall"]["baseline"] is not None
        assert result["targetRecall"]["poisoned"] is not None
        assert result["nonTargetRecall"]["baseline"] is not None
        assert result["aggregate"]["poisoned"]["recall"] is not None

    def test_it_is_deterministic_for_a_seed(self) -> None:
        first = tp.measure(seed=99, target_category="PORT_SCAN")
        second = tp.measure(seed=99, target_category="PORT_SCAN")
        assert first["targetRecall"]["poisoned"] == second["targetRecall"]["poisoned"]


class TestTargetedPoisoningRunner:
    def test_it_reports_attenuation_and_the_aggregate_seed_spread(
        self, tmp_path
    ) -> None:
        """Both are needed to judge detectability: how much the aggregate hides,
        and whether what remains is bigger than the aggregate's own noise."""
        import json

        from app.adaptation.experiments import run_targeted_poisoning_eval

        assert (
            run_targeted_poisoning_eval.main(
                [
                    "--seeds",
                    "3",
                    "--targets",
                    "MALWARE",
                    "--output-dir",
                    str(tmp_path),
                    "--max-seconds",
                    "900",
                ]
            )
            == 0
        )
        report = json.loads(
            next(tmp_path.glob("v6-targeted-poisoning-*.json")).read_text()
        )
        row = report["results"][0]
        assert row["targetRecall"]["delta"] is not None
        assert row["aggregateRecall"]["seedStdev"] is not None
        assert report["threatModel"]


class TestCapPoliciesAgainstTheAttack:
    """§8 measured that the global cap cannot stop this. These assert what the
    per-group policies do about it, and what they cost."""

    def test_a_baseline_relative_cap_admits_far_fewer_poisoned_rows(self) -> None:
        from app.adaptation.experiments import feedback_caps

        rates = tp.honest_baseline_rates(seeds=(4242, 99))
        unguarded = tp.measure(seed=1337, target_category="MALWARE")
        guarded = tp.measure(
            seed=1337,
            target_category="MALWARE",
            cap_policy=feedback_caps.POLICY_BASELINE_RELATIVE,
            baseline_rates=rates,
        )
        assert guarded["poisonedRows"] < unguarded["poisonedRows"]

    def test_the_baseline_is_learned_from_honest_feedback_only(self) -> None:
        """If the baseline were computed from the attacked stream it would learn
        the attack as normal."""
        rates = tp.honest_baseline_rates(seeds=(4242, 99))
        assert rates["malware_detected"] < 5.0
        assert rates["auth_success"] > 50.0

    def test_grouping_uses_an_observable_field_not_the_label(self) -> None:
        """A defence keyed on ground-truth category could not ship."""
        assert tp.GROUP_FIELD == "event_type"
