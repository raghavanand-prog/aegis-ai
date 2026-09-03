"""The patient adversary V6 §9.3 named and did not test.

§9's defence caps a group's admitted-benign rows at ``tolerance x baseline``,
where the baseline is learned from prior feedback datasets. §8's smash-and-grab
attack lands 22 rows in one batch and is clipped to 4.

The patient version does not fight the cap. It **feeds** it. Each cycle it
contributes slightly more than the last, staying inside the tolerance so every
batch passes; the next cycle's baseline is computed from a history that now
includes that contribution, so the ceiling it must stay under has risen. The
question is whether that ratchets, and how fast.

This became more load-bearing, not less, when ``baseline_relative`` became the
default cap policy: the baseline is now consulted on every run.

The control matters as much as the treatment. An honest campaign must **not**
ratchet, or the effect is an artefact of the simulation rather than an attack.
"""

from __future__ import annotations

import pytest

from app.adaptation.experiments import patient_poisoning as pp


class TestCampaignMechanics:
    def test_an_honest_campaign_does_not_ratchet(self) -> None:
        """The control. Honest feedback volume is roughly stationary, so the
        allowance it earns must be too."""
        campaign = pp.run_campaign(
            seed=1337, target_category="MALWARE", cycles=6, adversary_reach=0.0
        )
        allowances = [cycle["targetAllowance"] for cycle in campaign["cycles"]]
        assert max(allowances) < 3 * allowances[0] + 1, (
            "an honest campaign must not inflate its own ceiling"
        )

    def test_honest_noise_admits_malicious_rows_and_that_is_not_the_attack(
        self,
    ) -> None:
        """Measured while building this: an honest campaign admits ~14 malicious
        rows per cycle purely from 5% label noise. A metric counting all
        admitted-malicious rows is dominated by that and cannot see an attack,
        which is why the campaign separates the two."""
        campaign = pp.run_campaign(
            seed=1337, target_category="MALWARE", cycles=4, adversary_reach=0.0
        )
        noise = [cycle["maliciousAdmitted"] for cycle in campaign["cycles"]]
        targeted = [cycle["poisonLanded"] for cycle in campaign["cycles"]]
        assert sum(noise) > 0, "realistic noise must admit some malicious rows"
        assert sum(targeted) < sum(noise), "the targeted count must be the narrow one"

    def test_the_adversary_ratchets_its_own_allowance(self) -> None:
        campaign = pp.run_campaign(
            seed=1337, target_category="MALWARE", cycles=6, adversary_reach=1.0
        )
        allowances = [cycle["targetAllowance"] for cycle in campaign["cycles"]]
        assert allowances[-1] > allowances[0], "the ceiling must rise"

    def test_poison_landed_per_cycle_is_reported(self) -> None:
        campaign = pp.run_campaign(
            seed=1337, target_category="MALWARE", cycles=4, adversary_reach=1.0
        )
        for cycle in campaign["cycles"]:
            assert "poisonLanded" in cycle
            assert "targetAllowance" in cycle
            assert "baselineRate" in cycle

    def test_the_baseline_is_learned_from_prior_cycles_only(self) -> None:
        """A baseline that included the batch under review would sanction the
        batch under review."""
        campaign = pp.run_campaign(
            seed=1337, target_category="MALWARE", cycles=3, adversary_reach=1.0
        )
        assert campaign["cycles"][0]["baselineRate"] == pytest.approx(
            campaign["honestBaselineRate"], abs=1e-6
        )

    def test_it_refuses_a_campaign_with_no_honest_history(self) -> None:
        """Production refuses a cold start, so a campaign that began from one
        would be modelling something the system does not permit."""
        with pytest.raises(ValueError, match="honest history"):
            pp.run_campaign(
                seed=1337,
                target_category="MALWARE",
                cycles=3,
                adversary_reach=1.0,
                honest_history=0,
            )


class TestDamage:
    def test_the_campaign_reports_recall_damage_at_its_end(self) -> None:
        result = pp.measure_damage(
            seed=1337, target_category="MALWARE", cycles=6, adversary_reach=1.0
        )
        assert result["targetRecall"]["honest"] is not None
        assert result["targetRecall"]["poisoned"] is not None
        assert result["finalPoisonLanded"] >= 0


class TestPatientPoisoningRunner:
    def test_it_reports_the_honest_control_beside_the_attack(self, tmp_path) -> None:
        """A ratchet with no control is a simulation artefact until proven
        otherwise."""
        import json

        from app.adaptation.experiments import run_patient_poisoning_eval

        assert (
            run_patient_poisoning_eval.main(
                [
                    "--seeds",
                    "2",
                    "--cycles",
                    "3",
                    "--tolerances",
                    "1.5",
                    "3.0",
                    "--damage-cycles",
                    "3",
                    "--output-dir",
                    str(tmp_path),
                    "--max-seconds",
                    "900",
                ]
            )
            == 0
        )
        report = json.loads(
            next(tmp_path.glob("v6-patient-poisoning-*.json")).read_text()
        )
        assert set(report["arms"]) == {"honest", "adversary"}
        assert len(report["tolerance"]) == 2
        assert report["damage"][0]["cohensD"] is not None
