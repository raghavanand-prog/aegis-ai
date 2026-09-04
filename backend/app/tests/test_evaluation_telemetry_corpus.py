"""A labelled corpus drawn from the distribution production actually fits.

V6 §4 measured the problem: the labelled evaluation corpus's fit split is **40%
malicious**, and its own provenance calls it out of distribution for the anomaly
model. It was built to exercise *rule thresholds* and was then pressed into
service as ML training data. Every detection number V4 and V5 published on it
bounds an artefact.

This corpus is drawn from the **runtime telemetry generator** - the one
`train_anomaly_model` actually fits - and labelled from that generator's own
scenario intent, which its docstrings state explicitly.

The labelling is the whole substance, so most of these tests are about it. In
particular, four scenarios exist specifically to be *anomalous but not
attacks* - "simply rare", "deliberately not a DGA label" - and calling them
malicious would fabricate ground truth in the direction that flatters an anomaly
detector.
"""

from __future__ import annotations

import pytest

from app.evaluation.datasets import telemetry_labelled as tl


class TestLabelMap:
    def test_every_generator_scenario_has_an_explicit_label(self) -> None:
        """A scenario added later must not silently default to benign, which
        would quietly deflate the malicious rate of every future corpus."""
        from app.telemetry.sources.synthetic import SyntheticTelemetrySource

        generated = {name for _, name in SyntheticTelemetrySource.SCENARIOS}
        assert generated == set(tl.SCENARIO_LABELS), (
            "scenario set and label map have diverged"
        )

    def test_rare_but_ordinary_behaviour_is_labelled_benign(self) -> None:
        """The generator says these are 'simply rare' and 'not rule-breaking'.
        Rare is not malicious. Labelling them malicious would reward an anomaly
        detector for flagging ordinary novelty."""
        for scenario in (
            "_sysmon_rare_process",
            "_dns_rare_domain",
            "_firewall_unusual_port",
            "_entra_rare_source",
        ):
            assert tl.SCENARIO_LABELS[scenario] is tl.Label.BENIGN

    def test_named_attacks_are_labelled_malicious(self) -> None:
        for scenario in (
            "_defender_malware",
            "_sysmon_lsass_access",
            "_edr_ransomware",
            "_edr_exfiltration",
            "_firewall_port_scan",
            "_dns_beaconing",
        ):
            assert tl.SCENARIO_LABELS[scenario] is tl.Label.MALICIOUS

    def test_ordinary_traffic_is_labelled_benign(self) -> None:
        for scenario in (
            "_defender_benign_scan",
            "_sysmon_process",
            "_entra_signin_success",
            "_firewall_allow",
            "_dns_query",
            "_linux_ssh",
        ):
            assert tl.SCENARIO_LABELS[scenario] is tl.Label.BENIGN

    def test_every_label_carries_its_justification(self) -> None:
        """A label map without stated reasons is an assertion. These decide what
        every number on this corpus means."""
        for scenario in tl.SCENARIO_LABELS:
            assert tl.LABEL_RATIONALE[scenario].strip()


class TestCorpus:
    def test_contamination_is_production_like_not_forty_percent(self) -> None:
        """The entire point of the rebuild."""
        dataset = tl.telemetry_labelled_dataset(seed=1337, samples=2000)
        rate = sum(1 for s in dataset.samples if s.is_malicious) / len(dataset.samples)
        assert 0.02 < rate < 0.25, f"malicious rate {rate:.3f} is not production-like"

    def test_it_is_reproducible_for_a_seed(self) -> None:
        first = tl.telemetry_labelled_dataset(seed=99, samples=500)
        second = tl.telemetry_labelled_dataset(seed=99, samples=500)
        assert first.fingerprint() == second.fingerprint()

    def test_a_different_seed_is_a_different_corpus(self) -> None:
        assert (
            tl.telemetry_labelled_dataset(seed=1, samples=500).fingerprint()
            != tl.telemetry_labelled_dataset(seed=2, samples=500).fingerprint()
        )

    def test_samples_carry_the_scenario_as_their_category(self) -> None:
        """Per-category analysis is what V6 §8 showed aggregate metrics hide."""
        dataset = tl.telemetry_labelled_dataset(seed=1337, samples=500)
        categories = {s.category for s in dataset.samples}
        assert categories <= set(tl.SCENARIO_LABELS)
        assert len(categories) > 5

    def test_it_refuses_a_corpus_too_small_to_split(self) -> None:
        with pytest.raises(ValueError, match="too small"):
            tl.telemetry_labelled_dataset(seed=1337, samples=10)


class TestItIsTheRightDistribution:
    def test_the_fit_split_is_not_dominated_by_attacks(self) -> None:
        """The V4/V5 corpus put 40% malicious in the fit split, which is what
        broke the density estimate. This must not."""
        from app.evaluation.splits import STRATIFIED_GROUP, build_split

        dataset = tl.telemetry_labelled_dataset(seed=1337, samples=3000)
        plan = build_split(dataset, strategy=STRATIFIED_GROUP, seed=1337)
        fit = list(plan.train.samples) + list(plan.validation.samples)
        rate = sum(1 for s in fit if s.is_malicious) / len(fit)
        assert rate < 0.25, f"fit split is {rate:.1%} malicious"


class TestPrevalenceIsControlled:
    """The generator is attack-heavy by design - measured at 42.7% malicious,
    which is *worse* than the 40% corpus this was meant to improve on. A demo
    generator over-represents attacks because a demo with 1% attacks shows
    nothing.

    So prevalence is a **design parameter of the evaluation corpus**, set
    explicitly rather than inherited. That is standard practice for an eval
    corpus and it is the only way to get a fit split an unsupervised density
    model can learn from.
    """

    @pytest.mark.parametrize("target", [0.05, 0.10, 0.20])
    def test_it_hits_the_requested_malicious_rate(self, target: float) -> None:
        dataset = tl.telemetry_labelled_dataset(
            seed=1337, samples=2000, malicious_rate=target
        )
        rate = sum(1 for s in dataset.samples if s.is_malicious) / len(dataset.samples)
        assert rate == pytest.approx(target, abs=0.02)

    def test_the_requested_rate_is_recorded_on_the_dataset(self) -> None:
        """A corpus whose prevalence was chosen must say so, or a reader will
        take it for an observed base rate."""
        dataset = tl.telemetry_labelled_dataset(
            seed=1337, samples=2000, malicious_rate=0.10
        )
        assert dataset.sampling["maliciousRate"] == 0.10
        assert any("prevalence" in note.lower() for note in dataset.provenance.notes)

    def test_the_generator_rate_is_available_unresampled(self) -> None:
        """Passing None keeps the generator's own mix, so the attack-heaviness
        can be measured rather than only asserted."""
        dataset = tl.telemetry_labelled_dataset(
            seed=1337, samples=2000, malicious_rate=None
        )
        rate = sum(1 for s in dataset.samples if s.is_malicious) / len(dataset.samples)
        assert rate > 0.30, "the generator is attack-heavy; this documents it"

    @pytest.mark.parametrize("bad", [0.0, 1.0, 1.5, -0.1])
    def test_a_rate_outside_the_unit_interval_is_refused(self, bad: float) -> None:
        with pytest.raises(ValueError, match="must lie in"):
            tl.telemetry_labelled_dataset(
                seed=1337, samples=2000, malicious_rate=bad
            )

