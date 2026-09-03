"""V5 adaptation experiments (Phase L).

These tests cover the *instrument*, not the findings. A simulated analyst whose
noise rate is wrong, or a curation step that quietly drops the wrong rows, would
produce results that look fine and mean nothing.
"""

from __future__ import annotations

import json

import pytest

from app.adaptation.experiments import (
    run_adaptation_eval,
    run_novel_behaviour_eval,
    scenarios,
    seeds,
    simulation,
)
from app.adaptation.feedback.labels import FeedbackLabel
from app.evaluation.datasets.adapters import synthetic_dataset
from app.evaluation.splits import STRATIFIED_GROUP, build_split


class TestSimulatedAnalyst:
    def test_the_same_seed_produces_the_same_feedback(self) -> None:
        truth = [True, False, True, False] * 25
        first = simulation.simulate_feedback(truth, seed=7)
        second = simulation.simulate_feedback(truth, seed=7)
        assert [item.label for item in first] == [item.label for item in second]

    def test_zero_noise_and_full_coverage_agrees_with_truth(self) -> None:
        truth = [True, False] * 50
        feedback = simulation.simulate_feedback(
            truth, seed=1, noise_rate=0.0, coverage=1.0, abstention_rate=0.0
        )
        assert len(feedback) == len(truth)
        for item in feedback:
            assert item.label.binary_label is truth[item.index]

    def test_noise_flips_roughly_the_requested_share(self) -> None:
        """Approximate on purpose - an exact count would be testing the RNG."""
        truth = [True, False] * 500
        feedback = simulation.simulate_feedback(
            truth, seed=3, noise_rate=0.15, coverage=1.0, abstention_rate=0.0
        )
        wrong = sum(1 for item in feedback if item.label.binary_label is not truth[item.index])
        assert 0.10 < wrong / len(feedback) < 0.20

    def test_coverage_limits_how_much_is_reviewed(self) -> None:
        truth = [True, False] * 250
        feedback = simulation.simulate_feedback(truth, seed=5, coverage=0.25)
        assert 0.15 < len(feedback) / len(truth) < 0.35

    def test_abstention_produces_uncertain_labels(self) -> None:
        truth = [True, False] * 250
        feedback = simulation.simulate_feedback(
            truth, seed=11, coverage=1.0, abstention_rate=0.2, noise_rate=0.0
        )
        uncertain = [item for item in feedback if item.label is FeedbackLabel.UNCERTAIN]
        assert uncertain, "abstention should produce uncertain verdicts"
        # And an uncertain verdict carries no binary position, so it cannot
        # silently become a training label.
        assert all(item.label.binary_label is None for item in uncertain)

    def test_shuffled_control_destroys_the_label_signal(self) -> None:
        """The control the whole comparison rests on. If this still correlates
        with truth, it is not a control."""
        truth = [True] * 200 + [False] * 200
        shuffled = simulation.simulate_feedback(
            truth, seed=13, coverage=1.0, noise_rate=0.0, abstention_rate=0.0, shuffle_labels=True
        )
        agreement = sum(
            1 for item in shuffled if item.label.binary_label is truth[item.index]
        ) / len(shuffled)
        assert 0.35 < agreement < 0.65, "shuffled labels should be near chance"


class TestThresholdArm:
    def test_the_chosen_threshold_is_bounded_by_the_safety_step(self) -> None:
        scores = [0.1, 0.2, 0.6, 0.66, 0.7, 0.9]
        truth = [False, False, False, True, True, True]
        chosen = simulation.choose_threshold(
            scores, truth, current=0.65, max_step=0.05
        )
        assert abs(chosen - 0.65) <= 0.05

    def test_it_prefers_an_operating_point_that_reduces_false_positives(self) -> None:
        # Benign scores cluster just above the current threshold.
        scores = [0.66, 0.67, 0.68] * 20 + [0.95] * 10
        truth = [False] * 60 + [True] * 10
        chosen = simulation.choose_threshold(scores, truth, current=0.65, max_step=0.05)
        assert chosen > 0.65

    def test_it_refuses_to_choose_from_no_labelled_data(self) -> None:
        with pytest.raises(ValueError, match="labelled"):
            simulation.choose_threshold([], [], current=0.65, max_step=0.05)


class TestCurationArm:
    def test_curation_drops_events_analysts_called_malicious(self) -> None:
        """Isolation Forest assumes its fit set is mostly normal. Curation is
        the only way feedback can act on that assumption."""
        vectors = [(float(i),) for i in range(10)]
        verdicts = {0: False, 1: True, 2: False, 3: True}
        kept = simulation.curate_fit_set(vectors, verdicts)
        assert len(kept) == len(vectors) - 2
        assert (1.0,) not in kept and (3.0,) not in kept

    def test_unreviewed_events_are_kept(self) -> None:
        """Absence of a verdict is not evidence of malice, and dropping
        unreviewed data would shrink the corpus for no reason."""
        vectors = [(float(i),) for i in range(10)]
        kept = simulation.curate_fit_set(vectors, {1: True})
        assert len(kept) == 9

    def test_curation_refuses_to_empty_the_fit_set(self) -> None:
        vectors = [(1.0,), (2.0,)]
        with pytest.raises(ValueError, match="fit set"):
            simulation.curate_fit_set(vectors, {0: True, 1: True})


class TestSeedPlan:
    """V6 Track 1 needs substantially more than three seeds, and the V5 result
    must stay reproducible from its own published command. Both constraints
    land on the seed plan, so the plan is tested rather than assumed."""

    def test_the_first_three_seeds_are_the_v5_seeds(self) -> None:
        """`--seeds 3` must still reproduce docs/V5_RESEARCH_REPORT.md exactly.
        Changing these would silently invalidate a published result."""
        assert seeds.build_seeds(3) == [1337, 4242, 99]

    def test_a_longer_plan_extends_a_shorter_one(self) -> None:
        """Adding seeds must not resample the ones already reported, or every
        V6 run would be incomparable with the run before it."""
        short = seeds.build_seeds(5)
        long = seeds.build_seeds(50)
        assert long[: len(short)] == short

    def test_it_produces_the_requested_count(self) -> None:
        assert len(seeds.build_seeds(50)) == 50

    def test_seeds_are_distinct(self) -> None:
        """A repeated seed is a repeated run reported as an independent one,
        which would understate the variance the V5 report called unsettled."""
        plan = seeds.build_seeds(50)
        assert len(set(plan)) == 50

    def test_it_is_deterministic_across_calls(self) -> None:
        assert seeds.build_seeds(50) == seeds.build_seeds(50)

    def test_it_refuses_a_non_positive_count(self) -> None:
        with pytest.raises(ValueError, match="at least one seed"):
            seeds.build_seeds(0)


class TestRunnerSeedWiring:
    """The V5 runner truncated against a five-element list, so `--seeds 50`
    silently ran five. Track 1's whole point is more seeds than that."""

    def test_the_runner_honours_a_seed_count_beyond_the_v5_list(
        self, tmp_path, monkeypatch
    ) -> None:
        calls: list[int] = []

        def fake_run_condition(corpus, *, condition, seed, **kwargs):
            calls.append(seed)
            return scenarios.ScenarioResult(
                name=condition,
                condition=condition,
                seed=seed,
                metrics=dict.fromkeys(("precision", "recall", "f1", "falsePositiveRate", "falseNegativeRate", "alertVolume", "threshold"), 0.0),
            )

        monkeypatch.setattr(scenarios, "run_condition", fake_run_condition)
        monkeypatch.setattr(
            run_adaptation_eval.scenarios, "run_condition", fake_run_condition
        )

        exit_code = run_adaptation_eval.main(
            ["--seeds", "8", "--output-dir", str(tmp_path), "--max-seconds", "600"]
        )

        assert exit_code == 0
        reported = json.loads(
            next(tmp_path.glob("v5-adaptation-*.json")).read_text()
        )
        for result in reported["results"]:
            assert len(result["seeds"]) == 8
            assert len(set(result["seeds"])) == 8
        assert set(calls) == set(seeds.build_seeds(8))


class TestNoiseInvariantConditions:
    def test_the_random_control_is_run_once_rather_than_per_noise_rate(self) -> None:
        """`shuffle_labels` skips the noise branch entirely, so the control is
        identical at every noise rate - the V5 report shows all three rows at
        F1 0.106497. Running it three times per seed triples the cost of the
        single most important control for no extra evidence."""
        assert "random_feedback" in run_adaptation_eval.NOISE_INVARIANT

    def test_the_control_really_is_invariant_to_the_requested_noise(self) -> None:
        """The reason the condition may be collapsed. If the simulator ever
        starts consuming noise under shuffling, this fails before the runner
        silently drops a genuine dimension."""
        truth = [True, False] * 100
        quiet = simulation.simulate_feedback(
            truth, seed=17, noise_rate=0.0, coverage=1.0, shuffle_labels=True
        )
        loud = simulation.simulate_feedback(
            truth, seed=17, noise_rate=0.15, coverage=1.0, shuffle_labels=True
        )
        assert [(v.index, v.label) for v in quiet] == [(v.index, v.label) for v in loud]


def _varying_run_condition(corpus, *, condition, seed, **kwargs):
    """A stand-in that varies with condition and seed, so spread exists and an
    interval and an effect size are actually computable."""
    base = 0.25 if condition == "both_arms" else 0.10
    offset = (seed % 7) / 100.0
    return scenarios.ScenarioResult(
        name=condition,
        condition=condition,
        seed=seed,
        metrics={
            "precision": 0.8,
            "recall": 0.14,
            "f1": base + offset,
            "falsePositiveRate": 0.017,
            "falseNegativeRate": 0.86,
            "alertVolume": 26.0,
            "threshold": 0.65,
        },
    )


def _run(tmp_path, monkeypatch, seed_count: int) -> dict:
    monkeypatch.setattr(scenarios, "run_condition", _varying_run_condition)
    monkeypatch.setattr(
        run_adaptation_eval.scenarios, "run_condition", _varying_run_condition
    )
    assert (
        run_adaptation_eval.main(
            [
                "--seeds",
                str(seed_count),
                "--output-dir",
                str(tmp_path),
                "--max-seconds",
                "600",
            ]
        )
        == 0
    )
    return json.loads(next(tmp_path.glob("v5-adaptation-*.json")).read_text())


class TestReportEvidence:
    """V6 requires per-seed results, intervals and effect sizes. V5's report
    aggregated the per-seed values away, so its stated 0.117-0.333 spread could
    not be recomputed from the artifact - only from the console log."""

    def test_every_condition_records_its_per_seed_results(
        self, tmp_path, monkeypatch
    ) -> None:
        report = _run(tmp_path, monkeypatch, 10)
        for result in report["results"]:
            per_seed = result["perSeed"]
            assert [row["seed"] for row in per_seed] == result["seeds"]
            assert all("f1" in row["metrics"] for row in per_seed)

    def test_aggregates_carry_a_bootstrap_interval(self, tmp_path, monkeypatch) -> None:
        report = _run(tmp_path, monkeypatch, 10)
        f1 = report["results"][0]["metrics"]["f1"]
        assert f1["ci95"]["lower"] is not None
        assert f1["ci95"]["lower"] <= f1["mean"] <= f1["ci95"]["upper"]

    def test_an_interval_is_unavailable_rather_than_invented_below_three_seeds(
        self, tmp_path, monkeypatch
    ) -> None:
        report = _run(tmp_path, monkeypatch, 2)
        f1 = report["results"][0]["metrics"]["f1"]
        assert f1["ci95"]["lower"] is None
        assert f1["ci95"]["unavailableReason"]

    def test_the_report_compares_adaptation_against_the_random_control(
        self, tmp_path, monkeypatch
    ) -> None:
        """The comparison V5 had to compute by hand. Without it in the artifact,
        the 34%/66% mechanism-versus-content split is not reproducible."""
        report = _run(tmp_path, monkeypatch, 10)
        comparisons = {
            (row["treatment"], row["control"], row["metric"]): row
            for row in report["comparisons"]
        }
        row = comparisons[("both_arms", "random_feedback", "f1")]
        assert row["meanDifference"] > 0
        assert row["cohensD"] is not None
        assert row["seeds"] == 10


class TestV5NovelBehaviourHarness:
    """Pins the V5 harness as it was, so the historical result stays
    interpretable. These tests were missing: nothing in the repository called
    `run_new_behaviour`, so V5 section 3 was produced by an uncommitted ad-hoc
    invocation."""

    def test_the_v5_harness_draws_feedback_only_from_the_fit_set(self) -> None:
        """The confound, pinned as a fact about the historical harness. The
        withheld category is removed from the fit set and feedback is then drawn
        from that same fit set, so no verdict about the withheld category can
        reach the loop."""
        result = scenarios.run_new_behaviour(seed=1337, withheld_category="PORT_SCAN")
        assert result["verdictsAboutWithheld"] == 0

    def test_the_v5_harness_still_reports_both_sides(self) -> None:
        result = scenarios.run_new_behaviour(seed=1337, withheld_category="PORT_SCAN")
        assert result["static"]["newBehaviour"]["recall"] is not None
        assert result["adapted"]["historical"]["recall"] is not None


class TestControlledNovelBehaviour:
    """Track 3's controlled comparison. Same dataset, same seed, same adaptation
    configuration; the single variable is whether the analyst ever labelled an
    instance of the withheld category."""

    def test_the_scoring_set_is_disjoint_from_the_adaptation_window(self) -> None:
        """Without this the corrected arm would simply leak test labels, and a
        gain would mean nothing."""
        result = scenarios.run_novel_behaviour_controlled(
            seed=1337, withheld_category="PORT_SCAN", feedback_includes_withheld=True
        )
        assert set(result["adaptationWindowIds"]).isdisjoint(result["scoringIds"])
        assert result["scoringIds"]

    def test_both_arms_score_on_exactly_the_same_events(self) -> None:
        """One variable changed at a time. If the arms scored different events
        the comparison would be uninterpretable."""
        withheld = scenarios.run_novel_behaviour_controlled(
            seed=1337, withheld_category="PORT_SCAN", feedback_includes_withheld=False
        )
        supplied = scenarios.run_novel_behaviour_controlled(
            seed=1337, withheld_category="PORT_SCAN", feedback_includes_withheld=True
        )
        assert withheld["scoringIds"] == supplied["scoringIds"]
        assert withheld["adaptationWindowIds"] == supplied["adaptationWindowIds"]

    def test_the_withheld_arm_reproduces_the_v5_confound(self) -> None:
        result = scenarios.run_novel_behaviour_controlled(
            seed=1337, withheld_category="PORT_SCAN", feedback_includes_withheld=False
        )
        assert result["verdictsAboutWithheld"] == 0

    def test_the_supplied_arm_actually_supplies_verdicts(self) -> None:
        result = scenarios.run_novel_behaviour_controlled(
            seed=1337, withheld_category="PORT_SCAN", feedback_includes_withheld=True
        )
        assert result["verdictsAboutWithheld"] > 0

    def test_it_reports_the_reachable_threshold_floor_and_novel_scores(self) -> None:
        """The measurement that separates a representation failure from a
        feedback failure: if novel events do not score above the most permissive
        reachable threshold, no feedback can help through the threshold arm."""
        result = scenarios.run_novel_behaviour_controlled(
            seed=1337, withheld_category="LATERAL_MOVEMENT", feedback_includes_withheld=True
        )
        floor = result["reachableThresholdFloor"]
        assert floor == pytest.approx(
            scenarios.DEFAULT_THRESHOLD - scenarios.MAX_THRESHOLD_STEP
        )
        assert result["novelScores"]["aboveFloor"] == 0
        assert result["novelScores"]["max"] < floor

    def test_it_refuses_a_category_it_cannot_measure(self) -> None:
        with pytest.raises(ValueError, match="no held-out samples"):
            scenarios.run_novel_behaviour_controlled(
                seed=1337,
                withheld_category="NOT_A_CATEGORY",
                feedback_includes_withheld=True,
            )


class TestNovelBehaviourRunner:
    def test_it_reports_both_arms_per_category_without_aggregating(
        self, tmp_path
    ) -> None:
        """V5 averaged recall across categories and reported 0.0085 over nine
        runs. Track 3 measured that the categories differ in kind - one is
        separable by the model, two are not - so a mean across them describes
        none of them."""
        report = run_novel_behaviour_eval.main(
            [
                "--seeds",
                "2",
                "--categories",
                "PORT_SCAN",
                "LATERAL_MOVEMENT",
                "--output-dir",
                str(tmp_path),
                "--max-seconds",
                "900",
                "--format",
                "json",
            ]
        )
        assert report == 0
        written = json.loads(
            next(tmp_path.glob("v6-novel-behaviour-*.json")).read_text()
        )
        categories = {row["withheldCategory"] for row in written["results"]}
        assert categories == {"PORT_SCAN", "LATERAL_MOVEMENT"}
        for row in written["results"]:
            assert set(row["arms"]) == {"feedbackWithheld", "feedbackSupplied"}
            assert row["arms"]["feedbackWithheld"]["verdictsAboutWithheld"] == 0
            assert row["perSeed"]


class TestTrack1IsNotAffectedByTheConfound:
    """The novel-behaviour confound is a property of `run_new_behaviour`, which
    withholds a category from the fit set and then draws feedback from that same
    fit set. `run_condition` - the path every Track 1 number came from, noise
    sensitivity included - withholds nothing. These tests assert that difference
    rather than leaving it to be re-derived by reading."""

    def test_run_condition_offers_feedback_over_the_entire_fit_set(self) -> None:
        """No category is excluded, so the confound has no precondition here."""
        corpus = scenarios.prepare_corpus(seed=1337)
        seen: list[int] = []

        real = simulation.simulate_feedback

        def recording(ground_truth, **kwargs):
            seen.append(len(ground_truth))
            return real(ground_truth, **kwargs)

        original = scenarios.simulation.simulate_feedback
        scenarios.simulation.simulate_feedback = recording
        try:
            scenarios.run_condition(corpus, condition="both_arms", seed=1337)
        finally:
            scenarios.simulation.simulate_feedback = original

        assert seen == [len(corpus.fit_labels)]

    def test_no_sample_reaches_both_the_feedback_pool_and_the_scoring_set(self) -> None:
        """Feedback and threshold selection read the fit set; scoring reads the
        test set. If a *sample* crossed that line, every Track 1 number would be
        tuned on its own test data."""
        dataset = synthetic_dataset(seed=1337)
        plan = build_split(dataset, strategy=STRATIFIED_GROUP, seed=1337)
        fit_ids = {s.id for s in plan.train.samples} | {
            s.id for s in plan.validation.samples
        }
        test_ids = {s.id for s in plan.test.samples}
        assert fit_ids.isdisjoint(test_ids)

    def test_the_corpus_has_duplicate_feature_vectors_across_the_split(self) -> None:
        """Measured, and deliberately not called leakage. Distinct events can
        share a feature vector - 5.1% of test rows at seed 1337, 17 benign and 3
        malicious - because the feature space is coarser than the event space.
        The split is sample- and group-disjoint, so no sample is scored against
        itself; but the detector does meet vectors in test that it fitted on,
        and that is a property of the corpus worth pinning rather than
        discovering later."""
        corpus = scenarios.prepare_corpus(seed=1337)
        fit = set(corpus.fit_vectors)
        colliding = sum(1 for vector in corpus.test_vectors if vector in fit)
        assert 0 < colliding / len(corpus.test_vectors) < 0.10
