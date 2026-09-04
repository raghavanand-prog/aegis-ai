"""Why §5's gap exists: a fixed threshold is not portable between models.

V6 §5 measured a model fitted on telemetry reaching F1 0.6526 on the eval test
split while one refitted on the eval corpus reached 0.0389 — a 17x gap. §13.2
established that contamination cannot explain it, because both corpora are ~40%
malicious, and left it open.

The answer is in how the score is defined. `anomaly_score` is a logistic squash
of the raw score about `_raw_offset`, which is the **median of the training
scores**. Score 0.5 therefore means "typical of *this model's own* training
data". The scale is relative to the fit set, so a fixed 0.65 means something
different for every model, and comparing two differently-fitted models at one
frozen threshold compares their calibrations as much as their detection.
"""

from __future__ import annotations

import pytest

from app.adaptation.experiments import threshold_portability as tp


class TestDecomposition:
    def test_it_separates_threshold_placement_from_discrimination(self) -> None:
        """The whole point: report the gap at a fixed threshold *and* at each
        model's own best one, so the two causes are not conflated."""
        result = tp.compare(seed=1337)
        for arm in ("telemetryFit", "evalCorpusFit"):
            assert result[arm]["f1AtFrozen"] is not None
            assert result[arm]["bestF1"] is not None
            assert result[arm]["rocAuc"] is not None

    def test_the_frozen_threshold_sits_at_a_different_percentile_per_model(
        self,
    ) -> None:
        """The mechanism, measured rather than argued."""
        result = tp.compare(seed=1337)
        telemetry = result["telemetryFit"]["frozenPercentile"]
        evaluation = result["evalCorpusFit"]["frozenPercentile"]
        assert evaluation > 95.0, "0.65 should be far out in the eval-fit tail"
        assert telemetry < 80.0, "0.65 should be mid-distribution for telemetry-fit"

    def test_the_gap_shrinks_dramatically_at_each_models_own_threshold(self) -> None:
        result = tp.compare(seed=1337)
        assert result["frozenRatio"] > 5.0
        assert result["bestRatio"] < 2.0
        assert result["frozenRatio"] > result["bestRatio"]

    def test_it_reports_how_much_of_the_gap_is_placement(self) -> None:
        result = tp.compare(seed=1337)
        assert 0.5 < result["shareFromThresholdPlacement"] <= 1.0


class TestScoreScaleIsRelative:
    def test_the_training_median_maps_to_roughly_one_half(self) -> None:
        """The property that makes a fixed threshold unportable. If this ever
        stopped holding, the explanation above would need revisiting."""
        assert tp.training_median_score(seed=1337) == pytest.approx(0.5, abs=0.05)


class TestContaminationSurvivesTheCorrection:
    def test_the_section_4_effect_is_not_merely_threshold_placement(self) -> None:
        """§4 claimed contamination degrades the detector. If that were only a
        calibration artefact, the threshold-free measures would be flat. They are
        not, so §4 stands — but its F1 column understates the effect."""
        sweep = tp.contamination_sweep(seed=1337, levels=(0.40, 0.08))
        dirty, clean = sweep[0.40], sweep[0.08]
        assert clean["rocAuc"] > dirty["rocAuc"] + 0.2
        assert clean["bestF1"] > dirty["bestF1"] + 0.1
        # And the F1@frozen column understates it, because 0.65 is badly placed
        # at every level.
        assert clean["frozenPercentile"] > 80.0
