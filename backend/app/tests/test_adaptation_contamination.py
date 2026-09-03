"""V6: does fit-set contamination explain the V4/V5 detection baseline?

The hypothesis-5 comparison measured that the evaluation corpus's fit set is 40%
malicious. The production anomaly model is trained on a different corpus - the
runtime telemetry generator, whose suspicious scenarios are about 12% - and the
labelled corpus's own provenance notes call it "out of distribution for the
anomaly model".

So V4 and V5 fitted an unsupervised detector on data far more contaminated than
anything it meets in production, and then reported its near-inert behaviour as
the static baseline every adaptation gain is measured against. These tests cover
the instrument that varies contamination and nothing else.
"""

from __future__ import annotations

import pytest

from app.adaptation.experiments import contamination as contam


class TestFitSetConstruction:
    def test_the_fit_set_size_is_identical_at_every_level(self) -> None:
        """Otherwise the comparison confounds contamination with sample count,
        and Isolation Forest is sensitive to both."""
        sizes = {
            contam.build_fit_set(seed=1337, malicious_fraction=level, size=900)[
                "size"
            ]
            for level in (0.0, 0.08, 0.20, 0.40)
        }
        assert sizes == {900}

    def test_it_achieves_the_requested_contamination(self) -> None:
        for level in (0.0, 0.08, 0.12, 0.40):
            built = contam.build_fit_set(seed=1337, malicious_fraction=level, size=900)
            assert built["maliciousFraction"] == pytest.approx(level, abs=0.005)

    def test_the_test_set_is_untouched_by_the_level(self) -> None:
        """One variable. The scoring set must not move when the fit set does."""
        low = contam.build_fit_set(seed=1337, malicious_fraction=0.0, size=900)
        high = contam.build_fit_set(seed=1337, malicious_fraction=0.40, size=900)
        assert low["testVectors"] == high["testVectors"]
        assert low["testLabels"] == high["testLabels"]

    def test_it_is_deterministic_for_a_seed(self) -> None:
        first = contam.build_fit_set(seed=99, malicious_fraction=0.20, size=900)
        second = contam.build_fit_set(seed=99, malicious_fraction=0.20, size=900)
        assert first["fitVectors"] == second["fitVectors"]

    def test_it_refuses_a_level_the_corpus_cannot_supply(self) -> None:
        with pytest.raises(ValueError, match="cannot supply"):
            contam.build_fit_set(seed=1337, malicious_fraction=0.95, size=1500)


class TestContaminationSweep:
    def test_it_reports_threshold_free_and_operating_point_metrics(self) -> None:
        """AUC because it is threshold-free, and F1 at the frozen 0.65 because
        that is the number V5 reported as the static baseline."""
        result = contam.measure(seed=1337, malicious_fraction=0.08, size=900)
        assert result["rocAuc"] is not None
        assert result["metrics"]["f1"] is not None
        assert result["maliciousFraction"] == pytest.approx(0.08, abs=0.005)


class TestContaminationRunner:
    def test_it_reports_every_level_and_the_curation_residual(self, tmp_path) -> None:
        import json

        from app.adaptation.experiments import run_contamination_eval

        assert (
            run_contamination_eval.main(
                [
                    "--seeds",
                    "2",
                    "--output-dir",
                    str(tmp_path),
                    "--max-seconds",
                    "900",
                ]
            )
            == 0
        )
        report = json.loads(next(tmp_path.glob("v6-contamination-*.json")).read_text())
        assert [row["requestedMaliciousFraction"] for row in report["results"]] == list(
            contam.LEVELS
        )
        # The quantity that links this sweep to Track 1's noise sensitivity.
        residual = {row["noiseRate"]: row for row in report["curationResidual"]}
        assert residual[0.0]["maliciousFractionAfter"] < residual[0.15][
            "maliciousFractionAfter"
        ], "more label noise must leave more contamination behind"
