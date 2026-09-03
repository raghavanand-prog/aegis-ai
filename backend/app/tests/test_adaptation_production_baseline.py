"""Re-establish the detection baseline in the configuration production uses.

V4 and V5 measured their static baseline by re-fitting an Isolation Forest on
the *labelled evaluation corpus*, whose fit split is 40% malicious. Production
does not do that: `train_anomaly_model` fits the runtime telemetry generator's
corpus and the labelled corpus is used only for scoring.

V5 saw the gap and did not act on it. Its own experimental design records the
deployed artifact at F1 0.663 on this corpus while its experiments reported a
static baseline of F1 0.038 from the refit - a difference it noted only as a
reason to withdraw prediction P1.

These tests cover the instrument that measures the production configuration.
"""

from __future__ import annotations

from app.adaptation.experiments import production_baseline as pb


class TestProductionFit:
    def test_it_fits_on_the_telemetry_corpus_not_the_labelled_one(self) -> None:
        """The whole point. If this ever starts fitting the labelled corpus it
        has become the thing it exists to correct."""
        result = pb.measure(seed=1337)
        assert result["fitCorpus"] == "runtime-telemetry-generator"
        assert result["fitSamples"] > 0
        # The labelled corpus contributes scoring data only.
        assert result["scoredOn"] == "aegisx-detection-eval test split"

    def test_no_scored_sample_was_fitted_on(self) -> None:
        """The two corpora are generated independently, so this is structural -
        but it is the property the whole comparison rests on."""
        result = pb.measure(seed=1337)
        assert result["fitScoringOverlap"] == 0

    def test_it_reports_threshold_free_and_frozen_threshold_metrics(self) -> None:
        result = pb.measure(seed=1337)
        assert result["rocAuc"] is not None
        assert result["frozenThreshold"]["f1"] is not None

    def test_it_is_deterministic_for_a_seed(self) -> None:
        assert pb.measure(seed=99)["rocAuc"] == pb.measure(seed=99)["rocAuc"]

    def test_threshold_adaptation_is_applicable_but_curation_is_not(self) -> None:
        """Arm 1 chooses an operating point from labelled observed events, which
        works whatever the model was fitted on. Arm 2 purifies the fit set - and
        production's fit set is unlabelled telemetry, not observed events, so
        there is nothing for analyst labels to purify. Recorded rather than
        silently skipped."""
        result = pb.measure(seed=1337)
        assert result["arms"]["thresholdAdaptation"]["applicable"] is True
        assert result["arms"]["curation"]["applicable"] is False
        assert result["arms"]["curation"]["reason"]


class TestProductionBaselineRunner:
    def test_it_records_the_fit_and_scoring_corpora_separately(self, tmp_path) -> None:
        import json

        from app.adaptation.experiments import run_production_baseline_eval

        assert (
            run_production_baseline_eval.main(
                ["--seeds", "2", "--output-dir", str(tmp_path), "--max-seconds", "900"]
            )
            == 0
        )
        report = json.loads(
            next(tmp_path.glob("v6-production-baseline-*.json")).read_text()
        )
        assert report["fit"]["corpus"] == pb.FIT_CORPUS
        assert report["scoring"]["corpus"] == pb.SCORED_ON
        assert report["scoring"]["fitScoringOverlap"] == 0
        assert report["arms"]["curation"]["applicable"] is False
