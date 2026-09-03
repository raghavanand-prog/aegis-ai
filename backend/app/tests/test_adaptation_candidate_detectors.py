"""V6 Track 3 / hypothesis 5: is the detector class the limit, or the features?

Track 3 measured that nine of thirteen withheld attack categories are
unreachable by any threshold under the production Isolation Forest. That is
either a fact about Isolation Forest or a fact about the feature space, and the
two call for completely different work. These tests cover the instrument that
separates them.

The safety property first: nothing here may reach production. A comparison
framework that could quietly swap the deployed detector would be a far worse
outcome than an unanswered research question.
"""

from __future__ import annotations

import json

import pytest

from app.adaptation.experiments import candidate_detectors as cd


class TestProductionIsolation:
    """The invariant that matters more than any result this module produces."""

    def test_only_the_incumbent_is_marked_production(self) -> None:
        production = [
            spec for spec in cd.REGISTRY.values() if spec.maturity == cd.MATURITY_PRODUCTION
        ]
        assert [spec.name for spec in production] == ["isolation_forest"]

    def test_every_candidate_declares_a_known_maturity(self) -> None:
        for spec in cd.REGISTRY.values():
            assert spec.maturity in cd.MATURITIES

    def test_a_detector_that_needs_labels_is_never_deployable(self) -> None:
        """The production detector is unsupervised. A supervised model here is a
        diagnostic ceiling on what the features can support - it is not a
        candidate for deployment, and V5 refused exactly that substitution."""
        for spec in cd.REGISTRY.values():
            if spec.requires_labels:
                assert not spec.deployable

    def test_the_module_never_touches_the_model_registry(self) -> None:
        """Isolation asserted against the parsed module, not against prose - a
        substring search matches this module's own docstring, which explains the
        invariant it must not violate. The only write into production detection
        state is registry.activate_model, and an experiment must not reach it."""
        import ast
        import inspect

        tree = ast.parse(inspect.getsource(cd))
        imported: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported.add(node.module)
        assert not {name for name in imported if "registry" in name or "models" in name.split(".")[-1:]}

        called = {
            node.func.attr
            for node in ast.walk(tree)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
        }
        assert "activate_model" not in called


class TestSeparability:
    def test_it_measures_separability_without_a_threshold(self) -> None:
        """ROC-AUC, not recall. Track 3 showed recall here is dominated by the
        threshold clamp, which would confound a detector comparison with an
        operating-point artefact."""
        result = cd.measure_separability(
            seed=1337, withheld_category="PORT_SCAN", detector="isolation_forest"
        )
        assert 0.0 <= result["novelAuc"] <= 1.0
        assert result["detector"] == "isolation_forest"
        assert result["maturity"] == cd.MATURITY_PRODUCTION

    def test_the_withheld_category_never_enters_any_fit_set(self) -> None:
        """True for the supervised ceiling too, or it would be answering an
        easier question than the one asked."""
        result = cd.measure_separability(
            seed=1337, withheld_category="PORT_SCAN", detector="supervised_ceiling"
        )
        assert result["withheldInFitSet"] == 0

    def test_it_is_reproducible_for_a_seed(self) -> None:
        first = cd.measure_separability(
            seed=99, withheld_category="RANSOMWARE", detector="isolation_forest"
        )
        second = cd.measure_separability(
            seed=99, withheld_category="RANSOMWARE", detector="isolation_forest"
        )
        assert first["novelAuc"] == second["novelAuc"]

    def test_it_refuses_an_unknown_detector(self) -> None:
        with pytest.raises(KeyError, match="unknown detector"):
            cd.measure_separability(
                seed=1337, withheld_category="PORT_SCAN", detector="nope"
            )

    def test_it_refuses_a_category_it_cannot_measure(self) -> None:
        with pytest.raises(ValueError, match="no held-out samples"):
            cd.measure_separability(
                seed=1337, withheld_category="NOT_A_CATEGORY", detector="isolation_forest"
            )

    @pytest.mark.parametrize("detector", ["local_outlier_factor", "one_class_svm"])
    def test_every_unsupervised_candidate_runs(self, detector: str) -> None:
        result = cd.measure_separability(
            seed=1337, withheld_category="PORT_SCAN", detector=detector
        )
        assert result["novelAuc"] is not None
        assert result["maturity"] == cd.MATURITY_CANDIDATE


class TestDetectorComparisonRunner:
    def test_it_reports_every_detector_per_category_with_provenance(
        self, tmp_path
    ) -> None:
        from app.adaptation.experiments import run_detector_comparison

        assert (
            run_detector_comparison.main(
                [
                    "--seeds",
                    "1",
                    "--categories",
                    "PORT_SCAN",
                    "RANSOMWARE",
                    "--output-dir",
                    str(tmp_path),
                    "--max-seconds",
                    "900",
                ]
            )
            == 0
        )
        report = json.loads(
            next(tmp_path.glob("v6-detector-comparison-*.json")).read_text()
        )
        assert report["dataset"]["fingerprint"]
        categories = {row["withheldCategory"] for row in report["results"]}
        assert categories == {"PORT_SCAN", "RANSOMWARE"}
        for row in report["results"]:
            assert set(row["detectors"]) == set(cd.REGISTRY)
            for name, entry in row["detectors"].items():
                assert entry["maturity"] == cd.REGISTRY[name].maturity
                assert entry["deployable"] == cd.REGISTRY[name].deployable

    def test_the_report_states_that_nothing_here_is_deployed(self, tmp_path) -> None:
        """A comparison report that did not say so could be read as a
        recommendation to swap the production detector."""
        from app.adaptation.experiments import run_detector_comparison

        run_detector_comparison.main(
            [
                "--seeds",
                "1",
                "--categories",
                "PORT_SCAN",
                "--output-dir",
                str(tmp_path),
                "--max-seconds",
                "900",
            ]
        )
        report = json.loads(
            next(tmp_path.glob("v6-detector-comparison-*.json")).read_text()
        )
        assert any("not deployed" in caveat.lower() for caveat in report["caveats"])
