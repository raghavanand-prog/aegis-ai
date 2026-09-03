"""Model artifacts are immutable on disk, not merely in the database.

The registry has always documented model versions as immutable, and enforced it
by refusing to register a name@version that already has a row. That guard is
necessary and not sufficient: it protects the *record*, not the *file*.

Measured during the V5 Phase A audit: with a rebuilt database, next_version()
re-issued v1.0 and training overwrote the digest-verified production artifact
(053d1ff3 -> 016c6dbf). The deployed model was destroyed by a routine training
run, and nothing refused.

V5 adds candidate training, which trains repeatedly by design against a registry
holding a live production model. These tests close the gap first.
"""

from __future__ import annotations

import pytest

from app.ml.registry import registry
from app.ml.registry.registry import RegistryError


class TestArtifactPathsAreNotOverwritten:
    def test_reserving_an_existing_artifact_path_is_refused(self, tmp_path) -> None:
        """The core defect. An artifact on disk is evidence a version exists,
        whatever the database currently remembers."""
        artifact = tmp_path / "isolation_forest-v1.0.joblib"
        artifact.write_bytes(b"the deployed model")

        with pytest.raises(RegistryError, match="already exists on disk"):
            registry.reserve_artifact_path("isolation_forest", "1.0", directory=tmp_path)

    def test_the_existing_artifact_is_left_untouched(self, tmp_path) -> None:
        artifact = tmp_path / "isolation_forest-v1.0.joblib"
        artifact.write_bytes(b"the deployed model")
        before = artifact.read_bytes()

        with pytest.raises(RegistryError):
            registry.reserve_artifact_path("isolation_forest", "1.0", directory=tmp_path)

        assert artifact.read_bytes() == before

    def test_an_unused_path_is_returned(self, tmp_path) -> None:
        path = registry.reserve_artifact_path("isolation_forest", "2.0", directory=tmp_path)
        assert path.name == "isolation_forest-v2.0.joblib"


class TestVersionAllocationSurvivesARebuiltDatabase:
    def test_next_version_accounts_for_artifacts_on_disk(self, db, tmp_path) -> None:
        """The exact Phase A scenario: an empty ml_models table and a v1.0
        artifact still on disk must not yield 1.0 again."""
        (tmp_path / "isolation_forest-v1.0.joblib").write_bytes(b"deployed")
        (tmp_path / "isolation_forest-v2.0.joblib").write_bytes(b"also deployed")

        version = registry.next_version(db, "isolation_forest", directory=tmp_path)

        assert version not in {"1.0", "2.0"}
        assert version == "3.0"

    def test_the_database_still_wins_when_it_is_ahead(self, db, tmp_path) -> None:
        """Disk is a floor, not the answer. A registered version with no
        artifact must still not be reissued."""
        (tmp_path / "isolation_forest-v1.0.joblib").write_bytes(b"deployed")
        existing = registry.next_version(db, "isolation_forest", directory=tmp_path)
        assert existing == "2.0"


class TestDigestVerification:
    def test_a_tampered_artifact_is_detected(self, tmp_path) -> None:
        """An artifact whose hash no longer matches the registry has been
        altered, and a tampered model is a detection engine that lies."""
        artifact = tmp_path / "model.joblib"
        artifact.write_bytes(b"original")
        digest = registry.artifact_digest(artifact)

        artifact.write_bytes(b"tampered")

        assert registry.verify_artifact(artifact, expected_sha256=digest) is False

    def test_an_untouched_artifact_verifies(self, tmp_path) -> None:
        artifact = tmp_path / "model.joblib"
        artifact.write_bytes(b"original")
        digest = registry.artifact_digest(artifact)
        assert registry.verify_artifact(artifact, expected_sha256=digest) is True

    def test_a_missing_artifact_does_not_verify(self, tmp_path) -> None:
        assert registry.verify_artifact(tmp_path / "absent.joblib", expected_sha256="a" * 64) is False


class TestPathValidationIsPreserved:
    def test_traversal_in_a_version_is_still_refused(self, tmp_path) -> None:
        """The V3 control must survive the change."""
        with pytest.raises(RegistryError):
            registry.reserve_artifact_path("isolation_forest", "../../etc", directory=tmp_path)
