"""Model registry.

Small on purpose. The requirement is reproducibility, not an MLOps platform:
given a registry row you must be able to say what was trained, from what, with
which settings, which feature schema it speaks, and where the artifact is.

Two rules the registry enforces:

* **Versions are never overwritten.** Registering a version that already exists
  is refused. Silently replacing an artifact would make every inference row
  that names that version unverifiable.
* **At most one active version per model name.** Activating archives whatever
  was active, which is what makes a rollback a one-line operation rather than
  an archaeology project.
"""

from __future__ import annotations

import logging
import re
from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.models.enums import MLModelStatus
from app.models.ml import MLModel

logger = logging.getLogger(__name__)


def _iso(value) -> str | None:  # noqa: ANN001 - datetime | None
    """UTC-stamped ISO string, or None. See app.schemas.common.as_utc."""
    from app.schemas.common import as_utc

    stamped = as_utc(value)
    return stamped.isoformat() if stamped else None


class RegistryError(RuntimeError):
    """Raised for invalid registry operations (duplicate version, unknown id)."""


def artifact_dir() -> Path:
    return settings.ml_artifact_dir


#: Model names and versions are single path components. Anything outside this
#: alphabet is refused rather than stripped: silently rewriting ``../../etc`` to
#: ``etc`` produces a path that is safe but is not the one the caller asked for,
#: and a registry that quietly renames artifacts is worse than one that errors.
_SAFE_NAME = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
_SAFE_VERSION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,31}$")


def artifact_path(name: str, version: str, *, directory: Path | None = None) -> Path:
    """Artifact location for one model version.

    ``name`` and ``version`` come from application code, never from a request
    body. They are still validated, because a registry that accepts ``../`` in a
    version string is a path traversal waiting for the first caller who does
    pass user input.
    """
    if not _SAFE_NAME.match(name or ""):
        raise RegistryError(
            f"Model name {name!r} is not a single safe path component "
            "(letters, digits, hyphen, underscore)."
        )
    if not _SAFE_VERSION.match(version or "") or ".." in version:
        raise RegistryError(
            f"Model version {version!r} is not a single safe path component."
        )

    root = (directory or artifact_dir()).resolve()
    path = (root / f"{name}-v{version}.joblib").resolve()
    # Belt and braces: the resolved path must still be inside the artifact
    # directory, whatever the patterns above let through.
    if not str(path).startswith(str(root)):
        raise RegistryError(f"Refusing an artifact path outside {root}")
    return path


def get(db: Session, model_id: int) -> MLModel | None:
    return db.get(MLModel, model_id)


def get_by_version(db: Session, name: str, version: str) -> MLModel | None:
    return db.scalar(select(MLModel).where(MLModel.name == name, MLModel.version == version))


def get_active(db: Session, name: str) -> MLModel | None:
    """The version currently serving inference for ``name``, if any."""
    return db.scalar(
        select(MLModel)
        .where(MLModel.name == name, MLModel.status == MLModelStatus.ACTIVE.value)
        .order_by(MLModel.activated_at.desc())
    )


def get_previous(db: Session, name: str) -> MLModel | None:
    """The most recently archived version - the rollback target."""
    return db.scalar(
        select(MLModel)
        .where(MLModel.name == name, MLModel.status == MLModelStatus.ARCHIVED.value)
        .order_by(MLModel.trained_at.desc())
    )


def list_models(db: Session, *, name: str | None = None, limit: int = 100) -> list[MLModel]:
    stmt = select(MLModel).order_by(MLModel.trained_at.desc()).limit(limit)
    if name:
        stmt = stmt.where(MLModel.name == name)
    return list(db.scalars(stmt))


def _highest_version_on_disk(name: str, directory: Path | None = None) -> int:
    """Largest major version with an artifact present.

    The database is not the only record that a version existed. An artifact on
    disk is evidence too, and it is the evidence that survives a database being
    rebuilt from migrations - which is exactly when re-issuing a version would
    overwrite a deployed model.
    """
    root = directory or artifact_dir()
    try:
        entries = list(root.glob(f"{name}-v*.joblib"))
    except OSError:  # pragma: no cover - unreadable directory
        return 0

    highest = 0
    for entry in entries:
        stem = entry.name[len(f"{name}-v") : -len(".joblib")]
        try:
            highest = max(highest, int(stem.split(".")[0]))
        except (ValueError, IndexError):
            continue
    return highest


def next_version(db: Session, name: str, *, directory: Path | None = None) -> str:
    """Next ``major.minor`` for a model name. Existing versions are untouched.

    Takes the maximum of what the database records and what exists on disk.
    Consulting the database alone was a measured defect: with an empty
    ``ml_models`` table and a v1.0 artifact still present, this returned "1.0"
    and the subsequent write destroyed a digest-verified production model.
    """
    existing = list(db.scalars(select(MLModel.version).where(MLModel.name == name)))
    highest = 0
    for value in existing:
        try:
            highest = max(highest, int(str(value).split(".")[0]))
        except (ValueError, IndexError):  # noqa: PERF203 - a hand-written version is fine
            continue

    highest = max(highest, _highest_version_on_disk(name, directory))
    return f"{highest + 1}.0"


def reserve_artifact_path(
    name: str, version: str, *, directory: Path | None = None
) -> Path:
    """Validated artifact path for a version that must not already exist.

    Every writer goes through here rather than through ``artifact_path``. The
    registry has always refused to register a name@version twice, but that guard
    protects the database row, not the file: a rebuilt database made the row
    disappear while the artifact stayed exactly where it was, and the next
    training run silently overwrote a deployed model.

    Refusing is the whole behaviour. An artifact is immutable, so a caller that
    wants a different model wants a different version.
    """
    path = artifact_path(name, version, directory=directory)
    if path.exists():
        raise RegistryError(
            f"{path.name} already exists on disk. Model artifacts are immutable: "
            "overwriting one would invalidate the digest recorded against every "
            "inference that version produced, and would destroy the deployed "
            "model if this is the serving version. Train a new version instead."
        )
    return path


def artifact_digest(path: Path) -> str:
    """SHA-256 of an artifact on disk."""
    # Imported here rather than at module scope: the detector module pulls in
    # scikit-learn, and the registry is imported on the API path where that
    # cost is not wanted.
    from app.ml.models.isolation_forest import sha256_file

    return sha256_file(path)


def verify_artifact(path: Path, *, expected_sha256: str | None) -> bool:
    """Whether the artifact on disk still matches the digest recorded for it.

    A mismatch means the file changed after registration. That is a tampered or
    clobbered model, and a tampered model is a detection engine that lies - so
    callers treat a False here as fatal rather than as a warning.
    """
    if expected_sha256 is None:
        return False
    try:
        if not path.exists():
            return False
        return artifact_digest(path) == expected_sha256
    except OSError:  # pragma: no cover - unreadable artifact
        return False


def register(
    db: Session,
    *,
    name: str,
    version: str,
    model_type: str,
    feature_schema_version: str,
    dataset_version: str,
    dataset_fingerprint: str | None,
    training_samples: int,
    parameters: dict,
    metrics: dict,
    feature_names: list[str],
    artifact_path_str: str,
    artifact_sha256: str,
    created_by: str = "system",
    notes: str | None = None,
    activate: bool = False,
) -> MLModel:
    """Record a trained artifact. Refuses to overwrite an existing version."""
    if get_by_version(db, name, version) is not None:
        raise RegistryError(
            f"{name}@{version} is already registered. Model versions are immutable - "
            "train a new version rather than overwriting one that inference rows "
            "already point at."
        )

    model = MLModel(
        name=name,
        version=version,
        model_type=model_type,
        feature_schema_version=feature_schema_version,
        dataset_version=dataset_version,
        dataset_fingerprint=dataset_fingerprint,
        training_samples=training_samples,
        parameters=parameters,
        metrics=metrics,
        feature_names=feature_names,
        artifact_path=artifact_path_str,
        artifact_sha256=artifact_sha256,
        status=MLModelStatus.ARCHIVED.value,
        created_by=created_by,
        notes=notes,
        trained_at=datetime.now(timezone.utc),
    )
    db.add(model)
    db.flush()

    if activate:
        activate_model(db, model)
    return model


def activate_model(db: Session, model: MLModel) -> MLModel:
    """Make ``model`` the serving version, archiving the incumbent."""
    if model.status == MLModelStatus.FAILED.value:
        raise RegistryError(
            f"{model.identity} is marked failed and cannot be activated."
        )

    current = get_active(db, model.name)
    if current is not None and current.id != model.id:
        current.status = MLModelStatus.ARCHIVED.value

    model.status = MLModelStatus.ACTIVE.value
    model.activated_at = datetime.now(timezone.utc)
    db.flush()
    logger.info(
        "ML model activated",
        extra={"model": model.identity, "operation": "ml.activate"},
    )
    return model


def deactivate_model(db: Session, model: MLModel) -> MLModel:
    """Stop serving a model. Inference degrades to rules-only if none remain."""
    model.status = MLModelStatus.ARCHIVED.value
    db.flush()
    logger.info(
        "ML model deactivated",
        extra={"model": model.identity, "operation": "ml.deactivate"},
    )
    return model


def to_dict(model: MLModel) -> dict:
    """Serializable view. No filesystem path is exposed to API callers."""
    return {
        "id": model.id,
        "name": model.name,
        "version": model.version,
        "identity": model.identity,
        "modelType": model.model_type,
        "featureSchemaVersion": model.feature_schema_version,
        "datasetVersion": model.dataset_version,
        "datasetFingerprint": model.dataset_fingerprint,
        "trainingSamples": model.training_samples,
        "parameters": model.parameters or {},
        "metrics": model.metrics or {},
        "featureNames": model.feature_names or [],
        "featureCount": len(model.feature_names or []),
        "artifactName": Path(model.artifact_path).name,
        "artifactSha256": model.artifact_sha256,
        "status": model.status,
        "notes": model.notes,
        "createdBy": model.created_by,
        "trainedAt": _iso(model.trained_at),
        "activatedAt": _iso(model.activated_at),
    }
