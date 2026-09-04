"""Augmentation provenance reaches the approver (V8).

V6 recorded how analyst feedback entered a candidate's fit set - the admitted
count, the per-group and per-actor composition, the cap policy and the baseline
monitor's assessment - on the candidate **model's** ``parameters``. The V7
handoff closed by naming what that left undone:

    "The augmentation provenance is not in the dashboard. ``actorCounts``,
    ``groupCounts`` and ``baselineAssessment`` live on the *model's*
    ``parameters``, not the proposal's ``validation``, and surfacing them needs
    an API change the phase did not justify."

So an approver could see how a candidate **scored** and not what it was
**trained on** - which is precisely the half an adversary controls. A poisoned
candidate that scores well is the case the evidence panel exists to catch, and
until V8 the panel could not show the poisoning.

The tests below hold two properties:

* the provenance is exposed on the proposal, read through the candidate model
  rather than copied onto the proposal at creation time - a copy would go stale
  the moment anything about the candidate changed, and the auditable fact is
  what the model actually records;
* the **four** reasons it can be absent stay distinguishable. "No feedback was
  admitted" and "nobody recorded what was admitted" are opposite situations, and
  a single null for both is exactly the failure V4's "a dash is not a zero" rule
  exists to prevent.
"""

from __future__ import annotations

from app.adaptation.proposals import service as proposals
from app.api.v1.adaptation import _proposal_read
from app.models.enums import MLModelStatus, ProposalType
from app.models.ml import MLModel

ANALYST = "analyst@aegisx.dev"

AUGMENTATION = {
    "admitted": 42,
    "groupCounts": {"authentication": 30, "process": 12},
    "actorCounts": {"mallory@aegisx.dev": 33, "chidi@aegisx.dev": 9},
    "capPolicy": "baseline_relative",
    "actorCapPolicy": None,
    "skipped": {
        "notBenign": 4,
        "nonEvent": 0,
        "noInference": 2,
        "incompleteVector": 1,
        "byCap": 118,
    },
    "baselineAssessment": {"flagged": ["authentication"], "findings": {}},
    "baselineRatesDerived": True,
    "datasetFingerprint": "9f8e7d6c5b4a3021",
}


def _model(db, *, parameters: dict) -> MLModel:
    model = MLModel(
        name="isolation_forest",
        version="9.0",
        model_type="sklearn.ensemble.IsolationForest",
        feature_schema_version="1.0",
        dataset_version="1.0",
        dataset_fingerprint="f0fbefc8d38a8a53",
        training_samples=4800,
        parameters=parameters,
        metrics={},
        feature_names=["hour_sin"],
        artifact_path="/nowhere/isolation_forest-v9.0.joblib",
        artifact_sha256="0" * 64,
        status=MLModelStatus.ARCHIVED.value,
        created_by="test",
    )
    db.add(model)
    db.flush()
    return model


def _proposal(db, *, candidate_model_id: int | None):
    return proposals.create(
        db,
        proposal_type=ProposalType.MODEL_UPDATE,
        title="Promote the feedback-augmented candidate",
        reason="Recall improved on the categories the detector is weakest on.",
        affected_component="ml.anomaly_model",
        before_state={"model": "isolation_forest@1.0"},
        after_state={"model": "isolation_forest@9.0"},
        evidence={"feedbackIds": [1, 2]},
        proposed_by=ANALYST,
        proposed_by_role="analyst",
        candidate_model_id=candidate_model_id,
    )


class TestProvenanceReachesTheApprover:
    def test_the_augmentation_block_is_exposed_on_the_proposal(self, db) -> None:
        model = _model(db, parameters={"augmentation": AUGMENTATION, "seed": 4242})
        read = _proposal_read(_proposal(db, candidate_model_id=model.id))

        assert read.augmentation_status == "recorded"
        assert read.augmentation == AUGMENTATION

    def test_the_actor_composition_survives(self, db) -> None:
        """The per-actor axis is the one a compromised account concentrates in."""
        model = _model(db, parameters={"augmentation": AUGMENTATION})
        read = _proposal_read(_proposal(db, candidate_model_id=model.id))

        assert read.augmentation is not None
        assert read.augmentation["actorCounts"]["mallory@aegisx.dev"] == 33
        assert read.augmentation["baselineAssessment"]["flagged"] == ["authentication"]
        assert read.augmentation["skipped"]["byCap"] == 118

    def test_it_is_read_through_the_model_not_copied(self, db) -> None:
        """Changing the model changes what the approver sees.

        A value copied onto the proposal at creation time would keep showing the
        old composition after a retrain, which is the more dangerous direction:
        it would show an approver provenance that no longer describes the
        artifact they are about to deploy.
        """
        model = _model(db, parameters={"augmentation": AUGMENTATION})
        proposal = _proposal(db, candidate_model_id=model.id)
        assert _proposal_read(proposal).augmentation is not None

        model.parameters = {"augmentation": {**AUGMENTATION, "admitted": 7}}
        db.flush()
        db.refresh(proposal)

        assert _proposal_read(proposal).augmentation["admitted"] == 7


class TestTheFourAbsencesStayDistinguishable:
    def test_a_proposal_with_no_candidate_model(self, db) -> None:
        read = _proposal_read(_proposal(db, candidate_model_id=None))

        assert read.augmentation is None
        assert read.augmentation_status == "no_candidate_model"

    def test_a_candidate_trained_without_augmentation(self, db) -> None:
        """Fitted on telemetry alone - a fact, not a gap."""
        model = _model(db, parameters={"seed": 4242, "contamination": 0.08})
        read = _proposal_read(_proposal(db, candidate_model_id=model.id))

        assert read.augmentation is None
        assert read.augmentation_status == "not_recorded"

    def test_a_null_augmentation_block_is_not_recorded(self, db) -> None:
        """``parameters['augmentation'] = None`` is what candidate training
        writes when no feedback was admitted, and it must not read as a
        recorded-but-empty composition."""
        model = _model(db, parameters={"augmentation": None})
        read = _proposal_read(_proposal(db, candidate_model_id=model.id))

        assert read.augmentation is None
        assert read.augmentation_status == "not_recorded"

    def test_a_deleted_candidate_model_is_reported_as_unavailable(self, db) -> None:
        """``ON DELETE SET NULL`` keeps the proposal and loses the model.

        This must not be reported as "no candidate model": the proposal *does*
        propose a model change, and the evidence for it can no longer be read.
        That is the one absence an approver should refuse on.
        """
        model = _model(db, parameters={"augmentation": AUGMENTATION})
        proposal = _proposal(db, candidate_model_id=model.id)
        model_id = model.id

        # Simulate the FK's SET NULL not having fired - the row is gone while
        # the proposal still names it. On SQLite, where foreign keys are not
        # enforced by default, this is also the realistic post-delete state.
        db.delete(model)
        db.flush()
        proposal.candidate_model_id = model_id
        db.flush()
        db.expire(proposal, ["candidate_model"])

        read = _proposal_read(proposal)
        assert read.augmentation is None
        assert read.augmentation_status == "candidate_model_unavailable"
