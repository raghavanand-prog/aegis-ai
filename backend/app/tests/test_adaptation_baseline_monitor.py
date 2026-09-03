"""Detecting a patient baseline-poisoning campaign (V6 §12).

§11 lowered the cap tolerance to 1.5, which *bounds* the ratchet. It does not
*detect* one: every batch stays within policy by construction, so there is
nothing for a policy check to fire on.

The signal is not what gets admitted. Measured while building this: at the
default tolerance the adversary's admitted counts are **flatter than honest**
(growth ratio 1.03 against 1.34), because the cap clamps exactly the quantity a
naive monitor would watch. The cap erases its own evidence.

What the cap does not touch is what an analyst *submits*. A group whose
submissions persistently dwarf its own historical rate is the signature, and it
separates cleanly: over 12 seeds, honest campaigns reach a mean suppression
ratio of at most 1.85 and adversarial ones at least 9.34.

This is advisory. V5 decision 25 — drift is a signal, not a verdict — applies
here too: the cap does the blocking, the monitor makes an invisible campaign
visible to a person.
"""

from __future__ import annotations

import pytest

from app.adaptation.drift.metrics import DriftStatus
from app.adaptation.feedback import baseline_monitor
from app.adaptation.feedback import service as feedback_service
from app.adaptation.feedback.labels import FeedbackLabel, FeedbackTargetType
from app.models.event import Event
from app.models.ml import MLInference

_INDEX = [7000]


def _event(db, *, event_type: str) -> Event:
    _INDEX[0] += 1
    event = Event(
        event_id=f"EVT-BM-{_INDEX[0]:05d}",
        source="test",
        source_type="endpoint",
        event_type=event_type,
        title=event_type,
    )
    db.add(event)
    db.flush()
    return event


def _benign_feedback(db, event: Event) -> None:
    db.add(
        MLInference(
            event_id=event.id,
            model_name="isolation_forest",
            model_version="1.0",
            feature_schema_version="1.0",
            anomaly_score=0.5,
            is_anomaly=False,
            threshold=0.65,
            features={},
            top_contributors=[],
            latency_ms=1.0,
        )
    )
    feedback_service.submit(
        db,
        target_type=FeedbackTargetType.EVENT,
        target_id=event.id,
        label=FeedbackLabel.BENIGN,
        analyst="a@aegisx.dev",
        source="simulation",
    )


def _cycle(db, name: str, *, counts: dict[str, int]):
    from app.adaptation.feedback import datasets

    for event_type, count in counts.items():
        for _ in range(count):
            _benign_feedback(db, _event(db, event_type=event_type))
    return datasets.build(db, name=name, version="1.0", created_by="test")


class TestStableHistory:
    def test_a_steady_group_is_stable(self, db) -> None:
        for cycle in range(3):
            _cycle(db, f"steady-{cycle}", counts={"auth_success": 5})
        latest = _cycle(db, "steady-latest", counts={"auth_success": 5})

        report = baseline_monitor.assess(db, dataset_id=latest.id)
        finding = report.findings["auth_success"]
        assert finding.status is DriftStatus.STABLE
        assert not report.flagged


class TestCampaignIsVisible:
    def test_a_group_submitting_far_above_its_baseline_is_flagged(self, db) -> None:
        for cycle in range(3):
            _cycle(db, f"camp-{cycle}", counts={"auth_success": 5, "malware_detected": 1})
        # The campaign: submissions dwarf the group's own history.
        latest = _cycle(
            db, "camp-latest", counts={"auth_success": 5, "malware_detected": 20}
        )

        report = baseline_monitor.assess(db, dataset_id=latest.id)
        assert report.findings["malware_detected"].status is DriftStatus.SIGNIFICANT
        assert "malware_detected" in report.flagged
        # The honest group in the same batch must not be swept up with it.
        assert report.findings["auth_success"].status is DriftStatus.STABLE

    def test_the_finding_carries_what_an_analyst_needs_to_argue_with_it(
        self, db
    ) -> None:
        for cycle in range(3):
            _cycle(db, f"arg-{cycle}", counts={"malware_detected": 1})
        latest = _cycle(db, "arg-latest", counts={"malware_detected": 20})

        finding = baseline_monitor.assess(db, dataset_id=latest.id).findings[
            "malware_detected"
        ]
        # A feedback dataset is a snapshot of *all* current feedback, not an
        # incremental batch, so counts are cumulative: prior snapshots hold
        # 1, 2 and 3 of this group and the latest holds those plus the campaign.
        assert finding.submitted == 23
        assert finding.baseline_rate == pytest.approx(2.0, abs=0.5)
        assert finding.suppression_ratio > 6.0
        assert finding.datasets_in_baseline == 3


class TestBaselineHygiene:
    def test_the_assessed_dataset_is_excluded_from_its_own_baseline(self, db) -> None:
        """A baseline containing the batch under review would sanction it."""
        for cycle in range(3):
            _cycle(db, f"excl-{cycle}", counts={"malware_detected": 1})
        latest = _cycle(db, "excl-latest", counts={"malware_detected": 20})

        finding = baseline_monitor.assess(db, dataset_id=latest.id).findings[
            "malware_detected"
        ]
        assert finding.datasets_in_baseline == 3
        # Prior snapshots hold 1, 2 and 3; the mean is 2.0. Had the batch under
        # review been included the mean would be 6.5, and the ratio it sanctions
        # would be a third of the true one.
        assert finding.baseline_rate == pytest.approx(2.0, abs=0.01)

    def test_a_group_with_no_history_is_reported_not_flagged(self, db) -> None:
        """A genuinely new event type is not evidence of an attack. It is
        reported as unbaselined so a person can look, and is not counted as a
        campaign."""
        for cycle in range(3):
            _cycle(db, f"new-{cycle}", counts={"auth_success": 5})
        latest = _cycle(db, "new-latest", counts={"auth_success": 5, "brand_new": 9})

        report = baseline_monitor.assess(db, dataset_id=latest.id)
        finding = report.findings["brand_new"]
        assert finding.datasets_in_baseline == 0
        assert finding.status is DriftStatus.STABLE
        assert finding.unbaselined
        assert "brand_new" not in report.flagged

    def test_too_little_history_is_refused_rather_than_guessed(self, db) -> None:
        latest = _cycle(db, "thin", counts={"auth_success": 5})
        with pytest.raises(ValueError, match="history"):
            baseline_monitor.assess(db, dataset_id=latest.id)


class TestItIsAdvisory:
    def test_the_report_states_that_it_blocks_nothing(self, db) -> None:
        """V5 decision 25: a signal, not a verdict. The cap does the blocking."""
        for cycle in range(3):
            _cycle(db, f"adv-{cycle}", counts={"malware_detected": 1})
        latest = _cycle(db, "adv-latest", counts={"malware_detected": 20})

        payload = baseline_monitor.assess(db, dataset_id=latest.id).as_dict()
        assert "advisory" in payload["interpretation"].lower()
        assert payload["flagged"] == ["malware_detected"]


class TestSurfacedToTheApprover:
    """A signal nobody sees is not a control. §11.5.4's complaint was that the
    campaign is invisible; putting the assessment on the candidate is what fixes
    that, because the approver reads the candidate."""

    def test_training_records_the_baseline_assessment(self, db, tmp_path_factory) -> None:
        from app.adaptation.candidates import training

        for cycle in range(3):
            _cycle(db, f"surf-{cycle}", counts={"auth_success": 5, "malware_detected": 1})
        latest = _cycle(
            db, "surf-latest", counts={"auth_success": 5, "malware_detected": 20}
        )

        model = training.train_candidate(
            db,
            samples=600,
            seed=1337,
            directory=tmp_path_factory.mktemp("surf"),
            created_by="test",
            feedback_dataset_id=latest.id,
        )
        assessment = model.parameters["augmentation"]["baselineAssessment"]
        assert assessment["flagged"] == ["malware_detected"]
        assert assessment["findings"]["malware_detected"]["status"] == "significant"

    def test_a_clean_batch_records_an_empty_flag_list_not_a_missing_field(
        self, db, tmp_path_factory
    ) -> None:
        """"No campaign detected" is a fact about the candidate. A missing field
        would read as "not checked"."""
        from app.adaptation.candidates import training

        for cycle in range(3):
            _cycle(db, f"clean-{cycle}", counts={"auth_success": 5})
        latest = _cycle(db, "clean-latest", counts={"auth_success": 5})

        model = training.train_candidate(
            db,
            samples=600,
            seed=1337,
            directory=tmp_path_factory.mktemp("clean"),
            created_by="test",
            feedback_dataset_id=latest.id,
        )
        assert model.parameters["augmentation"]["baselineAssessment"]["flagged"] == []

    def test_thin_history_records_why_it_could_not_assess(
        self, db, tmp_path_factory
    ) -> None:
        """The monitor refuses on thin history. Training must not fail with it -
        the reason is recorded and the candidate proceeds."""
        from app.adaptation.candidates import training

        first = _cycle(db, "thin-1", counts={"auth_success": 5})
        second = _cycle(db, "thin-2", counts={"auth_success": 6})

        model = training.train_candidate(
            db,
            samples=600,
            seed=1337,
            directory=tmp_path_factory.mktemp("thin"),
            created_by="test",
            feedback_dataset_id=second.id,
            cap_policy="global",
        )
        assessment = model.parameters["augmentation"]["baselineAssessment"]
        assert assessment["unavailableReason"]
        assert first.id != second.id
