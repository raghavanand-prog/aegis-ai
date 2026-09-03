"""Wiring the redesigned Arm 2 into the production training path.

V6 §5.5 established that V5's Arm 2 could not run in production: it purified a
fit set that production does not have. §6 redesigned it to *add* analyst-verified
benign observed events to the telemetry corpus, and §8/§9 established that the
addition needs a per-group cap or a single analyst can poison one attack category
while every aggregate metric improves.

This module is where that reaches the real pipeline, so these tests are mostly
about what does *not* get into training data.

The feature vector for an admitted event comes from its stored ``MLInference``
row - the vector the model actually scored - rather than being re-derived from
the event's columns. Re-deriving would risk training on a vector that was never
the one the analyst's verdict referred to.
"""

from __future__ import annotations

import pytest

from app.adaptation.feedback import augmentation, caps
from app.adaptation.feedback import service as feedback_service
from app.adaptation.feedback.labels import FeedbackLabel, FeedbackTargetType
from app.ml.features.extractor import FEATURE_NAMES
from app.models.event import Event
from app.models.ml import MLInference

SCHEMA = "1.0"


def _event(db, *, event_type: str, index: int) -> Event:
    event = Event(
        event_id=f"EVT-TEST-{index:05d}",
        source="simulation",
        source_type="endpoint",
        event_type=event_type,
        title=f"{event_type} {index}",
    )
    db.add(event)
    db.flush()
    return event


def _inference(db, event: Event, *, offset: float = 0.0, shuffled: bool = False) -> MLInference:
    names = list(FEATURE_NAMES)
    if shuffled:
        names = list(reversed(names))
    features = {name: float(i) + offset for i, name in enumerate(names)}
    row = MLInference(
        event_id=event.id,
        model_name="isolation_forest",
        model_version="1.0",
        feature_schema_version=SCHEMA,
        anomaly_score=0.5,
        is_anomaly=False,
        threshold=0.65,
        features=features,
        top_contributors=[],
        latency_ms=1.0,
    )
    db.add(row)
    db.flush()
    return row


def _feedback(db, event: Event, label: FeedbackLabel, analyst: str = "a@aegisx.dev"):
    return feedback_service.submit(
        db,
        target_type=FeedbackTargetType.EVENT,
        target_id=event.id,
        label=label,
        analyst=analyst,
        source="simulation",
    )


def _dataset(db, name: str):
    from app.adaptation.feedback import datasets

    return datasets.build(
        db, name=name, version="1.0", created_by="test", feature_schema_version=SCHEMA
    )


class TestAdmission:
    def test_only_verified_benign_events_reach_training_data(self, db) -> None:
        """A confirmed-malicious event added to an anomaly model's fit set
        teaches it that the attack is normal. It must never be admitted."""
        benign = _event(db, event_type="auth_success", index=1)
        malicious = _event(db, event_type="malware_detected", index=2)
        _inference(db, benign)
        _inference(db, malicious)
        _feedback(db, benign, FeedbackLabel.BENIGN)
        _feedback(db, malicious, FeedbackLabel.CONFIRMED_MALICIOUS)

        result = augmentation.build(
            db, dataset=_dataset(db, "aug-admission"), feature_names=tuple(FEATURE_NAMES)
        )
        assert result.admitted == 1
        assert result.group_counts == {"auth_success": 1}
        assert result.skipped_not_benign == 1

    def test_a_member_without_an_inference_is_skipped_and_counted(self, db) -> None:
        """No stored vector means no verifiable claim about what was scored."""
        scored = _event(db, event_type="auth_success", index=10)
        unscored = _event(db, event_type="auth_success", index=11)
        _inference(db, scored)
        _feedback(db, scored, FeedbackLabel.BENIGN)
        _feedback(db, unscored, FeedbackLabel.BENIGN)

        result = augmentation.build(
            db, dataset=_dataset(db, "aug-missing"), feature_names=tuple(FEATURE_NAMES)
        )
        assert result.admitted == 1
        assert result.skipped_no_inference == 1

    def test_a_non_event_target_is_skipped_and_counted(self, db) -> None:
        """An incident has no single feature vector. Skipped visibly, never
        guessed at."""
        event = _event(db, event_type="auth_success", index=20)
        _inference(db, event)
        _feedback(db, event, FeedbackLabel.BENIGN)
        feedback_service.submit(
            db,
            target_type=FeedbackTargetType.INCIDENT,
            target_id=999,
            label=FeedbackLabel.BENIGN,
            analyst="a@aegisx.dev",
            source="simulation",
        )

        result = augmentation.build(
            db, dataset=_dataset(db, "aug-nonevent"), feature_names=tuple(FEATURE_NAMES)
        )
        assert result.admitted == 1
        assert result.skipped_non_event == 1


class TestVectorFidelity:
    def test_the_vector_follows_the_feature_order_not_the_stored_dict_order(
        self, db
    ) -> None:
        """`features` is JSON. Its key order is not a contract, and training on
        a permuted vector would be silently wrong rather than an error."""
        event = _event(db, event_type="auth_success", index=30)
        _inference(db, event, shuffled=True)
        _feedback(db, event, FeedbackLabel.BENIGN)

        result = augmentation.build(
            db, dataset=_dataset(db, "aug-order"), feature_names=tuple(FEATURE_NAMES)
        )
        vector = result.vectors[0]
        assert len(vector) == len(FEATURE_NAMES)
        # _inference(shuffled=True) numbers the reversed name list, so the value
        # for the first feature name must be len-1, not 0.
        assert vector[0] == float(len(FEATURE_NAMES) - 1)

    def test_a_vector_missing_a_feature_is_refused_not_padded(self, db) -> None:
        event = _event(db, event_type="auth_success", index=40)
        inference = _inference(db, event)
        broken = dict(inference.features)
        broken.pop(FEATURE_NAMES[0])
        inference.features = broken
        db.flush()
        _feedback(db, event, FeedbackLabel.BENIGN)

        result = augmentation.build(
            db, dataset=_dataset(db, "aug-broken"), feature_names=tuple(FEATURE_NAMES)
        )
        assert result.admitted == 0
        assert result.skipped_incomplete_vector == 1


class TestCapIsApplied:
    def test_a_baseline_relative_cap_clips_a_single_group_spike(self, db) -> None:
        """§9's defence, reaching the production path. One event type supplying
        far more benign verdicts than its baseline is the poisoning signature."""
        for index in range(20):
            event = _event(db, event_type="malware_detected", index=100 + index)
            _inference(db, event)
            _feedback(db, event, FeedbackLabel.BENIGN)

        result = augmentation.build(
            db,
            dataset=_dataset(db, "aug-cap"),
            feature_names=tuple(FEATURE_NAMES),
            cap_policy=caps.POLICY_BASELINE_RELATIVE,
            baseline_rates={"malware_detected": 1.0},
            tolerance=3.0,
        )
        assert result.admitted <= 3
        assert result.cap_policy == caps.POLICY_BASELINE_RELATIVE

    def test_the_default_policy_leaves_existing_behaviour_unchanged(self, db) -> None:
        for index in range(5):
            event = _event(db, event_type="auth_success", index=200 + index)
            _inference(db, event)
            _feedback(db, event, FeedbackLabel.BENIGN)

        result = augmentation.build(
            db, dataset=_dataset(db, "aug-default"), feature_names=tuple(FEATURE_NAMES)
        )
        assert result.admitted == 5
        assert result.cap_policy == caps.POLICY_GLOBAL


class TestBaselineRates:
    def test_the_baseline_excludes_the_dataset_under_review(self, db) -> None:
        """§9 learned the baseline from held-out honest seeds. The production
        analogue is excluding the very batch being admitted - otherwise the
        baseline learns the attack as normal."""
        for index in range(6):
            event = _event(db, event_type="malware_detected", index=300 + index)
            _inference(db, event)
            _feedback(db, event, FeedbackLabel.BENIGN)
        dataset = _dataset(db, "aug-baseline")

        rates = augmentation.baseline_rates(db, exclude_dataset_id=dataset.id)
        assert rates.get("malware_detected", 0.0) == 0.0


class TestTrainCandidateWiring:
    """Before V6, `train_candidate` recorded `feedbackDatasetId` as metadata and
    fitted on telemetry alone - feedback had never influenced production
    training. These assert that it now does, and that nothing changes when no
    dataset is passed."""

    def _feedback_dataset(self, db, name: str, count: int = 6):
        for index in range(count):
            event = _event(db, event_type="auth_success", index=900 + index)
            _inference(db, event)
            _feedback(db, event, FeedbackLabel.BENIGN)
        return _dataset(db, name)

    def test_without_a_dataset_the_fit_set_is_telemetry_alone(
        self, db, tmp_path_factory
    ) -> None:
        from app.adaptation.candidates import training

        model = training.train_candidate(
            db,
            samples=600,
            seed=1337,
            directory=tmp_path_factory.mktemp("noaug"),
            created_by="test",
        )
        assert model.parameters["feedbackDatasetId"] is None
        assert model.parameters["augmentation"] is None

    def test_a_dataset_adds_its_admitted_rows_to_the_fit_set(
        self, db, tmp_path_factory
    ) -> None:
        from app.adaptation.candidates import training

        dataset = self._feedback_dataset(db, "wire-adds")
        plain = training.train_candidate(
            db,
            samples=600,
            seed=1337,
            directory=tmp_path_factory.mktemp("plain"),
            created_by="test",
        )
        augmented = training.train_candidate(
            db,
            samples=600,
            seed=1337,
            directory=tmp_path_factory.mktemp("aug"),
            created_by="test",
            feedback_dataset_id=dataset.id,
            # Explicit: this asserts rows reach the fit set, not what the cap
            # does to them. The default policy would refuse this cold start.
            cap_policy=caps.POLICY_GLOBAL,
        )
        assert augmented.training_samples > plain.training_samples
        assert augmented.parameters["augmentation"]["admitted"] == 6

    def test_the_cap_policy_is_recorded_on_the_model(
        self, db, tmp_path_factory
    ) -> None:
        """Provenance: an approver must be able to see which cap was in force
        when the candidate was fitted, not infer it."""
        from app.adaptation.candidates import training

        dataset = self._feedback_dataset(db, "wire-policy")
        model = training.train_candidate(
            db,
            samples=600,
            seed=1337,
            directory=tmp_path_factory.mktemp("policy"),
            created_by="test",
            feedback_dataset_id=dataset.id,
            cap_policy=caps.POLICY_BASELINE_RELATIVE,
            baseline_rates={"auth_success": 1.0},
        )
        provenance = model.parameters["augmentation"]
        assert provenance["capPolicy"] == caps.POLICY_BASELINE_RELATIVE
        assert provenance["admitted"] <= 3
        assert provenance["skipped"]["byCap"] >= 3

    def test_an_unknown_dataset_id_is_refused(self, db, tmp_path_factory) -> None:
        """Training on "whatever that id turned out to be" would make the
        model's provenance a guess."""
        from app.adaptation.candidates import training

        with pytest.raises(ValueError, match="feedback dataset"):
            training.train_candidate(
                db,
                samples=600,
                seed=1337,
                directory=tmp_path_factory.mktemp("badid"),
                created_by="test",
                feedback_dataset_id=999999,
            )


class TestTrainCandidateCli:
    def test_the_cli_can_select_the_cap_policy(self, db, tmp_path) -> None:
        """§9 measured that the default `global` policy does not stop targeted
        poisoning. An operator admitting real feedback must be able to choose
        the policy that does, without editing source."""
        from app.adaptation.candidates import train_candidate

        parser_choices = train_candidate.build_parser().parse_args(
            ["--cap-policy", caps.POLICY_BASELINE_RELATIVE]
        )
        assert parser_choices.cap_policy == caps.POLICY_BASELINE_RELATIVE

    def test_the_cli_defaults_to_the_policy_that_stops_the_attack(self) -> None:
        """An operator who types the minimum gets the safe policy, not the one
        §9 measured admitting 21.9 of 22 poisoned rows."""
        from app.adaptation.candidates import train_candidate

        args = train_candidate.build_parser().parse_args([])
        assert args.cap_policy == caps.POLICY_BASELINE_RELATIVE

    def test_the_cli_does_not_precompute_rates_around_the_cold_start_refusal(
        self,
    ) -> None:
        """train_candidate derives the rates itself and refuses a cold start.
        A CLI that pre-computed them would hand in an empty dict and bypass
        that refusal silently."""
        import inspect

        from app.adaptation.candidates import train_candidate

        source = inspect.getsource(train_candidate.main)
        assert "baseline_rates=" not in source


class TestBaselineRelativeIsTheDefault:
    """V6 §9 measured that `global` does not stop targeted poisoning, so the
    policy that does is the default.

    Flipping it is not a one-line change. `baseline_relative` needs per-group
    baseline rates, and with none supplied every group falls to the floor - a
    measured 6 rows admitted of 220. §7.4 measured that feedback that sparse
    makes the model *worse* than no feedback at all, so a naive flip would
    silently gut the arm it is protecting.
    """

    _next_index = 1000

    def _dataset_with_history(self, db, name: str, count: int = 6):
        base = TestBaselineRelativeIsTheDefault._next_index
        TestBaselineRelativeIsTheDefault._next_index += count
        for index in range(count):
            event = _event(db, event_type="auth_success", index=base + index)
            _inference(db, event)
            _feedback(db, event, FeedbackLabel.BENIGN)
        return _dataset(db, name)

    def test_the_default_policy_is_baseline_relative(self) -> None:
        import inspect

        from app.adaptation.candidates import training

        default = inspect.signature(training.train_candidate).parameters[
            "cap_policy"
        ].default
        assert default == caps.POLICY_BASELINE_RELATIVE

    def test_baseline_rates_are_derived_when_not_supplied(
        self, db, tmp_path_factory
    ) -> None:
        """An operator must not have to hand-compute rates to get the safe
        policy. Deriving them from history is what makes the default usable."""
        from app.adaptation.candidates import training

        # History: a prior dataset the baseline can be learned from.
        self._dataset_with_history(db, "hist-prior", count=8)
        current = self._dataset_with_history(db, "hist-current", count=6)

        model = training.train_candidate(
            db,
            samples=600,
            seed=1337,
            directory=tmp_path_factory.mktemp("derived"),
            created_by="test",
            feedback_dataset_id=current.id,
        )
        provenance = model.parameters["augmentation"]
        assert provenance["capPolicy"] == caps.POLICY_BASELINE_RELATIVE
        # Derived rates must admit more than the floor-for-everything collapse.
        assert provenance["admitted"] > 2
        assert provenance["baselineRatesDerived"] is True

    def test_a_cold_start_is_refused_not_silently_degraded(
        self, db, tmp_path_factory
    ) -> None:
        """With no feedback history there is no baseline to be relative to, and
        the floor would admit a handful of rows - which §7.4 measured is worse
        than admitting none. Refused loudly so the operator chooses."""
        from app.adaptation.candidates import training

        first_ever = self._dataset_with_history(db, "cold-start", count=6)

        with pytest.raises(ValueError, match="no feedback history"):
            training.train_candidate(
                db,
                samples=600,
                seed=1337,
                directory=tmp_path_factory.mktemp("cold"),
                created_by="test",
                feedback_dataset_id=first_ever.id,
            )

    def test_global_remains_available_as_an_explicit_opt_out(
        self, db, tmp_path_factory
    ) -> None:
        """A first batch with no history is a legitimate reason to choose the
        weaker policy knowingly. It must stay reachable."""
        from app.adaptation.candidates import training

        first_ever = self._dataset_with_history(db, "optout", count=6)
        model = training.train_candidate(
            db,
            samples=600,
            seed=1337,
            directory=tmp_path_factory.mktemp("optout"),
            created_by="test",
            feedback_dataset_id=first_ever.id,
            cap_policy=caps.POLICY_GLOBAL,
        )
        assert model.parameters["augmentation"]["capPolicy"] == caps.POLICY_GLOBAL
        assert model.parameters["augmentation"]["admitted"] == 6

    def test_explicit_baseline_rates_are_not_overridden(
        self, db, tmp_path_factory
    ) -> None:
        from app.adaptation.candidates import training

        self._dataset_with_history(db, "explicit-prior", count=8)
        current = self._dataset_with_history(db, "explicit-current", count=6)

        model = training.train_candidate(
            db,
            samples=600,
            seed=1337,
            directory=tmp_path_factory.mktemp("explicit"),
            created_by="test",
            feedback_dataset_id=current.id,
            baseline_rates={"auth_success": 1.0},
        )
        provenance = model.parameters["augmentation"]
        assert provenance["baselineRatesDerived"] is False
        assert provenance["admitted"] <= 3
