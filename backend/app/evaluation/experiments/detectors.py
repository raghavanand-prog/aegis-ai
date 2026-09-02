"""Detectors under evaluation, behind one interface.

Every baseline the research question needs - rules alone, the V3 anomaly model,
a supervised reference, and the hybrid combinations - is expressed here as a
:class:`Detector`. The experiment runner knows nothing about any of them beyond
this interface, which is what makes an ablation matrix possible without a
special case per configuration.

Score semantics are part of the interface, not a footnote
--------------------------------------------------------

``score_kind`` travels with every detector and into every stored result,
because these numbers are not interchangeable and presenting them as if they
were is the most common way a detection paper misleads:

``rule_hit``
    A binary indicator. 0 or 1. It has no ordering, so ROC-AUC and PR-AUC are
    not computed for it and the report says so rather than printing 0.5.

``anomaly_score``
    Isolation Forest's ranking, mapped monotonically to 0..1. Higher means
    "further from what the model considers normal". **Not** a probability: a
    0.7 does not mean 70% likely malicious, and nothing in this package treats
    it as one.

``probability``
    A supervised classifier's calibrated-ish class-1 estimate. This one *is* a
    probability, and it is the only kind here that is.

``risk_score``
    AEGISX's production 0..100 weighted risk, which is a policy output built
    from several signals, not a model output at all.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Protocol

from app.detection import rules as rule_engine
from app.evaluation.datasets.base import EvaluationSample
from app.ml.models.isolation_forest import IsolationForestDetector
from app.ml.schemas import FEATURE_SCHEMA_VERSION, InferenceResult
from app.scoring import risk as risk_engine

RULE_HIT = "rule_hit (binary indicator, not a score)"
ANOMALY_SCORE = "anomaly_score (ranking, NOT a probability)"
PROBABILITY = "probability (supervised class-1 estimate)"
RISK_SCORE = "risk_score (AEGISX weighted policy output, 0..100)"

#: Score kinds that carry a meaningful ordering, and can therefore support
#: threshold sweeps and ranking metrics.
ORDERED_KINDS = frozenset({ANOMALY_SCORE, PROBABILITY, RISK_SCORE})


@dataclass
class Prediction:
    """One detector's verdict on one sample."""

    sample_id: str
    score: float
    detected: bool
    latency_ms: float
    #: Rule ids that fired, where the detector has rules. Empty otherwise.
    rules_fired: tuple[str, ...] = ()


class Detector(Protocol):
    """What the experiment runner requires of anything it evaluates."""

    name: str
    score_kind: str

    def fit(self, samples: list[EvaluationSample], features: dict[str, tuple[float, ...]]) -> None:
        """Fit on the training split. A detector with nothing to fit does nothing."""

    def predict(
        self, sample: EvaluationSample, vector: tuple[float, ...] | None, threshold: float
    ) -> Prediction:
        """Score one sample. Must not consult the label, directly or otherwise."""

    def describe(self) -> dict[str, Any]:
        """Configuration and provenance, recorded with every result."""


# ------------------------------------------------------------------- rules


class RulesDetector:
    """The V3 deterministic rule engine, unmodified.

    Threshold is meaningless here - a rule either matched or it did not - so it
    is accepted and ignored, and the score is the indicator itself.
    """

    score_kind = RULE_HIT

    def __init__(self, *, enabled_rules: tuple[str, ...] | None = None) -> None:
        self.name = "rules"
        #: When set, only these rule ids may fire. Used by the ablation study to
        #: measure what a single rule family contributes.
        self.enabled_rules = enabled_rules

    def fit(self, samples: list[EvaluationSample], features: dict[str, tuple[float, ...]]) -> None:
        return None

    def predict(
        self, sample: EvaluationSample, vector: tuple[float, ...] | None, threshold: float
    ) -> Prediction:
        started = time.perf_counter()
        result = rule_engine.evaluate(
            sample.candidate, base_severity=sample.candidate.get("severity", "Low")
        )
        fired = tuple(detection.rule_id for detection in result.detections)
        if self.enabled_rules is not None:
            fired = tuple(rule_id for rule_id in fired if rule_id in self.enabled_rules)
        elapsed = (time.perf_counter() - started) * 1000.0
        return Prediction(
            sample_id=sample.id,
            score=1.0 if fired else 0.0,
            detected=bool(fired),
            latency_ms=elapsed,
            rules_fired=fired,
        )

    def describe(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "kind": "deterministic-rules",
            "scoreKind": self.score_kind,
            "rulesetFingerprint": _ruleset_fingerprint(),
            "ruleCount": len(rule_engine.catalogue()),
            "enabledRules": list(self.enabled_rules) if self.enabled_rules else "all",
        }


def _ruleset_fingerprint() -> str:
    from app.evaluation.runners.detection_runner import ruleset_fingerprint

    return ruleset_fingerprint()


# ------------------------------------------------------------- anomaly model


class AnomalyDetector:
    """Isolation Forest over AEGISX's production feature schema.

    Two provenances are possible and they answer different questions:

    ``fitted``
        Fitted here on this experiment's *training split only*. Measures what
        the architecture can do on this data.

    ``registered``
        The artifact the running system would load, verified by digest.
        Measures what the deployed model actually does - which, on a corpus
        from a different telemetry class, is expected to be much worse. That
        gap is a result, not a bug to hide.

    Isolation Forest is unsupervised, so fitting on the training split uses no
    labels. The labels are still withheld: they never enter ``fit``.
    """

    score_kind = ANOMALY_SCORE

    def __init__(
        self,
        *,
        feature_names: tuple[str, ...],
        contamination: float = 0.08,
        random_state: int = 1337,
        name: str = "isolation_forest",
        detector: IsolationForestDetector | None = None,
        provenance: str = "fitted",
        model_info: dict[str, Any] | None = None,
    ) -> None:
        self.name = name
        self.feature_names = tuple(feature_names)
        self.contamination = contamination
        self.random_state = random_state
        self.provenance = provenance
        self.model_info = model_info or {}
        self._detector = detector
        self._training_samples = 0

    def fit(self, samples: list[EvaluationSample], features: dict[str, tuple[float, ...]]) -> None:
        if self.provenance == "registered":
            # A registered artifact is immutable. Refitting it here would make
            # the result a measurement of something that was never deployed.
            return None
        vectors = [features[sample.id] for sample in samples if sample.id in features]
        if not vectors:
            raise ValueError("anomaly detector received no training vectors")
        self._detector = IsolationForestDetector(
            feature_names=self.feature_names,
            contamination=self.contamination,
            random_state=self.random_state,
        )
        self._detector.fit(vectors)
        self._training_samples = len(vectors)

    def predict(
        self, sample: EvaluationSample, vector: tuple[float, ...] | None, threshold: float
    ) -> Prediction:
        if self._detector is None or vector is None:
            return Prediction(sample_id=sample.id, score=0.0, detected=False, latency_ms=0.0)
        started = time.perf_counter()
        score = self._detector.anomaly_score(vector)
        elapsed = (time.perf_counter() - started) * 1000.0
        return Prediction(
            sample_id=sample.id,
            score=score,
            detected=score >= threshold,
            latency_ms=elapsed,
        )

    def inference_for(self, vector: tuple[float, ...], threshold: float) -> InferenceResult | None:
        """An ``InferenceResult`` shaped exactly as production emits one.

        Used by the hybrid detector so risk scoring sees the same object the
        ingestion path hands it.
        """
        if self._detector is None:
            return None
        score = self._detector.anomaly_score(vector)
        return InferenceResult(
            model_name=self.name,
            model_version=str(self.model_info.get("version", "experiment")),
            feature_schema_version=FEATURE_SCHEMA_VERSION,
            anomaly_score=score,
            is_anomaly=score >= threshold,
            threshold=threshold,
        )

    def describe(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "kind": "isolation-forest",
            "scoreKind": self.score_kind,
            "provenance": self.provenance,
            "contamination": self.contamination,
            "randomState": self.random_state,
            "featureSchemaVersion": FEATURE_SCHEMA_VERSION,
            "featureCount": len(self.feature_names),
            "trainingSamples": self._training_samples or None,
            "model": self.model_info or None,
        }


# ---------------------------------------------------------------- supervised


class SupervisedDetector:
    """Gradient-boosted trees over the same AEGISX features.

    Included because the central research question - does the hybrid beat its
    parts - is only meaningful against a competent alternative. An unsupervised
    detector losing to a supervised one on labelled data is expected; what the
    comparison establishes is how much of the gap is the *feature schema* and
    how much is the *learning setup*.

    ``HistGradientBoostingClassifier`` is chosen over XGBoost/LightGBM because
    it is already available in the pinned scikit-learn, is strong on tabular
    data, and adds no dependency. Deep learning is deliberately absent: nothing
    about 45 tabular features calls for it.

    Labels are used here - that is what "supervised" means - but only ever from
    the training split, and never from validation or test.
    """

    score_kind = PROBABILITY

    def __init__(
        self,
        *,
        feature_names: tuple[str, ...],
        random_state: int = 1337,
        max_iter: int = 200,
        learning_rate: float = 0.1,
        name: str = "supervised_hgb",
    ) -> None:
        self.name = name
        self.feature_names = tuple(feature_names)
        self.random_state = random_state
        self.max_iter = max_iter
        self.learning_rate = learning_rate
        self._model: Any = None
        self._training_samples = 0
        self._training_positives = 0

    def fit(self, samples: list[EvaluationSample], features: dict[str, tuple[float, ...]]) -> None:
        import numpy as np
        from sklearn.ensemble import HistGradientBoostingClassifier

        usable = [sample for sample in samples if sample.id in features]
        matrix = np.asarray([features[sample.id] for sample in usable], dtype=float)
        target = np.asarray([1 if sample.is_malicious else 0 for sample in usable], dtype=int)
        if matrix.size == 0:
            raise ValueError("supervised detector received no training vectors")
        if len(set(target.tolist())) < 2:
            raise ValueError(
                "the training split contains a single class; a supervised baseline "
                "cannot be fitted and must not be reported as if it were"
            )
        self._model = HistGradientBoostingClassifier(
            random_state=self.random_state,
            max_iter=self.max_iter,
            learning_rate=self.learning_rate,
        )
        self._model.fit(matrix, target)
        self._training_samples = int(matrix.shape[0])
        self._training_positives = int(target.sum())

    def predict(
        self, sample: EvaluationSample, vector: tuple[float, ...] | None, threshold: float
    ) -> Prediction:
        if self._model is None or vector is None:
            return Prediction(sample_id=sample.id, score=0.0, detected=False, latency_ms=0.0)
        import numpy as np

        started = time.perf_counter()
        probability = float(self._model.predict_proba(np.asarray([vector], dtype=float))[0][1])
        elapsed = (time.perf_counter() - started) * 1000.0
        return Prediction(
            sample_id=sample.id,
            score=probability,
            detected=probability >= threshold,
            latency_ms=elapsed,
        )

    def describe(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "kind": "supervised-hist-gradient-boosting",
            "scoreKind": self.score_kind,
            "library": "scikit-learn",
            "randomState": self.random_state,
            "maxIter": self.max_iter,
            "learningRate": self.learning_rate,
            "featureSchemaVersion": FEATURE_SCHEMA_VERSION,
            "featureCount": len(self.feature_names),
            "trainingSamples": self._training_samples or None,
            "trainingPositives": self._training_positives or None,
        }


# -------------------------------------------------------------------- hybrid


class UnionHybridDetector:
    """"Either detector fired" - the V3 hybrid definition, preserved.

    The score is the maximum of the two, which is *not* a meaningful quantity
    (a rule indicator and an anomaly ranking are different units), so this
    detector declares ``rule_hit`` semantics and ranking metrics are withheld.
    Presenting a max-of-two-units number as a score is exactly the sort of
    thing this project refuses to do.
    """

    score_kind = RULE_HIT

    def __init__(self, *, rules: RulesDetector, anomaly: Detector, name: str = "hybrid") -> None:
        self.name = name
        self.rules = rules
        self.anomaly = anomaly

    def fit(self, samples: list[EvaluationSample], features: dict[str, tuple[float, ...]]) -> None:
        self.rules.fit(samples, features)
        self.anomaly.fit(samples, features)

    def predict(
        self, sample: EvaluationSample, vector: tuple[float, ...] | None, threshold: float
    ) -> Prediction:
        rule_prediction = self.rules.predict(sample, vector, threshold)
        ml_prediction = self.anomaly.predict(sample, vector, threshold)
        detected = rule_prediction.detected or ml_prediction.detected
        return Prediction(
            sample_id=sample.id,
            score=1.0 if detected else 0.0,
            detected=detected,
            latency_ms=rule_prediction.latency_ms + ml_prediction.latency_ms,
            rules_fired=rule_prediction.rules_fired,
        )

    def describe(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "kind": "union-hybrid",
            "scoreKind": self.score_kind,
            "rule": "detected when a rule fired OR the anomaly score crossed the threshold",
            "components": [self.rules.describe(), self.anomaly.describe()],
        }


class RiskBandHybridDetector:
    """AEGISX's *production* hybrid: weighted risk scoring, thresholded on a band.

    This is the one configuration that measures the deployed system rather than
    an approximation of it. It calls ``app.scoring.risk.score_event`` with the
    same arguments the ingestion path supplies, so the architectural guarantee
    that ML alone cannot reach the High band (ML contributes at most 25, the
    band starts at 70) is exercised rather than asserted.
    """

    score_kind = RISK_SCORE

    def __init__(
        self,
        *,
        rules: RulesDetector,
        anomaly: AnomalyDetector,
        anomaly_threshold: float,
        name: str = "hybrid_risk",
    ) -> None:
        self.name = name
        self.rules = rules
        self.anomaly = anomaly
        self.anomaly_threshold = anomaly_threshold

    def fit(self, samples: list[EvaluationSample], features: dict[str, tuple[float, ...]]) -> None:
        self.rules.fit(samples, features)
        self.anomaly.fit(samples, features)

    def predict(
        self, sample: EvaluationSample, vector: tuple[float, ...] | None, threshold: float
    ) -> Prediction:
        started = time.perf_counter()
        detection_result = rule_engine.evaluate(
            sample.candidate, base_severity=sample.candidate.get("severity", "Low")
        )
        inference = (
            self.anomaly.inference_for(vector, self.anomaly_threshold)
            if vector is not None
            else None
        )
        assessment = risk_engine.score_event(
            detection_result=detection_result,
            inference=inference,
            base_severity=sample.candidate.get("severity", "Low"),
        )
        elapsed = (time.perf_counter() - started) * 1000.0
        score = float(assessment.risk_score)
        return Prediction(
            sample_id=sample.id,
            score=score,
            detected=score >= threshold,
            latency_ms=elapsed,
            rules_fired=tuple(d.rule_id for d in detection_result.detections),
        )

    def describe(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "kind": "risk-band-hybrid",
            "scoreKind": self.score_kind,
            "strategy": risk_engine.describe_strategy(),
            "anomalyThreshold": self.anomaly_threshold,
            "components": [self.rules.describe(), self.anomaly.describe()],
        }


@dataclass
class DetectorSpec:
    """A detector plus the threshold policy it is evaluated under."""

    detector: Any
    #: Candidate thresholds swept on the *validation* split. The winner is
    #: frozen before the test split is touched.
    threshold_grid: tuple[float, ...] = ()
    #: Used when the grid is empty (rule-style detectors have no threshold).
    fixed_threshold: float = 0.5
    notes: tuple[str, ...] = field(default_factory=tuple)

    @property
    def sweeps_threshold(self) -> bool:
        return bool(self.threshold_grid)
