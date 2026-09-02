"""Hybrid risk scoring.

The score an analyst sees is produced here, from named signals, with the
contribution of each one recorded alongside it. The requirement that shaped
this module: an analyst must always be able to answer *"why is this high
risk?"* without reading the source code.

    rule severity + ML anomaly + threat intelligence + correlation + context
                                  |
                          weighted, capped
                                  |
                     risk_score, risk_level, signals[]

Design decisions worth stating plainly:

**Rules dominate.** A deterministic rule match is evidence about a known attack
technique. An anomaly is evidence that something is unusual. Weighting them
equally would let statistical novelty outvote a confirmed technique match, and
the SOC would drown in interesting-but-harmless outliers.

**ML alone cannot reach High.** The ML ceiling below is deliberately under the
High threshold. An anomaly on its own raises the score and shows up in the UI;
it takes corroboration - a rule, a malicious reputation, or a correlated
sequence - to make an event high risk. That is what stops an anomaly detector
turning into an alert cannon.

**Nothing is hidden in a constant.** Every weight is a module-level named value
with a comment saying why. They are the strategy; changing them changes what
the SOC prioritises, and that should be a visible diff.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from app.models.enums import Severity, SignalType

# --------------------------------------------------------------------------- weights
#: Risk a rule contributes is the rule's own declared `risk` value; the engine
#: sums them. This multiplier lets the strategy scale rule influence without
#: editing every rule.
RULE_WEIGHT = 1.0

#: Maximum a purely statistical anomaly can contribute. Under HIGH_THRESHOLD by
#: construction, so ML can never on its own declare something high risk.
ML_MAX_CONTRIBUTION = 25
#: Anomalies below the model's own threshold contribute nothing: an event that
#: is only slightly unusual is not evidence.
ML_MIN_SCORE = 0.5

#: External reputation. A provider calling an indicator malicious is strong,
#: independent corroboration - but it is one vendor's opinion about an
#: indicator, not proof about this event, so it does not reach High alone.
THREAT_INTEL_CONTRIBUTION = {
    "malicious": 30,
    "suspicious": 15,
    "harmless": 0,
    "unknown": 0,
}

#: Correlation contribution scales with the correlator's own confidence.
CORRELATION_MAX_CONTRIBUTION = 30

#: Small nudges from event context. Kept deliberately minor - these are hints,
#: not findings.
CONTEXT_OFF_HOURS = 3
CONTEXT_EXTERNAL_SOURCE = 4

# --------------------------------------------------------------------------- bands
LOW_THRESHOLD = 25
MEDIUM_THRESHOLD = 50
HIGH_THRESHOLD = 70
CRITICAL_THRESHOLD = 85

STRATEGY_VERSION = "1.0"


@dataclass
class Signal:
    """One contribution to a risk score, with its provenance."""

    type: SignalType
    source: str
    contribution: int
    detail: str
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": self.type.value,
            "source": self.source,
            "contribution": self.contribution,
            "detail": self.detail,
            **({"metadata": self.metadata} if self.metadata else {}),
        }


@dataclass
class RiskAssessment:
    risk_score: int
    risk_level: str
    signals: list[Signal] = field(default_factory=list)
    strategy_version: str = STRATEGY_VERSION

    def signals_as_dicts(self) -> list[dict[str, Any]]:
        return [signal.to_dict() for signal in self.signals]

    def has(self, signal_type: SignalType) -> bool:
        return any(signal.type is signal_type for signal in self.signals)

    def to_dict(self) -> dict[str, Any]:
        return {
            "riskScore": self.risk_score,
            "riskLevel": self.risk_level,
            "strategyVersion": self.strategy_version,
            "signals": self.signals_as_dicts(),
        }


SEVERITY_RANK = {
    Severity.LOW.value: 1,
    Severity.MEDIUM.value: 2,
    Severity.HIGH.value: 3,
    Severity.CRITICAL.value: 4,
}


def risk_level(score: int, base_severity: str | None = None) -> str:
    """Map a 0..100 score onto the severity vocabulary the UI already speaks.

    ``base_severity`` is the severity the deterministic rules already assigned.
    The band can raise it but never lower it: a rule that says "this is a
    credential dump" has made a categorical statement about *what happened*,
    and an arithmetic band is not entitled to overrule it.
    """
    banded = Severity.LOW.value

    if score >= CRITICAL_THRESHOLD:
        banded = Severity.CRITICAL.value
    elif score >= HIGH_THRESHOLD:
        banded = Severity.HIGH.value
    elif score >= MEDIUM_THRESHOLD:
        banded = Severity.MEDIUM.value

    if base_severity and SEVERITY_RANK.get(base_severity, 0) > SEVERITY_RANK[banded]:
        return base_severity
    return banded


def ml_contribution(anomaly_score: float) -> int:
    """Scale an anomaly score above the floor onto the ML budget, linearly."""
    if anomaly_score < ML_MIN_SCORE:
        return 0
    span = max(1.0 - ML_MIN_SCORE, 1e-6)
    return int(round(ML_MAX_CONTRIBUTION * (anomaly_score - ML_MIN_SCORE) / span))


def score_event(
    *,
    detection_result: Any = None,
    inference: Any = None,
    threat_intel: list[Any] | None = None,
    correlation_confidence: float = 0.0,
    correlation_source: str | None = None,
    context: dict[str, Any] | None = None,
    base_severity: str | None = None,
) -> RiskAssessment:
    """Combine every available signal into one explainable score.

    Every argument is optional. With none of them the result is a zero score
    with no signals - which is the correct answer for an event nothing has
    anything to say about, and is what the platform produces when ML, threat
    intelligence and correlation are all unavailable.
    """
    signals: list[Signal] = []
    total = 0

    # --- Deterministic rules ----------------------------------------------
    if detection_result is not None:
        for detection in getattr(detection_result, "detections", []) or []:
            contribution = int(round(detection.risk_contribution * RULE_WEIGHT))
            total += contribution
            signals.append(
                Signal(
                    type=SignalType.RULE,
                    source=detection.rule_id,
                    contribution=contribution,
                    detail=detection.reason,
                    metadata={
                        "ruleVersion": detection.rule_version,
                        "ruleName": detection.rule_name,
                        "severity": detection.severity,
                        "mitreTechniques": list(detection.mitre_techniques),
                    },
                )
            )

    # --- ML anomaly --------------------------------------------------------
    if inference is not None and getattr(inference, "is_anomaly", False):
        contribution = ml_contribution(inference.anomaly_score)
        if contribution > 0:
            total += contribution
            drivers = [c.name for c in (inference.top_contributors or [])[:3]]
            signals.append(
                Signal(
                    type=SignalType.ML,
                    source=inference.model_name,
                    contribution=contribution,
                    detail=(
                        "Behaviour is statistically unusual compared with the "
                        f"learned baseline (anomaly score {inference.anomaly_score:.2f} "
                        f"vs threshold {inference.threshold:.2f})"
                        + (f"; furthest from normal: {', '.join(drivers)}" if drivers else "")
                    ),
                    metadata={
                        "modelVersion": inference.model_version,
                        "featureSchemaVersion": inference.feature_schema_version,
                        "anomalyScore": round(inference.anomaly_score, 4),
                        "threshold": inference.threshold,
                        # Named so nobody downstream reads this as a probability.
                        "scoreKind": "anomaly_score",
                    },
                )
            )

    # --- Threat intelligence ----------------------------------------------
    for result in threat_intel or []:
        reputation = getattr(result, "reputation", "unknown")
        if not getattr(result, "is_actionable", False):
            continue
        contribution = THREAT_INTEL_CONTRIBUTION.get(reputation, 0)
        if contribution <= 0:
            continue
        total += contribution
        signals.append(
            Signal(
                type=SignalType.THREAT_INTEL,
                source=result.provider,
                contribution=contribution,
                detail=(
                    f"{result.provider} reports {result.ioc_value} as {reputation} "
                    f"({result.malicious_count} malicious / "
                    f"{result.suspicious_count} suspicious verdicts)"
                ),
                metadata={
                    "indicator": result.ioc_value,
                    "indicatorType": result.ioc_type,
                    "reputation": reputation,
                    "providerConfidence": result.confidence,
                },
            )
        )

    # --- Correlation -------------------------------------------------------
    if correlation_confidence > 0:
        contribution = int(round(CORRELATION_MAX_CONTRIBUTION * min(correlation_confidence, 1.0)))
        if contribution > 0:
            total += contribution
            signals.append(
                Signal(
                    type=SignalType.CORRELATION,
                    source=correlation_source or "correlation-engine",
                    contribution=contribution,
                    detail=(
                        "This event is part of a correlated sequence of related activity "
                        f"(correlation confidence {correlation_confidence:.2f})"
                    ),
                    metadata={"confidence": round(correlation_confidence, 3)},
                )
            )

    # --- Contextual nudges -------------------------------------------------
    context = context or {}
    if context.get("off_hours"):
        total += CONTEXT_OFF_HOURS
        signals.append(
            Signal(
                type=SignalType.CONTEXT,
                source="event-context",
                contribution=CONTEXT_OFF_HOURS,
                detail="Activity occurred outside working hours",
            )
        )
    if context.get("external_source"):
        total += CONTEXT_EXTERNAL_SOURCE
        signals.append(
            Signal(
                type=SignalType.CONTEXT,
                source="event-context",
                contribution=CONTEXT_EXTERNAL_SOURCE,
                detail="Source address is outside the internal estate",
            )
        )

    score = max(0, min(total, 100))
    return RiskAssessment(
        risk_score=score,
        risk_level=risk_level(score, base_severity),
        signals=signals,
    )


def describe_strategy() -> dict[str, Any]:
    """The weights, served by the API so the scoring is inspectable at runtime."""
    return {
        "version": STRATEGY_VERSION,
        "weights": {
            "ruleWeight": RULE_WEIGHT,
            "mlMaxContribution": ML_MAX_CONTRIBUTION,
            "mlMinAnomalyScore": ML_MIN_SCORE,
            "threatIntelContribution": dict(THREAT_INTEL_CONTRIBUTION),
            "correlationMaxContribution": CORRELATION_MAX_CONTRIBUTION,
            "contextOffHours": CONTEXT_OFF_HOURS,
            "contextExternalSource": CONTEXT_EXTERNAL_SOURCE,
        },
        "bands": {
            "low": LOW_THRESHOLD,
            "medium": MEDIUM_THRESHOLD,
            "high": HIGH_THRESHOLD,
            "critical": CRITICAL_THRESHOLD,
        },
        "notes": [
            "Rule contributions come from each rule's own declared risk value.",
            (
                "The ML budget is deliberately below the High band: an anomaly alone "
                "cannot make an event high risk without corroboration."
            ),
            (
                "'anomaly score' is a ranking, not a probability and not a confidence. "
                "The three are never used interchangeably."
            ),
            (
                "The band can raise the severity a rule assigned, never lower it: an "
                "arithmetic score does not overrule a categorical rule match."
            ),
        ],
    }
