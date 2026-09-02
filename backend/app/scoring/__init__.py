"""Hybrid risk scoring.

One transparent strategy that turns rule matches, ML anomalies, threat
intelligence verdicts and correlation confidence into a single explainable
score, with every contribution recorded.
"""

from app.scoring.risk import (
    STRATEGY_VERSION,
    RiskAssessment,
    Signal,
    describe_strategy,
    ml_contribution,
    risk_level,
    score_event,
)

__all__ = [
    "STRATEGY_VERSION",
    "RiskAssessment",
    "Signal",
    "describe_strategy",
    "ml_contribution",
    "risk_level",
    "score_event",
]
