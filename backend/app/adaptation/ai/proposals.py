"""AI-assisted adaptation recommendations.

The AI's role is unchanged from V3: it explains and suggests. V5 lets it draft a
proposal, and draws one line hard.

**The prose is the model's. The numbers are not.**

An LLM asked for a threshold returns a plausible-looking token sequence, not a
measurement. So the model argues for a *direction* and this module computes the
*value* from measured evidence, bounded by an explicit safety limit. A model
that says "raise it to 0.99" and one that says "raise it a little" produce the
same proposal here, because the number never came from either.

Everything else follows from that. The evidence package is assembled from the
database before the model is called; the model's output is sanitized and
grounded on the way back; techniques it cites that the evidence does not support
are recorded as ungrounded rather than carried; and the resulting proposal is
``pending``, attributed to the AI, and worth exactly as much as any other
pending proposal - which is to say, nothing until a person approves it.
"""

from __future__ import annotations

import logging
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.adaptation.drift.monitor import latest_by_feature
from app.adaptation.proposals import service as proposals
from app.ai import sanitize
from app.ai.grounding import TECHNIQUE_PATTERN
from app.ml.registry import registry
from app.ml.schemas import FEATURE_SCHEMA_VERSION
from app.models.adaptation import AdaptationProposal, AnalystFeedback
from app.models.enums import ProposalType

logger = logging.getLogger("aegisx.adaptation.ai")

#: The largest single move an automated threshold proposal may request.
#:
#: Not a tuned value - a deliberate brake. A proposal that wants to move further
#: than this is asking for a change big enough that it should be argued for by a
#: person, in several steps, each measured. V4 measured what happens when the
#: anomaly threshold is chased downward on flow telemetry: 987 alerts per 1,000
#: events. Small steps are how that is avoided.
MAX_THRESHOLD_STEP = 0.05

#: Identifies AI-authored proposals. The prefix is load-bearing: the approval
#: path refuses any actor that carries it.
AI_ACTOR_PREFIX = "ai:"


def build_evidence(db: Session) -> dict[str, Any]:
    """Assemble the measured context an adaptation recommendation rests on.

    Built from the database *before* the model is called, so that what the model
    sees is a record of what happened rather than a summary it produced.
    """
    label_counts = dict(
        db.execute(
            select(AnalystFeedback.label, func.count(AnalystFeedback.id))
            .where(AnalystFeedback.superseded_by_id.is_(None))
            .group_by(AnalystFeedback.label)
        ).all()
    )
    total_feedback = sum(label_counts.values())

    comments = list(
        db.scalars(
            select(AnalystFeedback.comment)
            .where(
                AnalystFeedback.comment.is_not(None),
                AnalystFeedback.superseded_by_id.is_(None),
            )
            .order_by(AnalystFeedback.id.desc())
            .limit(50)
        )
    )
    # Analyst comments are untrusted text. They are scrubbed before they reach a
    # prompt, and the fact that something tried to steer the model is itself
    # reported rather than quietly removed.
    injection_suspected = any(sanitize.contains_injection_attempt(text) for text in comments)
    scrubbed_comments = [sanitize.scrub_text(text) for text in comments[:20]]

    drift = [
        {
            "feature": reading.feature,
            "kind": reading.kind,
            "metric": reading.metric_name,
            "value": reading.metric_value,
            "status": reading.status,
        }
        for reading in latest_by_feature(db, limit=50)
    ]

    active = registry.get_active(db, "isolation_forest")

    limitations: list[str] = []
    if total_feedback == 0:
        limitations.append(
            "No analyst feedback has been recorded. Any recommendation rests on "
            "distribution evidence alone."
        )
    if not drift:
        limitations.append("No drift measurements exist for this deployment.")
    if active is None:
        limitations.append("No model is currently deployed.")
    limitations.append(
        "Recommendations are advisory. No evaluation has been run against this "
        "proposal, and its expected impact is an estimate, not a measurement."
    )

    return {
        "featureSchemaVersion": FEATURE_SCHEMA_VERSION,
        "feedback": {
            "total": total_feedback,
            "byLabel": label_counts,
            "recentComments": scrubbed_comments,
        },
        "drift": drift,
        "model": {
            "identity": active.identity if active else None,
            "artifactSha256": active.artifact_sha256 if active else None,
        },
        "injectionSuspected": injection_suspected,
        "limitations": limitations,
    }


def _ground_techniques(text: str, evidence: dict[str, Any]) -> tuple[list[str], list[str], dict]:
    """Separate techniques the model cited from techniques the evidence supports.

    AEGISX has never let a model introduce MITRE attribution, and V5 does not
    start. A cited technique that nothing in the evidence supports is recorded
    as ungrounded - kept visible, never promoted to a finding.
    """
    cited = sorted(set(TECHNIQUE_PATTERN.findall(text or "")))
    supported_pool = {
        technique
        for item in evidence.get("drift", [])
        for technique in TECHNIQUE_PATTERN.findall(str(item))
    }
    supported = [technique for technique in cited if technique in supported_pool]
    unsupported = [technique for technique in cited if technique not in supported_pool]

    grounding = {
        "grounded": not unsupported,
        "unsupportedTechniques": unsupported,
        "note": (
            "Techniques cited by the model that the evidence does not contain are "
            "recorded here and are not treated as attribution."
        ),
    }
    return cited, supported, grounding


def _bounded_threshold(current: float, observed_false_positive_rate: float) -> float:
    """Compute the proposed threshold from evidence, bounded by the safety step.

    Deliberately simple and deliberately not from the model. The size of the
    move scales with how far the observed false-positive rate sits above a
    tolerable one, and is then clamped.
    """
    tolerable = 0.10
    excess = max(0.0, observed_false_positive_rate - tolerable)
    # Proportional, then clamped. The clamp is what matters.
    step = min(MAX_THRESHOLD_STEP, round(excess * MAX_THRESHOLD_STEP / 0.5, 4))
    return round(min(0.99, current + step), 4)


def propose_threshold_change(
    db: Session,
    *,
    provider: Any,
    current_threshold: float,
    observed_false_positive_rate: float,
) -> AdaptationProposal | None:
    """Draft a threshold proposal with AI-written rationale and computed values."""
    evidence = build_evidence(db)

    try:
        response = provider.complete(
            [
                {
                    "role": "system",
                    "content": (
                        "You are assisting a security operations team. Explain "
                        "whether the evidence supports raising the anomaly "
                        "threshold. Do not state a numeric threshold: the value "
                        "is computed from measured data, not from your output."
                    ),
                },
                {"role": "user", "content": str(evidence)},
            ]
        )
    except Exception:  # pragma: no cover - provider failure must not break the SOC
        logger.warning("AI provider failed while drafting a proposal", exc_info=True)
        return None

    summary = sanitize.scrub_text(response.get("summary", ""))
    confidence = sanitize.scrub_text(str(response.get("confidence", "unstated")))
    cited, supported, grounding = _ground_techniques(
        f"{summary} {response.get('techniques', '')}", evidence
    )

    proposed = _bounded_threshold(current_threshold, observed_false_positive_rate)
    if proposed == current_threshold:
        # Nothing to propose. Creating a no-op would be refused anyway, and
        # returning None says so honestly.
        return None

    return proposals.create(
        db,
        proposal_type=ProposalType.THRESHOLD_UPDATE,
        title=f"Raise the anomaly threshold to {proposed}",
        reason=(
            f"AI-assisted recommendation. Model rationale: {summary or 'none provided'}"
        ),
        affected_component="ml.anomaly_threshold",
        before_state={"threshold": current_threshold},
        after_state={"threshold": proposed},
        evidence={
            **evidence,
            "observedFalsePositiveRate": observed_false_positive_rate,
            "aiSummary": summary,
            "aiConfidence": confidence,
            "aiCitedTechniques": cited,
            "supportedTechniques": supported,
            "grounding": grounding,
            "valueProvenance": (
                "The threshold was computed from the observed false-positive "
                "rate and clamped to the configured safety step. It did not come "
                "from the model's output."
            ),
        },
        validation={
            "status": "not_validated",
            "note": (
                "No candidate evaluation has been run for this proposal. Safety "
                "gates have not been applied."
            ),
        },
        expected_impact={
            "note": "Estimated, not measured. Run an evaluation before approving."
        },
        risk_assessment=(
            "Raising the threshold reduces false positives and may reduce recall "
            "on low-scoring true positives. This proposal has not been validated "
            "against a labelled corpus."
        ),
        proposed_by=f"{AI_ACTOR_PREFIX}{getattr(provider, 'name', 'unknown')}",
    )
