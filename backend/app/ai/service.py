"""AI analyst orchestration.

    incident -> evidence package -> prompt -> provider -> parse
             -> ground -> persist -> audit

Everything about this path is built so the analyst layer can fail without the
SOC noticing:

* provider not configured  -> 503 with a reason the UI renders as a degraded state
* provider times out       -> failure recorded, audited, surfaced; nothing else changes
* provider returns garbage -> stored as a malformed response, never guessed at
* evidence is too thin     -> answered "insufficient evidence" without calling out
* answer is not grounded   -> stored WITH its warnings, shown next to the text

Nothing here ever changes an incident's severity, status or risk score. The AI
produces a written opinion for a human to weigh, and that is the whole of its
authority in this system.
"""

from __future__ import annotations

import logging
import threading
from datetime import date, datetime, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.ai import prompts
from app.ai.base import AIAnalystProvider, ProviderResponse, parse_json_response
from app.ai.evidence import EvidencePackage
from app.ai.evidence import build as build_evidence
from app.ai.grounding import verify
from app.ai.providers.hosted import AnthropicProvider, OpenAIProvider
from app.ai.providers.mock import MockAnalystProvider
from app.core.config import settings
from app.models.ai_analysis import AIAnalysis
from app.models.enums import AIAnalysisKind, AuditAction
from app.models.incident import Incident
from app.models.user import User
from app.services import audit_service

logger = logging.getLogger(__name__)


def _iso(value) -> str | None:  # noqa: ANN001 - datetime | None
    """UTC-stamped ISO string, or None. See app.schemas.common.as_utc."""
    from app.schemas.common import as_utc

    stamped = as_utc(value)
    return stamped.isoformat() if stamped else None

_PROVIDERS: dict[str, type[AIAnalystProvider]] = {
    "mock": MockAnalystProvider,
    "openai": OpenAIProvider,
    "anthropic": AnthropicProvider,
}


class AIUnavailable(RuntimeError):
    """Raised when no analysis can be produced. Carries a displayable reason."""


class _Budget:
    """Per-process daily cap on provider requests.

    An analyst holding down a button, or a loop in a script, must not be able
    to run up an unbounded bill against a metered API.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._day: date | None = None
        self._used = 0

    def take(self, limit: int) -> bool:
        today = datetime.now(timezone.utc).date()
        with self._lock:
            if self._day != today:
                self._day = today
                self._used = 0
            if self._used >= limit:
                return False
            self._used += 1
            return True

    def snapshot(self, limit: int) -> dict[str, Any]:
        with self._lock:
            return {
                "day": self._day.isoformat() if self._day else None,
                "used": self._used,
                "limit": limit,
                "remaining": max(limit - self._used, 0),
            }


_budget = _Budget()
_provider_lock = threading.Lock()
_provider: AIAnalystProvider | None = None
#: The configuration value the cached provider was built from. Compared against
#: settings rather than the provider's own name, so an explicitly installed
#: provider is not discarded for "not matching the config".
_provider_source: str | None = None
_provider_pinned = False


def get_provider() -> AIAnalystProvider:
    global _provider, _provider_source
    with _provider_lock:
        if _provider_pinned and _provider is not None:
            return _provider
        if _provider is None or _provider_source != settings.ai_provider:
            factory = _PROVIDERS.get(settings.ai_provider)
            if factory is None:
                raise AIUnavailable(
                    f"AI_PROVIDER={settings.ai_provider!r} is not a provider this build "
                    f"knows. Available: {', '.join(sorted(_PROVIDERS))}."
                )
            _provider = factory()
            _provider_source = settings.ai_provider
        return _provider


def set_provider(provider: AIAnalystProvider | None) -> None:
    """Install a provider explicitly. Used by tests; not reachable from the API."""
    global _provider, _provider_pinned, _provider_source
    with _provider_lock:
        _provider = provider
        _provider_pinned = provider is not None
        _provider_source = provider.name if provider is not None else None


def reset_provider() -> None:
    global _provider, _provider_source, _provider_pinned
    with _provider_lock:
        _provider = None
        _provider_source = None
        _provider_pinned = False


# --------------------------------------------------------------------------- status
def status() -> dict[str, Any]:
    """What the analyst can currently do, and why not if it cannot."""
    if not settings.ai_enabled or settings.ai_provider in {"none", ""}:
        return {
            "enabled": False,
            "available": False,
            "provider": settings.ai_provider or "none",
            "reason": "The AI analyst is disabled by configuration (AI_ENABLED / AI_PROVIDER).",
            "isTemplateProvider": False,
            "promptVersion": prompts.PROMPT_VERSION,
            "analysisVersion": prompts.ANALYSIS_VERSION,
            "budget": _budget.snapshot(settings.ai_daily_request_budget),
        }

    try:
        provider = get_provider()
    except AIUnavailable as exc:
        return {
            "enabled": True,
            "available": False,
            "provider": settings.ai_provider,
            "reason": str(exc),
            "isTemplateProvider": False,
            "promptVersion": prompts.PROMPT_VERSION,
            "analysisVersion": prompts.ANALYSIS_VERSION,
            "budget": _budget.snapshot(settings.ai_daily_request_budget),
        }

    configured = provider.configured
    return {
        "enabled": True,
        "available": configured,
        "provider": provider.name,
        "model": provider.model_name,
        "reason": None if configured else f"{provider.name} requires AI_API_KEY to be set.",
        # The UI labels a template answer differently from a model answer.
        "isTemplateProvider": provider.name == "mock",
        "sendsDataExternally": provider.name not in {"mock"},
        "promptVersion": prompts.PROMPT_VERSION,
        "analysisVersion": prompts.ANALYSIS_VERSION,
        "maxEvidenceEvents": settings.ai_max_evidence_events,
        "budget": _budget.snapshot(settings.ai_daily_request_budget),
    }


# --------------------------------------------------------------------------- analysis
def analyze_incident(
    db: Session,
    incident: Incident,
    *,
    kind: AIAnalysisKind = AIAnalysisKind.ANALYZE,
    question: str | None = None,
    user: User | None = None,
    ip_address: str | None = None,
) -> AIAnalysis:
    """Produce, verify and store one analysis. Raises :class:`AIUnavailable`."""
    state = status()
    if not state["available"]:
        raise AIUnavailable(state["reason"] or "The AI analyst is unavailable.")

    provider = get_provider()
    package = build_evidence(db, incident)
    fingerprint = package.fingerprint()

    audit_service.record(
        db,
        action=AuditAction.AI_ANALYSIS_REQUESTED,
        user=user,
        target_type="incident",
        target_id=incident.incident_id,
        ip_address=ip_address,
        details={
            "kind": kind.value,
            "provider": provider.name,
            "evidenceFingerprint": fingerprint,
            "evidence": package.summary(),
            "hasQuestion": bool(question),
        },
    )

    if not _budget.take(settings.ai_daily_request_budget):
        _audit_failure(
            db, incident, user, provider.name, "daily request budget exhausted", ip_address
        )
        raise AIUnavailable(
            "The daily AI request budget for this instance is exhausted. It resets at "
            "midnight UTC, or an administrator can raise AI_DAILY_REQUEST_BUDGET."
        )

    system_prompt, user_prompt = prompts.build_messages(package, kind, question=question)
    response = provider.complete(system_prompt, user_prompt)

    if not response.ok:
        _audit_failure(
            db, incident, user, provider.name, response.error or "unknown error", ip_address
        )
        raise AIUnavailable(response.error or f"{provider.name} did not return an analysis.")

    parsed = parse_json_response(response.text)
    if parsed is None:
        _audit_failure(db, incident, user, provider.name, "malformed response", ip_address)
        logger.warning(
            "AI provider %s returned unparseable output for %s",
            provider.name,
            incident.incident_id,
        )
        raise AIUnavailable(
            f"{provider.name} returned a response that was not valid JSON. Nothing has "
            "been stored - retry, or check the provider configuration."
        )

    report = verify(parsed, package)
    if not report.grounded:
        logger.warning(
            "AI analysis for %s failed grounding checks: %s",
            incident.incident_id,
            "; ".join(report.warnings[:3]),
        )

    analysis = _persist(
        db,
        incident=incident,
        kind=kind,
        provider_name=provider.name,
        response=response,
        parsed=parsed,
        package=package,
        fingerprint=fingerprint,
        grounding=report,
        user=user,
    )

    audit_service.record(
        db,
        action=AuditAction.AI_ANALYSIS_GENERATED,
        user=user,
        target_type="incident",
        target_id=incident.incident_id,
        ip_address=ip_address,
        details={
            "analysisId": analysis.id,
            "kind": kind.value,
            "provider": provider.name,
            "model": response.model,
            "promptVersion": prompts.PROMPT_VERSION,
            "grounded": report.grounded,
            "groundingWarnings": len(report.warnings),
            "confidence": analysis.confidence,
            "latencyMs": round(response.latency_ms, 1),
            "tokensUsed": response.tokens_used,
        },
    )
    return analysis


def _audit_failure(
    db: Session,
    incident: Incident,
    user: User | None,
    provider: str,
    reason: str,
    ip_address: str | None = None,
) -> None:
    audit_service.record(
        db,
        action=AuditAction.AI_ANALYSIS_FAILED,
        user=user,
        target_type="incident",
        target_id=incident.incident_id,
        ip_address=ip_address,
        details={"provider": provider, "reason": reason},
    )


def _text(value: Any, limit: int = 4000) -> str:
    if value is None:
        return ""
    text = value if isinstance(value, str) else str(value)
    return text.strip()[:limit]


def _string_list(value: Any, limit: int = 12) -> list[str]:
    if not isinstance(value, list):
        return []
    return [_text(item, 600) for item in value[:limit] if _text(item, 600)]


def _persist(
    db: Session,
    *,
    incident: Incident,
    kind: AIAnalysisKind,
    provider_name: str,
    response: ProviderResponse,
    parsed: dict[str, Any],
    package: EvidencePackage,
    fingerprint: str,
    grounding,  # GroundingReport
    user: User | None,
) -> AIAnalysis:
    supporting = [
        {
            "claim": _text(entry.get("claim"), 600),
            "evidenceRef": _text(entry.get("evidenceRef"), 200),
        }
        for entry in (parsed.get("supportingEvidence") or [])[:12]
        if isinstance(entry, dict)
    ]
    techniques = [
        {
            "technique": _text(entry.get("technique"), 16),
            "provenance": _text(entry.get("provenance"), 16),
            "rationale": _text(entry.get("rationale"), 400),
        }
        for entry in (parsed.get("mitreTechniques") or [])[:12]
        if isinstance(entry, dict) and entry.get("technique")
    ]

    confidence = _text(parsed.get("confidence"), 32).lower() or "unknown"
    if confidence not in {"high", "medium", "low", "insufficient_evidence", "unknown"}:
        confidence = "unknown"

    analysis = AIAnalysis(
        incident_id=incident.id,
        kind=kind.value,
        provider=provider_name,
        model=response.model,
        prompt_version=prompts.PROMPT_VERSION,
        analysis_version=prompts.ANALYSIS_VERSION,
        summary=_text(parsed.get("summary")),
        why_it_matters=_text(parsed.get("whyItMatters")),
        risk_assessment=_text(parsed.get("riskAssessment")),
        likely_behaviour=_text(parsed.get("likelyBehaviour")),
        supporting_evidence=supporting,
        mitre_techniques=techniques,
        investigation_steps=_string_list(parsed.get("investigationSteps")),
        containment_actions=_string_list(parsed.get("containmentActions")),
        confidence=confidence,
        uncertainty=_text(parsed.get("uncertainty")),
        evidence_fingerprint=fingerprint,
        evidence_summary=package.summary(),
        grounded=grounding.grounded,
        grounding_warnings=grounding.warnings[:20],
        # Capped: the raw response is kept for traceability, not as a second
        # copy of the whole conversation.
        raw_response=response.text[:20_000],
        latency_ms=response.latency_ms,
        tokens_used=response.tokens_used,
        requested_by=(user.email if user else "system"),
        requested_by_id=user.id if user else None,
    )
    db.add(analysis)
    db.flush()
    return analysis


# --------------------------------------------------------------------------- reads
def list_analyses(db: Session, incident: Incident, *, limit: int = 20) -> list[AIAnalysis]:
    return list(
        db.scalars(
            select(AIAnalysis)
            .where(AIAnalysis.incident_id == incident.id)
            .order_by(AIAnalysis.created_at.desc())
            .limit(limit)
        )
    )


def latest_analysis(db: Session, incident: Incident) -> AIAnalysis | None:
    analyses = list_analyses(db, incident, limit=1)
    return analyses[0] if analyses else None


def to_dict(analysis: AIAnalysis, *, include_raw: bool = False) -> dict[str, Any]:
    """Serializable view. Always labelled as AI-generated."""
    return {
        "id": analysis.id,
        "kind": analysis.kind,
        "provider": analysis.provider,
        "model": analysis.model,
        "promptVersion": analysis.prompt_version,
        "analysisVersion": analysis.analysis_version,
        "summary": analysis.summary,
        "whyItMatters": analysis.why_it_matters,
        "riskAssessment": analysis.risk_assessment,
        "likelyBehaviour": analysis.likely_behaviour,
        "supportingEvidence": analysis.supporting_evidence or [],
        "mitreTechniques": analysis.mitre_techniques or [],
        "investigationSteps": analysis.investigation_steps or [],
        "containmentActions": analysis.containment_actions or [],
        "confidence": analysis.confidence,
        "uncertainty": analysis.uncertainty,
        "evidenceFingerprint": analysis.evidence_fingerprint,
        "evidenceSummary": analysis.evidence_summary or {},
        "grounded": analysis.grounded,
        "groundingWarnings": analysis.grounding_warnings or [],
        "latencyMs": round(analysis.latency_ms, 1),
        "tokensUsed": analysis.tokens_used,
        "requestedBy": analysis.requested_by,
        "createdAt": _iso(analysis.created_at),
        # Carried on every payload so no consumer can present this as
        # deterministic platform output.
        "generatedBy": "ai",
        "isTemplateProvider": analysis.provider == "mock",
        "disclaimer": (
            "AI-generated analysis. It is an interpretation of the evidence AEGISX "
            "collected, not a determination by the platform. Verify before acting."
        ),
        **({"rawResponse": analysis.raw_response} if include_raw else {}),
    }
