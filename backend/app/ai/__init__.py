"""AI analyst layer.

The LLM is not a detector here. Detection is done by deterministic rules, an
anomaly model and the correlation engine; this layer takes what they found and
explains it to a human.

    sanitize.py   neutralise untrusted telemetry text before it reaches a model
    evidence.py   assemble the structured package the analyst may reason from
    prompts.py    versioned system/user prompts, with the evidence fenced off
    base.py       provider abstraction and response parsing
    grounding.py  verify the answer against the evidence it was given
    service.py    orchestration, persistence, budget and audit

The analyst has no tools, no database access and no authority. Its output is
stored as structured fields, labelled AI-generated, and never changes an
incident's severity, status or risk score.
"""

from app.ai.base import AIAnalystProvider, ProviderResponse, parse_json_response
from app.ai.evidence import EvidencePackage
from app.ai.grounding import GroundingReport, verify
from app.ai.prompts import ANALYSIS_VERSION, PROMPT_VERSION
from app.ai.sanitize import contains_injection_attempt, scrub_text, scrub_value

__all__ = [
    "ANALYSIS_VERSION",
    "PROMPT_VERSION",
    "AIAnalystProvider",
    "EvidencePackage",
    "GroundingReport",
    "ProviderResponse",
    "contains_injection_attempt",
    "parse_json_response",
    "scrub_text",
    "scrub_value",
    "verify",
]
