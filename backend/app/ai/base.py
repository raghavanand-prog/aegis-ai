"""AI analyst provider abstraction.

The platform depends on this interface, never on a vendor SDK. Swapping OpenAI
for Anthropic, or for a locally hosted model, is one class - the evidence
builder, the prompt, the grounding check, the storage and the API do not change.

Every provider must:

* accept a system prompt and a user prompt, and return raw text;
* never raise into the caller - failures come back as a
  :class:`ProviderResponse` with ``ok=False`` and a reason;
* never place an API key in a return value, an exception message or a log line.
"""

from __future__ import annotations

import json
import re
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any


@dataclass
class ProviderResponse:
    """Raw provider output, or the reason there is none."""

    ok: bool
    text: str = ""
    model: str = ""
    tokens_used: int = 0
    latency_ms: float = 0.0
    error: str | None = None
    raw: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def failure(cls, error: str, *, model: str = "", latency_ms: float = 0.0) -> ProviderResponse:
        return cls(ok=False, error=error, model=model, latency_ms=latency_ms)


class AIAnalystProvider(ABC):
    """One source of AI analysis."""

    #: Stable identifier stored on every analysis row.
    name: str = "unknown"

    @abstractmethod
    def complete(self, system_prompt: str, user_prompt: str) -> ProviderResponse:
        """Return the model's raw response. Must not raise."""

    @property
    def configured(self) -> bool:
        return True

    @property
    def model_name(self) -> str:
        return ""

    def health(self) -> dict[str, Any]:
        return {
            "provider": self.name,
            "configured": self.configured,
            "model": self.model_name,
        }


# --------------------------------------------------------------------------- parsing
_FENCE = re.compile(r"```(?:json)?\s*(.*?)```", re.DOTALL)


def parse_json_response(text: str) -> dict[str, Any] | None:
    """Extract the JSON object from a provider response.

    Models wrap JSON in prose or a markdown fence often enough that refusing to
    handle it would make the integration fragile for no benefit. Anything that
    still cannot be parsed returns ``None``, and the caller records a malformed
    response rather than guessing at what the model meant.
    """
    if not text:
        return None

    candidate = text.strip()

    fenced = _FENCE.search(candidate)
    if fenced:
        candidate = fenced.group(1).strip()

    try:
        parsed = json.loads(candidate)
        return parsed if isinstance(parsed, dict) else None
    except json.JSONDecodeError:
        pass

    # Fall back to the outermost brace pair.
    start = candidate.find("{")
    end = candidate.rfind("}")
    if start == -1 or end <= start:
        return None
    try:
        parsed = json.loads(candidate[start : end + 1])
    except json.JSONDecodeError:
        return None
    return parsed if isinstance(parsed, dict) else None
