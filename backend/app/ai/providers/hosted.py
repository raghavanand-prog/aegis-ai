"""Hosted LLM providers (OpenAI, Anthropic).

Both speak the same shape - system prompt, user prompt, text back - so they
share one base class and differ only in the request they build and the response
they unwrap. Adding a third hosted vendor, or a local server exposing an
OpenAI-compatible API, is a subclass and a dictionary entry.

Operational rules both providers hold to:

* The API key is read from server configuration, sent in a header, and never
  placed in a log line, an error message, a response body or an exception.
* Every failure - timeout, rate limit, refusal, malformed body - comes back as
  ``ProviderResponse.failure``. Nothing raises into the caller.
* ``max_tokens`` and ``timeout`` are bounded by configuration, so one request
  cannot run away with the bill or hold a worker open.
* Temperature is fixed low. This is an analysis task over supplied evidence;
  creative variation is a defect here, not a feature.

**Data leaving the estate.** Using a hosted provider sends the evidence package
- hostnames, usernames, addresses, command lines - to a third party. That is a
deliberate operator decision, which is why the default provider is ``mock`` and
why this is documented in docs/ai-architecture.md rather than buried.
"""

from __future__ import annotations

import logging
from time import perf_counter
from typing import Any

from app.ai.base import AIAnalystProvider, ProviderResponse
from app.core.config import settings

logger = logging.getLogger(__name__)

#: Low but not zero: fully deterministic decoding makes some models repetitive
#: and prone to falling into a template.
TEMPERATURE = 0.2


class _HostedProvider(AIAnalystProvider):
    """Shared HTTP plumbing for hosted chat-completion APIs."""

    default_model = ""
    default_base_url = ""

    @property
    def configured(self) -> bool:
        return bool(settings.ai_api_key)

    @property
    def model_name(self) -> str:
        return settings.ai_model or self.default_model

    @property
    def base_url(self) -> str:
        return (settings.ai_base_url or self.default_base_url).rstrip("/")

    # ------------------------------------------------------------- subclasses
    def _endpoint(self) -> str:
        raise NotImplementedError

    def _headers(self) -> dict[str, str]:
        raise NotImplementedError

    def _payload(self, system_prompt: str, user_prompt: str) -> dict[str, Any]:
        raise NotImplementedError

    def _unwrap(self, body: dict[str, Any]) -> tuple[str, int]:
        """Return ``(text, tokens_used)`` from a successful response body."""
        raise NotImplementedError

    # ------------------------------------------------------------------ call
    def complete(self, system_prompt: str, user_prompt: str) -> ProviderResponse:
        if not self.configured:
            return ProviderResponse.failure(
                f"{self.name} is selected but AI_API_KEY is not set",
                model=self.model_name,
            )

        try:
            import httpx
        except ImportError:  # pragma: no cover - httpx ships with the backend
            return ProviderResponse.failure("httpx is not installed", model=self.model_name)

        started = perf_counter()
        try:
            with httpx.Client(timeout=settings.ai_timeout_seconds, follow_redirects=False) as client:
                response = client.post(
                    f"{self.base_url}{self._endpoint()}",
                    headers=self._headers(),
                    json=self._payload(system_prompt, user_prompt),
                )
        except httpx.TimeoutException:
            elapsed = (perf_counter() - started) * 1000.0
            logger.warning("AI provider %s timed out after %.0fms", self.name, elapsed)
            return ProviderResponse.failure(
                f"{self.name} timed out after {settings.ai_timeout_seconds:.0f}s",
                model=self.model_name,
                latency_ms=elapsed,
            )
        except Exception as exc:  # noqa: BLE001 - the analyst is optional, always
            elapsed = (perf_counter() - started) * 1000.0
            logger.warning("AI provider %s failed: %s", self.name, type(exc).__name__)
            return ProviderResponse.failure(
                f"{self.name} request failed ({type(exc).__name__})",
                model=self.model_name,
                latency_ms=elapsed,
            )

        elapsed = (perf_counter() - started) * 1000.0

        if response.status_code == 429:
            return ProviderResponse.failure(
                f"{self.name} rate limit reached", model=self.model_name, latency_ms=elapsed
            )
        if response.status_code in (401, 403):
            # Never echo the key, its prefix, or the provider's message, which
            # can contain request context.
            return ProviderResponse.failure(
                f"{self.name} rejected the configured credentials",
                model=self.model_name,
                latency_ms=elapsed,
            )
        if response.status_code >= 400:
            return ProviderResponse.failure(
                f"{self.name} returned HTTP {response.status_code}",
                model=self.model_name,
                latency_ms=elapsed,
            )

        try:
            body = response.json()
            text, tokens = self._unwrap(body)
        except Exception:  # noqa: BLE001
            return ProviderResponse.failure(
                f"{self.name} returned a response this build could not read",
                model=self.model_name,
                latency_ms=elapsed,
            )

        if not text.strip():
            return ProviderResponse.failure(
                f"{self.name} returned an empty completion",
                model=self.model_name,
                latency_ms=elapsed,
            )

        return ProviderResponse(
            ok=True,
            text=text,
            model=self.model_name,
            tokens_used=tokens,
            latency_ms=elapsed,
        )


class OpenAIProvider(_HostedProvider):
    name = "openai"
    default_model = "gpt-4o-mini"
    default_base_url = "https://api.openai.com/v1"

    def _endpoint(self) -> str:
        return "/chat/completions"

    def _headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {settings.ai_api_key}",
            "Content-Type": "application/json",
        }

    def _payload(self, system_prompt: str, user_prompt: str) -> dict[str, Any]:
        return {
            "model": self.model_name,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            "temperature": TEMPERATURE,
            "max_tokens": settings.ai_max_output_tokens,
            # Guarantees parseable output, which removes a whole class of
            # "the model wrapped it in prose" failures.
            "response_format": {"type": "json_object"},
        }

    def _unwrap(self, body: dict[str, Any]) -> tuple[str, int]:
        text = body["choices"][0]["message"]["content"] or ""
        tokens = int((body.get("usage") or {}).get("total_tokens", 0) or 0)
        return text, tokens


class AnthropicProvider(_HostedProvider):
    name = "anthropic"
    default_model = "claude-sonnet-4-5"
    default_base_url = "https://api.anthropic.com/v1"

    def _endpoint(self) -> str:
        return "/messages"

    def _headers(self) -> dict[str, str]:
        return {
            "x-api-key": settings.ai_api_key,
            "anthropic-version": "2023-06-01",
            "Content-Type": "application/json",
        }

    def _payload(self, system_prompt: str, user_prompt: str) -> dict[str, Any]:
        return {
            "model": self.model_name,
            "system": system_prompt,
            "messages": [{"role": "user", "content": user_prompt}],
            "temperature": TEMPERATURE,
            "max_tokens": settings.ai_max_output_tokens,
        }

    def _unwrap(self, body: dict[str, Any]) -> tuple[str, int]:
        blocks = body.get("content") or []
        text = "".join(
            block.get("text", "") for block in blocks if block.get("type") == "text"
        )
        usage = body.get("usage") or {}
        tokens = int(usage.get("input_tokens", 0) or 0) + int(
            usage.get("output_tokens", 0) or 0
        )
        return text, tokens
