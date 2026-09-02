"""HTTP middleware: request context, security headers, rate limiting, body size.

Ordering matters. Starlette runs middleware in reverse registration order, so
`main.py` registers these such that every request - including one rejected by
the rate limiter - still gets a request id and security headers.
"""

from __future__ import annotations

import logging
import time
import uuid
from collections import defaultdict, deque
from threading import Lock

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from app.core.config import settings
from app.core.logging_config import bind_request, clear_request_context

logger = logging.getLogger(__name__)

REQUEST_ID_HEADER = "X-Request-ID"

#: Paths that must stay cheap and quiet: probes and docs.
QUIET_PATHS = {"/api/v1/health", "/api/v1/health/ready", "/metrics", "/favicon.ico"}


class RequestContextMiddleware(BaseHTTPMiddleware):
    """Assigns a request id, times the request and logs one structured line."""

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        incoming = request.headers.get(REQUEST_ID_HEADER)
        # An inbound id is echoed so a trace can span the proxy, but it is
        # bounded and sanitised - it ends up in logs.
        request_id = (
            "".join(ch for ch in incoming if ch.isalnum() or ch in "-_")[:64]
            if incoming
            else uuid.uuid4().hex
        )

        operation = f"{request.method} {request.url.path}"
        bind_request(request_id, operation=operation)
        request.state.request_id = request_id

        started = time.perf_counter()
        try:
            response = await call_next(request)
        except Exception:
            duration_ms = (time.perf_counter() - started) * 1000
            logger.exception(
                "request failed",
                extra={
                    "method": request.method,
                    "path": request.url.path,
                    "durationMs": round(duration_ms, 2),
                    "result": "error",
                },
            )
            clear_request_context()
            raise

        duration_ms = (time.perf_counter() - started) * 1000
        response.headers[REQUEST_ID_HEADER] = request_id

        if request.url.path not in QUIET_PATHS:
            logger.info(
                "request completed",
                extra={
                    "method": request.method,
                    "path": request.url.path,
                    "status": response.status_code,
                    "durationMs": round(duration_ms, 2),
                    "result": "ok" if response.status_code < 400 else "error",
                    "clientIp": request.client.host if request.client else None,
                },
            )

        clear_request_context()
        return response


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Adds defensive response headers.

    The API serves JSON, not HTML, so the CSP is deliberately restrictive: a
    response that somehow renders in a browser should be able to do nothing.
    The SPA is served separately and carries its own policy.
    """

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        response = await call_next(request)

        if not settings.security_headers_enabled:
            return response

        headers = response.headers
        headers.setdefault("X-Content-Type-Options", "nosniff")
        headers.setdefault("X-Frame-Options", "DENY")
        headers.setdefault("Referrer-Policy", "no-referrer")
        headers.setdefault("Cross-Origin-Opener-Policy", "same-origin")
        headers.setdefault("Cross-Origin-Resource-Policy", "same-origin")
        headers.setdefault("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
        headers.setdefault(
            "Content-Security-Policy",
            "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'",
        )
        headers.setdefault("Cache-Control", "no-store")

        # Only meaningful over TLS; sending it on plain HTTP does nothing.
        if request.url.scheme == "https":
            headers.setdefault(
                "Strict-Transport-Security",
                f"max-age={settings.hsts_max_age_seconds}; includeSubDomains",
            )

        return response


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Sliding-window rate limiting, per client address.

    Authentication gets its own much tighter bucket: it is the endpoint worth
    brute forcing, and a generic limit large enough for a busy SOC UI would be
    useless there.

    Limitation, stated rather than hidden: counters live in this process, so
    with several workers the effective limit is multiplied. A shared store is
    the fix when AEGISX runs on more than one process.
    """

    AUTH_PATHS = ("/auth/login", "/auth/users")

    def __init__(self, app) -> None:  # noqa: ANN001 - starlette signature
        super().__init__(app)
        self._hits: dict[str, deque[float]] = defaultdict(deque)
        self._lock = Lock()

    def _client_key(self, request: Request) -> str:
        forwarded = request.headers.get("x-forwarded-for")
        if forwarded:
            return forwarded.split(",")[0].strip()
        return request.client.host if request.client else "unknown"

    def _limits(self, path: str) -> tuple[int, int, str]:
        if any(path.endswith(auth_path) for auth_path in self.AUTH_PATHS):
            return (
                settings.auth_rate_limit_requests,
                settings.auth_rate_limit_window_seconds,
                "auth",
            )
        return settings.rate_limit_requests, settings.rate_limit_window_seconds, "default"

    def _allow(self, key: str, limit: int, window: int) -> tuple[bool, int]:
        now = time.monotonic()
        with self._lock:
            hits = self._hits[key]
            cutoff = now - window
            while hits and hits[0] < cutoff:
                hits.popleft()
            if len(hits) >= limit:
                retry_after = max(1, int(window - (now - hits[0])))
                return False, retry_after
            hits.append(now)
            return True, 0

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        if not settings.rate_limit_enabled or request.url.path in QUIET_PATHS:
            return await call_next(request)

        limit, window, bucket = self._limits(request.url.path)
        key = f"{bucket}:{self._client_key(request)}"
        allowed, retry_after = self._allow(key, limit, window)

        if not allowed:
            logger.warning(
                "rate limit exceeded",
                extra={
                    "path": request.url.path,
                    "bucket": bucket,
                    "clientIp": self._client_key(request),
                    "result": "rate_limited",
                },
            )
            return JSONResponse(
                status_code=429,
                content={"detail": "Too many requests. Slow down and try again shortly."},
                headers={"Retry-After": str(retry_after)},
            )

        return await call_next(request)


class BodySizeLimitMiddleware(BaseHTTPMiddleware):
    """Rejects oversized request bodies before they are parsed."""

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        content_length = request.headers.get("content-length")
        if content_length:
            try:
                if int(content_length) > settings.max_request_bytes:
                    return JSONResponse(
                        status_code=413,
                        content={"detail": "Request body is too large."},
                    )
            except ValueError:
                return JSONResponse(status_code=400, content={"detail": "Invalid Content-Length."})

        return await call_next(request)
