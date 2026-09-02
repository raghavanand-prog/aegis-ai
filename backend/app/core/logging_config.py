"""Structured logging.

Every log line carries the request id, the acting user and the operation, so a
single incident can be traced end to end across the API, the telemetry
collector and the WebSocket layer. JSON is the default because these lines are
meant to be shipped somewhere and queried; `LOG_FORMAT=console` gives readable
output while developing.
"""

from __future__ import annotations

import json
import logging
import sys
from contextvars import ContextVar
from datetime import datetime, timezone
from typing import Any

from app.core.config import settings

# Per-request context, set by RequestContextMiddleware and read by the formatter.
request_id_var: ContextVar[str | None] = ContextVar("request_id", default=None)
user_var: ContextVar[str | None] = ContextVar("current_user", default=None)
operation_var: ContextVar[str | None] = ContextVar("operation", default=None)

_RESERVED = {
    "args", "asctime", "created", "exc_info", "exc_text", "filename", "funcName",
    "levelname", "levelno", "lineno", "module", "msecs", "message", "msg", "name",
    "pathname", "process", "processName", "relativeCreated", "stack_info",
    "thread", "threadName", "taskName",
}


class JsonFormatter(logging.Formatter):
    """Renders records as one JSON object per line."""

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "timestamp": datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat(),
            "severity": record.levelname,
            "service": "aegisx-backend",
            "environment": settings.environment,
            "logger": record.name,
            "message": record.getMessage(),
        }

        request_id = request_id_var.get()
        if request_id:
            payload["requestId"] = request_id

        user = user_var.get()
        if user:
            payload["user"] = user

        operation = operation_var.get()
        if operation:
            payload["operation"] = operation

        # Anything passed via logger.info(..., extra={...}) is merged in.
        for key, value in record.__dict__.items():
            if key not in _RESERVED and not key.startswith("_"):
                payload[key] = value

        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)

        return json.dumps(payload, default=str)


class ConsoleFormatter(logging.Formatter):
    """Human readable format for local development."""

    def format(self, record: logging.LogRecord) -> str:
        request_id = request_id_var.get()
        prefix = f"[{request_id[:8]}] " if request_id else ""
        base = (
            f"{datetime.fromtimestamp(record.created, tz=timezone.utc).strftime('%H:%M:%S')} "
            f"{record.levelname:<8} {prefix}{record.name}: {record.getMessage()}"
        )
        if record.exc_info:
            base = f"{base}\n{self.formatException(record.exc_info)}"
        return base


def configure_logging() -> None:
    """Install the configured formatter on the root logger."""
    formatter: logging.Formatter = (
        JsonFormatter() if settings.log_format.lower() == "json" else ConsoleFormatter()
    )

    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(formatter)

    root = logging.getLogger()
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(settings.log_level.upper())

    # uvicorn ships its own handlers; route them through ours so every line has
    # the same shape.
    for name in ("uvicorn", "uvicorn.error", "uvicorn.access"):
        uvicorn_logger = logging.getLogger(name)
        uvicorn_logger.handlers.clear()
        uvicorn_logger.propagate = True

    # SQLAlchemy is chatty at INFO when echo is on.
    logging.getLogger("sqlalchemy.engine").setLevel(
        logging.INFO if settings.db_echo else logging.WARNING
    )


def bind_request(request_id: str, user: str | None = None, operation: str | None = None) -> None:
    request_id_var.set(request_id)
    if user is not None:
        user_var.set(user)
    if operation is not None:
        operation_var.set(operation)


def bind_user(user: str | None) -> None:
    user_var.set(user)


def clear_request_context() -> None:
    request_id_var.set(None)
    user_var.set(None)
    operation_var.set(None)
