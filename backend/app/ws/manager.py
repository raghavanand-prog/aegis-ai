"""WebSocket connection manager for the live telemetry stream."""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone
from typing import Any

from fastapi import WebSocket

logger = logging.getLogger(__name__)


class ConnectionManager:
    """Tracks connected SOC clients and fans messages out to them.

    A reference to the running event loop is captured at application startup so
    synchronous code (request handlers running in the threadpool) can schedule
    broadcasts safely via :meth:`broadcast_threadsafe`.
    """

    def __init__(self) -> None:
        self._connections: set[WebSocket] = set()
        self._lock = asyncio.Lock()
        self._loop: asyncio.AbstractEventLoop | None = None

    def bind_loop(self, loop: asyncio.AbstractEventLoop) -> None:
        self._loop = loop

    @property
    def connection_count(self) -> int:
        return len(self._connections)

    async def connect(self, websocket: WebSocket) -> None:
        await websocket.accept()
        async with self._lock:
            self._connections.add(websocket)
        logger.info("WebSocket client connected (%d active)", len(self._connections))

    async def disconnect(self, websocket: WebSocket) -> None:
        async with self._lock:
            self._connections.discard(websocket)
        logger.info("WebSocket client disconnected (%d active)", len(self._connections))

    async def broadcast(self, message_type: str, data: Any) -> None:
        """Send an envelope to every connected client, dropping dead sockets."""
        payload = {
            "type": message_type,
            "data": data,
            "ts": datetime.now(timezone.utc).isoformat(),
        }

        async with self._lock:
            targets = list(self._connections)

        stale: list[WebSocket] = []
        for connection in targets:
            try:
                await connection.send_json(payload)
            except Exception:  # noqa: BLE001 - a dead socket must not stop the fan-out
                stale.append(connection)

        if stale:
            async with self._lock:
                for connection in stale:
                    self._connections.discard(connection)
            logger.info("Dropped %d stale WebSocket connection(s)", len(stale))

    def broadcast_threadsafe(self, message_type: str, data: Any) -> None:
        """Schedule a broadcast from synchronous code (e.g. a request handler)."""
        if self._loop is None or self._loop.is_closed():
            logger.debug("No event loop bound; skipping broadcast of %s", message_type)
            return
        try:
            asyncio.run_coroutine_threadsafe(self.broadcast(message_type, data), self._loop)
        except RuntimeError:  # pragma: no cover - loop shutting down
            logger.debug("Event loop unavailable; dropped broadcast of %s", message_type)


manager = ConnectionManager()
