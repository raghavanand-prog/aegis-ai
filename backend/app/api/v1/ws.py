"""WebSocket live stream.

Clients receive envelopes of the form::

    {"type": "event.created", "data": {...}, "ts": "2026-09-01T10:00:00+00:00"}

Message types: ``connection.ack``, ``event.created``, ``event.updated``,
``incident.created``, ``incident.updated``, ``notification.created``,
``heartbeat``.
"""

from __future__ import annotations

import asyncio
import logging

from fastapi import APIRouter, Query, WebSocket, WebSocketDisconnect

from app.core.config import settings
from app.core.security import TokenError, decode_access_token
from app.ws.manager import manager

logger = logging.getLogger(__name__)

router = APIRouter(tags=["realtime"])

# Close codes (application range).
WS_UNAUTHORIZED = 4401


@router.websocket("/ws/stream")
async def stream(websocket: WebSocket, token: str | None = Query(default=None)) -> None:
    """Live event/incident/notification stream for the SOC UI.

    Browsers cannot set headers on a WebSocket handshake, so the access token
    is passed as a query parameter and validated before the socket is accepted.
    """
    if settings.ws_require_auth:
        try:
            decode_access_token(token or "")
        except TokenError as exc:
            logger.info("Rejected WebSocket connection: %s", exc)
            await websocket.close(code=WS_UNAUTHORIZED, reason="Invalid or missing token")
            return

    await manager.connect(websocket)
    try:
        await websocket.send_json(
            {
                "type": "connection.ack",
                "data": {
                    "app": settings.app_name,
                    "version": settings.app_version,
                    "heartbeatSeconds": settings.ws_heartbeat_seconds,
                },
            }
        )

        while True:
            try:
                message = await asyncio.wait_for(
                    websocket.receive_text(), timeout=settings.ws_heartbeat_seconds
                )
            except asyncio.TimeoutError:
                # Idle: prove liveness so proxies do not silently drop the socket.
                await websocket.send_json({"type": "heartbeat", "data": None})
                continue

            if message == "ping":
                await websocket.send_json({"type": "pong", "data": None})

    except WebSocketDisconnect:
        pass
    except Exception:  # noqa: BLE001 - never let one socket take down the server
        logger.exception("WebSocket stream error")
    finally:
        await manager.disconnect(websocket)
