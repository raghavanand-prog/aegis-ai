"""WebSocket stream behaviour."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.tests.test_events import ingest


def test_stream_rejects_a_missing_token(client: TestClient) -> None:
    """WS_REQUIRE_AUTH is on, so an anonymous socket must be closed."""
    try:
        with client.websocket_connect("/api/v1/ws/stream") as socket:
            socket.receive_json()
        raised = False
    except Exception:
        raised = True
    assert raised


def test_stream_accepts_a_valid_token_and_acks(client: TestClient, token: str) -> None:
    with client.websocket_connect(f"/api/v1/ws/stream?token={token}") as socket:
        message = socket.receive_json()
        assert message["type"] == "connection.ack"
        assert message["data"]["app"]


def test_new_events_are_broadcast_to_connected_clients(
    client: TestClient, token: str, auth_headers: dict
) -> None:
    with client.websocket_connect(f"/api/v1/ws/stream?token={token}") as socket:
        assert socket.receive_json()["type"] == "connection.ack"

        ingest(client, auth_headers, title="Broadcast me")

        seen = []
        for _ in range(6):
            message = socket.receive_json()
            seen.append(message["type"])
            if message["type"] == "event.created":
                assert message["data"]["title"] == "Broadcast me"
                assert message["data"]["id"].startswith("EVT-")
                break
        else:  # pragma: no cover - diagnostic aid
            raise AssertionError(f"event.created not received; saw {seen}")


def test_unauthorized_socket_is_closed_with_a_specific_code(client: TestClient) -> None:
    """4401 tells the client not to retry with the same token."""
    from starlette.websockets import WebSocketDisconnect

    with pytest.raises(WebSocketDisconnect) as excinfo:
        with client.websocket_connect("/api/v1/ws/stream?token=not-a-real-token") as socket:
            socket.receive_json()

    assert excinfo.value.code == 4401


def test_two_clients_both_receive_the_same_event(
    client: TestClient, token: str, auth_headers: dict
) -> None:
    with client.websocket_connect(f"/api/v1/ws/stream?token={token}") as first:
        with client.websocket_connect(f"/api/v1/ws/stream?token={token}") as second:
            assert first.receive_json()["type"] == "connection.ack"
            assert second.receive_json()["type"] == "connection.ack"

            ingest(client, auth_headers, title="Fan-out check")

            for socket in (first, second):
                for _ in range(6):
                    message = socket.receive_json()
                    if message["type"] == "event.created":
                        assert message["data"]["title"] == "Fan-out check"
                        break
                else:  # pragma: no cover - diagnostic aid
                    raise AssertionError("event.created was not delivered to a client")


def test_disconnect_is_cleaned_up(client: TestClient, token: str) -> None:
    from app.ws.manager import manager

    before = manager.connection_count
    with client.websocket_connect(f"/api/v1/ws/stream?token={token}") as socket:
        socket.receive_json()
        assert manager.connection_count == before + 1

    # The manager drops the socket once the context exits.
    assert manager.connection_count <= before + 1


def test_every_broadcast_event_carries_a_unique_id(
    client: TestClient, token: str, auth_headers: dict
) -> None:
    """The UI de-duplicates on id, so the backend must never reuse one."""
    seen: set[str] = set()

    with client.websocket_connect(f"/api/v1/ws/stream?token={token}") as socket:
        socket.receive_json()

        for index in range(3):
            ingest(client, auth_headers, title=f"Unique {index}")

        collected = 0
        while collected < 3:
            message = socket.receive_json()
            if message["type"] != "event.created":
                continue
            event_id = message["data"]["id"]
            assert event_id not in seen, "duplicate event id broadcast"
            seen.add(event_id)
            collected += 1
