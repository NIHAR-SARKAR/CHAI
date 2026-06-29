"""Tests for the WebSocket connection manager and log broadcaster."""
import asyncio
import logging
import sys
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

sys.path.insert(0, str(Path(__file__).parent.parent))

import pytest

from web.ws_manager import ConnectionManager, WebSocketLogHandler, manager


@pytest.mark.asyncio
async def test_connection_manager_broadcast():
    cm = ConnectionManager()
    ws = AsyncMock()
    await cm.connect("sess-abc123", ws)
    await cm.broadcast("sess-abc123", {"type": "log", "message": "hello"})
    ws.send_json.assert_called_once_with({"type": "log", "message": "hello"})


@pytest.mark.asyncio
async def test_connection_manager_removes_dead_socket():
    cm = ConnectionManager()
    ws = AsyncMock()
    ws.send_json.side_effect = RuntimeError("connection closed")
    await cm.connect("sess-abc123", ws)
    await cm.broadcast("sess-abc123", {"type": "log"})
    assert ws not in cm._connections.get("sess-abc123", [])


def test_log_handler_skips_records_without_session():
    handler = WebSocketLogHandler(manager, level=logging.INFO)
    handler.setFormatter(logging.Formatter("%(name)s | %(message)s"))
    record = logging.LogRecord("test", logging.INFO, "", 0, "no session id here", (), None)

    with patch.object(manager, "broadcast", new_callable=AsyncMock) as mock_broadcast:
        with patch("asyncio.create_task") as mock_create_task:
            handler.emit(record)
    mock_create_task.assert_not_called()
    mock_broadcast.assert_not_called()


@pytest.mark.asyncio
async def test_log_handler_broadcasts_session_log():
    handler = WebSocketLogHandler(manager, level=logging.INFO)
    handler.setFormatter(logging.Formatter("%(name)s | %(message)s"))
    record = logging.LogRecord(
        "core.execution_loop",
        logging.INFO,
        "",
        0,
        "[LOOP] phase 1 session=sess-abc123",
        (),
        None,
    )

    mock_loop = MagicMock()
    with patch("web.ws_manager.asyncio.get_running_loop", return_value=mock_loop):
        with patch.object(manager, "broadcast", new_callable=AsyncMock) as mock_broadcast:
            handler.emit(record)
            assert mock_loop.create_task.called
            coro = mock_loop.create_task.call_args[0][0]
            await coro

    mock_broadcast.assert_called_once()
    session_id, payload = mock_broadcast.call_args[0]
    assert session_id == "sess-abc123"
    assert payload["type"] == "log"
    assert "sess-abc123" in payload["message"]
