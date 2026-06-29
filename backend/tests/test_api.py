"""Tests for backend/web/api.py endpoints and helpers."""
import sys
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

sys.path.insert(0, str(Path(__file__).parent.parent))

import pytest

from web.api import _build_tool_args


def test_build_tool_args_maps_scanner():
    args = _build_tool_args("scan_vulnerabilities", "nmap", "test.com")
    assert args == {"target": "test.com", "scanner": "nmap"}


def test_build_tool_args_maps_injection_type():
    args = _build_tool_args("test_injection", "sqli", "test.com")
    assert args == {"target": "test.com", "injection_type": "sqli"}


def test_build_tool_args_maps_xss_type():
    args = _build_tool_args("test_xss", "stored", "test.com")
    assert args == {"target": "test.com", "xss_type": "stored"}


def test_build_tool_args_defaults_to_test_type():
    args = _build_tool_args("test_network", "ssl", "test.com")
    assert args == {"target": "test.com", "test_type": "ssl"}


def test_build_tool_args_no_subtype_for_recon():
    args = _build_tool_args("recon_passive", "", "test.com")
    assert args == {"target": "test.com"}


@pytest.mark.asyncio
async def test_run_tool_endpoint_dispatches_by_tool_name():
    from fastapi.testclient import TestClient
    from web.api import api_app

    mock_tool = AsyncMock()
    mock_tool.run_passive = AsyncMock(return_value={"findings": [], "raw": {}})

    mock_ctx = MagicMock()
    mock_ctx.is_initialized = True
    mock_ctx.tools = {"recon": mock_tool}
    mock_ctx.session_manager = MagicMock()

    with patch("web.api.get_context", return_value=mock_ctx):
        client = TestClient(api_app)
        response = client.post("/api/tools/run", json={
            "session_id": "sess-test",
            "target": "test.com",
            "tool_name": "recon_passive",
        })

    assert response.status_code == 200
    mock_tool.run_passive.assert_awaited_once_with(session_id="sess-test", target="test.com")


@pytest.mark.asyncio
async def test_run_tool_endpoint_returns_404_for_unknown_tool():
    from fastapi.testclient import TestClient
    from web.api import api_app

    mock_ctx = MagicMock()
    mock_ctx.is_initialized = True
    mock_ctx.tools = {}

    with patch("web.api.get_context", return_value=mock_ctx):
        client = TestClient(api_app)
        response = client.post("/api/tools/run", json={
            "session_id": "sess-test",
            "target": "test.com",
            "tool_name": "nonexistent_tool",
        })

    assert response.status_code == 404
