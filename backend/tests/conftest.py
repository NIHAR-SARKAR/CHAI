"""Shared fixtures for CHAI test suite."""
import asyncio
import os
import sys
import tempfile
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))


@pytest.fixture
def event_loop():
    """Create an event loop for async tests."""
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()


@pytest.fixture
def tmp_dir():
    """Provide a temporary directory."""
    with tempfile.TemporaryDirectory() as d:
        yield d


@pytest.fixture
def mock_config():
    """Provide a mock configuration object."""
    config = MagicMock()
    config.server = MagicMock()
    config.server.transport = "stdio"
    config.server.sse_port = 9010
    config.server.log_level = "info"

    config.paths = MagicMock()
    config.paths.kb_path = tempfile.mkdtemp()
    config.paths.session_db = os.path.join(tempfile.mkdtemp(), "sessions.db")
    config.paths.sandbox_user = "pentester"
    config.paths.firejail_profile = "/etc/firejail/pentest.profile"
    config.paths.audit_log_path = os.path.join(tempfile.mkdtemp(), "audit.log")
    config.paths.reports_path = tempfile.mkdtemp()
    config.paths.plugins_path = tempfile.mkdtemp()

    config.sandbox = MagicMock()
    config.sandbox.max_ram_mb = 384
    config.sandbox.max_cpu_percent = 50
    config.sandbox.max_concurrent_jobs = 2
    config.sandbox.command_timeout = 300

    config.llm = MagicMock()
    config.llm.enabled = True
    config.llm.active_provider = "openai"
    config.llm.fallback_provider = ""
    config.llm.max_tokens = 1000
    config.llm.temperature = 0.1
    config.llm.timeout_seconds = 30
    config.llm.max_retries = 2
    config.llm.openai = MagicMock()
    config.llm.openai.enabled = True
    config.llm.openai.api_base = "https://api.openai.com/v1"
    config.llm.openai.model = "gpt-4.1"

    config.ai_planner = MagicMock()
    config.ai_planner.max_phases = 4
    config.ai_planner.stop_on_critical = True
    config.ai_planner.use_graph_prefilter = True
    config.ai_planner.include_ai_narrative = True

    config.plugins = MagicMock()
    config.plugins.enabled = False
    config.plugins.auto_discover = False

    return config


@pytest.fixture
def mock_session_manager():
    """Provide a mock session manager."""
    sm = AsyncMock()
    sm.create_session = AsyncMock(return_value="sess-test-123")
    sm.get_session = AsyncMock(return_value=None)
    sm.update_session_status = AsyncMock()
    sm.add_finding = AsyncMock(return_value="find-test-123")
    sm.get_findings = AsyncMock(return_value=[])
    sm.get_running_pids = AsyncMock(return_value=[])
    sm.record_ai_decision = AsyncMock(return_value="ai-test-123")
    sm.get_ai_decisions = AsyncMock(return_value=[])
    sm.initialize = AsyncMock()
    return sm


@pytest.fixture
def mock_process_controller():
    """Provide a mock process controller."""
    pc = AsyncMock()
    pc.run = AsyncMock(return_value={
        "stdout": "",
        "stderr": "",
        "returncode": 0,
        "duration_ms": 100,
        "pid": 12345,
        "command": "echo test",
        "sandbox_level": "none",
    })
    return pc
