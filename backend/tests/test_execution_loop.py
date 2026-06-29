"""Tests for core.execution_loop — tool dispatch and autonomous flow."""
import pytest
import sys
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

sys.path.insert(0, str(Path(__file__).parent.parent))

from core.execution_loop import ExecutionLoop, TOOL_DISPATCH
from core.session_manager import SessionManager
from models.schemas import ActionPlan, PhaseResult, FinalResult


class TestToolDispatch:
    def test_all_core_tools_registered(self):
        expected_core = [
            "recon_passive", "recon_active", "scan_vulnerabilities",
            "test_injection", "test_authentication", "test_network",
            "generate_poc", "execute_command", "analyze_findings",
        ]
        for tool in expected_core:
            assert tool in TOOL_DISPATCH, f"Core tool '{tool}' missing from TOOL_DISPATCH"

    def test_extended_tools_registered(self):
        extended = [
            "test_xss", "test_ssrf", "test_idor", "test_bola",
            "test_cors", "test_rate_limit", "test_js_secrets",
            "test_mass_assignment", "test_negative_values",
        ]
        for tool in extended:
            assert tool in TOOL_DISPATCH, f"Extended tool '{tool}' missing from TOOL_DISPATCH"

    def test_dispatch_values_are_tuples(self):
        for key, value in TOOL_DISPATCH.items():
            assert isinstance(value, tuple), f"TOOL_DISPATCH['{key}'] is not a tuple"
            assert len(value) == 2, f"TOOL_DISPATCH['{key}'] does not have 2 elements"

    def test_dispatch_modules_are_strings(self):
        for key, (module, method) in TOOL_DISPATCH.items():
            assert isinstance(module, str), f"Module for '{key}' is not a string"
            assert isinstance(method, str), f"Method for '{key}' is not a string"


class TestExecutionLoop:
    @pytest.fixture
    def loop_setup(self):
        mock_tools = {
            "recon": AsyncMock(),
            "scan": AsyncMock(),
            "injection": AsyncMock(),
            "auth": AsyncMock(),
            "network": AsyncMock(),
            "poc": AsyncMock(),
            "exec": AsyncMock(),
            "analyze": AsyncMock(),
            "report": AsyncMock(),
            "xss": AsyncMock(),
            "ssrf": AsyncMock(),
            "access_control": AsyncMock(),
            "api_security": AsyncMock(),
            "misconfig": AsyncMock(),
            "rate_limit": AsyncMock(),
            "sensitive_data": AsyncMock(),
            "business_logic": AsyncMock(),
        }
        mock_tools["recon"].run_passive = AsyncMock(return_value={
            "findings": [], "raw": {}
        })
        mock_tools["analyze"].build_planner_digest = AsyncMock(return_value={
            "target": "test.com", "confirmed_findings": [], "already_tested": [], "scope": []
        })

        config = MagicMock()
        config.ai_planner.stop_on_critical = True
        config.ai_planner.max_phases = 1

        session_mgr = AsyncMock()
        session_mgr.record_ai_decision = AsyncMock()

        return mock_tools, config, session_mgr

    @pytest.mark.asyncio
    async def test_run_phase_with_valid_tool(self, loop_setup):
        tools, config, session_mgr = loop_setup
        loop = ExecutionLoop(tools, None, session_mgr, config)

        plan = ActionPlan(
            session_id="sess-1",
            next_tool="recon_passive",
            args={"target": "test.com"},
            rationale="start recon",
        )
        result = await loop.run_phase("sess-1", plan)
        assert isinstance(result, PhaseResult)

    @pytest.mark.asyncio
    async def test_run_phase_with_invalid_tool(self, loop_setup):
        tools, config, session_mgr = loop_setup
        loop = ExecutionLoop(tools, None, session_mgr, config)

        plan = ActionPlan(
            session_id="sess-1",
            next_tool="nonexistent_tool",
            args={},
            rationale="invalid",
        )
        result = await loop.run_phase("sess-1", plan)
        assert result.error is not None
        assert "Unknown tool" in result.error

    @pytest.mark.asyncio
    async def test_run_phase_with_missing_module(self, loop_setup):
        tools, config, session_mgr = loop_setup
        tools.pop("recon")
        loop = ExecutionLoop(tools, None, session_mgr, config)

        plan = ActionPlan(
            session_id="sess-1",
            next_tool="recon_passive",
            args={},
            rationale="recon",
        )
        result = await loop.run_phase("sess-1", plan)
        assert result.error is not None

    @pytest.mark.asyncio
    async def test_run_phase_persists_findings(self, tmp_path):
        """Findings returned by tools must be saved to the session database."""
        db_path = tmp_path / "test.db"
        session_mgr = SessionManager(str(db_path))
        await session_mgr.initialize()
        session_id = await session_mgr.create_session("http://test.com")

        async def fake_run_passive(session_id: str, target: str, **kwargs):
            return {
                "findings": [{
                    "attack_type": "info_disclosure",
                    "confidence": 0.9,
                    "endpoint": "/api",
                    "evidence": "sensitive file exposed",
                    "status": "confirmed",
                    "cvss_score": 5.0,
                    "severity": "medium",
                }],
                "raw": {},
            }

        import types
        tools = {"recon": types.SimpleNamespace(run_passive=fake_run_passive)}
        config = MagicMock()
        config.ai_planner.stop_on_critical = True
        config.ai_planner.max_phases = 1

        loop = ExecutionLoop(tools, None, session_mgr, config)
        plan = ActionPlan(
            session_id=session_id,
            next_tool="recon_passive",
            args={"target": "http://test.com"},
            rationale="test persistence",
        )
        result = await loop.run_phase(session_id, plan)
        assert len(result.findings) == 1

        findings = await session_mgr.get_findings(session_id)
        assert len(findings) == 1
        assert findings[0].attack_type == "info_disclosure"
        assert findings[0].severity == "medium"
