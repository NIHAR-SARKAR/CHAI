"""Tests for core.fallback_engine error analysis and recovery behavior."""
import pytest
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from core.fallback_engine import FallbackEngine, RecoveryLog


class MockConfig:
    class WSLConfig:
        enabled = False
        distro_name = ""
        username = ""
        password = ""
        ssh_key_path = ""
        os_details = ""
        use_ssh = False
        auto_install_missing = False
        mount_path_prefix = "/mnt"
        default_shell = "bash"

    wsl = WSLConfig()


class MockProcessController:
    def __init__(self, responses=None):
        self._responses = responses or []
        self.calls = []

    async def run(self, command, session_id, timeout, sandbox_level="none"):
        self.calls.append({"command": command, "session_id": session_id, "timeout": timeout})
        if self._responses:
            return self._responses.pop(0)
        return {"stdout": "", "stderr": "", "returncode": 0}


class MockSafetyPolicy:
    async def validate(self, command, session_id):
        return {"approved": True, "modified_command": command, "tier": "tier1", "max_timeout": 300}


class MockWSLAdapter:
    def __init__(self, active=False):
        self._active = active

    def is_active(self):
        return self._active

    async def run(self, command, session_id, timeout):
        return {"stdout": "", "stderr": "", "returncode": 0}


def make_engine(process_responses=None, wsl_active=False):
    return FallbackEngine(
        config=MockConfig(),
        process_controller=MockProcessController(process_responses),
        safety_policy=MockSafetyPolicy(),
        wsl_adapter=MockWSLAdapter(active=wsl_active),
        max_retries=2,
    )


class TestErrorAnalysis:
    @pytest.mark.asyncio
    async def test_extracts_ffuf_from_command_not_found(self):
        engine = make_engine()
        result = {"stderr": "bash: line 1: ffuf: command not found", "stdout": "", "returncode": 127}
        analysis = engine._analyze_error("ffuf -w wordlist.txt -u target", result, "recon")
        assert analysis["category"] == "missing_tool"
        assert analysis["missing_tool"] == "ffuf"

    @pytest.mark.asyncio
    async def test_extracts_binary_from_command_not_found_suffix(self):
        engine = make_engine()
        result = {"stderr": "command not found: nuclei", "stdout": "", "returncode": 127}
        analysis = engine._analyze_error("nuclei -u target", result, "scan")
        assert analysis["category"] == "missing_tool"
        assert analysis["missing_tool"] == "nuclei"

    @pytest.mark.asyncio
    async def test_extracts_binary_from_command_when_stderr_empty(self):
        engine = make_engine()
        result = {"stderr": "", "stdout": "", "returncode": 127, "error": "gobuster: command not found"}
        analysis = engine._analyze_error("gobuster dir -u target -w list.txt", result, "recon")
        assert analysis["category"] == "missing_tool"
        assert analysis["missing_tool"] == "gobuster"

    @pytest.mark.asyncio
    async def test_permission_error_category(self):
        engine = make_engine()
        result = {"stderr": "permission denied", "stdout": "", "returncode": 13}
        analysis = engine._analyze_error("nmap target", result, "scan")
        assert analysis["category"] == "permission_error"


class TestFixExtraction:
    @pytest.mark.asyncio
    async def test_wsl_install_uses_correct_missing_binary(self):
        engine = make_engine(wsl_active=True)
        analysis = {"category": "missing_tool", "missing_tool": "ffuf"}
        fixes = engine._extract_fixes([], analysis)
        wsl_fixes = [f for f in fixes if f.get("type") == "wsl_install_package"]
        assert len(wsl_fixes) == 1
        assert wsl_fixes[0]["package"] == "ffuf"
        assert "apt-get install -y ffuf" in wsl_fixes[0]["command"]
        assert wsl_fixes[0].get("timeout") == 25
        assert "apt-get update" not in wsl_fixes[0]["command"]

    @pytest.mark.asyncio
    async def test_install_timeout_is_capped(self):
        engine = make_engine()
        analysis = {"category": "missing_tool", "missing_tool": "nmap"}
        fixes = engine._extract_fixes([], analysis)
        install_fixes = [f for f in fixes if f.get("type") == "install_package"]
        assert install_fixes
        assert install_fixes[0].get("timeout") == 25


class TestHandleFailure:
    @pytest.mark.asyncio
    async def test_missing_tool_tries_install_and_retries(self):
        engine = make_engine(process_responses=[
            # install fix succeeds
            {"stdout": "", "stderr": "", "returncode": 0},
            # retry of original command succeeds
            {"stdout": "results", "stderr": "", "returncode": 0},
        ])
        original = {"stderr": "bash: line 1: ffuf: command not found", "stdout": "", "returncode": 127}

        result = await engine.handle_failure(
            command="ffuf -w list.txt -u target",
            original_result=original,
            tool_name="recon",
            session_id="sess-1",
        )

        assert result.get("_recovered") is True
        assert result.get("returncode") == 0
        assert any("apt-get install -y ffuf" in c["command"] for c in engine._process.calls)

    @pytest.mark.asyncio
    async def test_no_retry_when_fix_fails(self):
        engine = make_engine(process_responses=[
            # install fix fails
            {"stdout": "", "stderr": "E: Unable to locate package ffuf", "returncode": 100},
        ])
        original = {"stderr": "bash: line 1: ffuf: command not found", "stdout": "", "returncode": 127}

        result = await engine.handle_failure(
            command="ffuf -w list.txt -u target",
            original_result=original,
            tool_name="recon",
            session_id="sess-1",
        )

        # Fix failed, so original command should NOT be retried.
        assert result.get("_recovered") is False
        assert len([c for c in engine._process.calls if "ffuf -w" in c["command"]]) == 0
        assert "_recovery_logs" in result

    @pytest.mark.asyncio
    async def test_retry_budget_prevents_infinite_loops(self):
        engine = make_engine()
        command = "ffuf -w list.txt -u target"
        original = {"stderr": "bash: line 1: ffuf: command not found", "stdout": "", "returncode": 127}

        # Exhaust retry budget
        for _ in range(engine._max_retries + 1):
            result = await engine.handle_failure(
                command=command,
                original_result=original,
                tool_name="recon",
                session_id="sess-1",
            )

        assert result.get("_recovered") is False
        budget_log = [log for log in result.get("_recovery_logs", []) if log.get("step") == "retry_budget_check"]
        assert budget_log
