"""Command execution tools module."""
import logging
from typing import Dict, Any
from tools.base import BaseTool

logger = logging.getLogger(__name__)


class ExecTools(BaseTool):
    @property
    def tool_name(self) -> str:
        return "exec"

    @property
    def description(self) -> str:
        return "Custom command execution tools"

    async def run_command(self, session_id: str, command: str, **kwargs) -> Dict[str, Any]:
        """Execute a custom command with safety validation."""
        # Safety policy validation is done in _execute
        result = await self._execute(command, session_id, timeout=kwargs.get("timeout", 300))

        return {
            "findings": [],
            "raw": {"command": command, "result": result},
            "stdout": result.get("stdout", ""),
            "stderr": result.get("stderr", ""),
            "returncode": result.get("returncode", -1),
        }
