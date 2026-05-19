"""Base tool class for all security testing tools."""
import logging
from abc import ABC, abstractmethod
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)


class BaseTool(ABC):
    """Base class for all security tools."""

    def __init__(self, session_manager, process_controller, safety_policy, audit_logger):
        self._session = session_manager
        self._process = process_controller
        self._safety = safety_policy
        self._audit = audit_logger

    @property
    @abstractmethod
    def tool_name(self) -> str:
        """Return the tool name."""
        ...

    @property
    @abstractmethod
    def description(self) -> str:
        """Return the tool description."""
        ...

    async def _execute(self, command: str, session_id: str, timeout: Optional[int] = None, sandbox_level: str = "firejail") -> Dict[str, Any]:
        """Execute a command with safety validation and audit logging."""
        # Validate command
        policy_result = await self._safety.validate(command, session_id)
        if not policy_result["approved"]:
            self._audit.log_security_event(
                session_id=session_id,
                event_type="command_blocked",
                description=f"Command blocked by safety policy: {policy_result['reason']}",
                severity="warning",
                details={"command": command, "reason": policy_result["reason"]},
            )
            return {
                "stdout": "",
                "stderr": f"Blocked by safety policy: {policy_result['reason']}",
                "returncode": -1,
                "blocked": True,
            }

        # Execute command
        result = await self._process.run(
            command=policy_result.get("modified_command", command),
            session_id=session_id,
            timeout=timeout or policy_result.get("max_timeout", 300),
            sandbox_level=sandbox_level,
        )

        # Log audit
        self._audit.log_command(session_id, command, result)

        return result
