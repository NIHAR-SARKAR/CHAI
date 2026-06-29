"""Base tool class for all security testing tools."""
import logging
from abc import ABC, abstractmethod
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)


class BaseTool(ABC):
    """Base class for all security tools."""

    def __init__(self, session_manager, process_controller, safety_policy, audit_logger, fallback_engine=None):
        self._session = session_manager
        self._process = process_controller
        self._safety = safety_policy
        self._audit = audit_logger
        self._fallback = fallback_engine

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
        """Execute a command with safety validation, audit logging, and fallback recovery."""
        logger.info(f"[EXEC] === START command='{command[:120]}' tool={self.tool_name} session={session_id} ===")

        # Validate command
        logger.info(f"[EXEC] Validating safety policy...")
        policy_result = await self._safety.validate(command, session_id)
        approved = policy_result["approved"]
        reason = policy_result.get("reason", "")
        tier = policy_result.get("tier", "?")
        max_to = policy_result.get("max_timeout", 300)
        logger.info(f"[EXEC] Safety: approved={approved}, tier={tier}, max_timeout={max_to}, reason='{reason[:80]}'")

        if not approved:
            logger.warning(f"[EXEC] BLOCKED by safety policy: {reason}")
            self._audit.log_security_event(
                session_id=session_id,
                event_type="command_blocked",
                description=f"Command blocked by safety policy: {reason}",
                severity="warning",
                details={"command": command, "reason": reason},
            )
            return {
                "stdout": "",
                "stderr": f"Blocked by safety policy: {reason}",
                "returncode": -1,
                "blocked": True,
            }

        modified_cmd = policy_result.get("modified_command", command)
        effective_timeout = timeout or max_to
        logger.info(f"[EXEC] Running: '{modified_cmd[:120]}...' timeout={effective_timeout}s sandbox={sandbox_level}")

        # Execute command
        result = await self._process.run(
            command=modified_cmd,
            session_id=session_id,
            timeout=effective_timeout,
            sandbox_level=sandbox_level,
        )

        rc = result.get("returncode", "?")
        dur = result.get("duration_ms", "?")
        pid = result.get("pid", "?")
        stdout_preview = result.get("stdout", "")[:200].replace("\n", " ")
        stderr_preview = result.get("stderr", "")[:200].replace("\n", " ")
        logger.info(f"[EXEC] Result: returncode={rc}, duration={dur}ms, pid={pid}")
        logger.info(f"[EXEC] stdout_preview: {stdout_preview}")
        if stderr_preview:
            logger.info(f"[EXEC] stderr_preview: {stderr_preview}")

        # Log audit
        self._audit.log_command(session_id, command, result)

        # ── Fallback & self-recovery ──
        is_failure = (
            result.get("returncode", 0) != 0
            or result.get("timeout", False)
            or result.get("error", "")
        )

        if is_failure and self._fallback is not None:
            logger.info(f"[EXEC] Execution failed (rc={rc}) — triggering fallback recovery")
            result = await self._fallback.handle_failure(
                command=command,
                original_result=result,
                tool_name=self.tool_name,
                session_id=session_id,
                timeout=effective_timeout,
                sandbox_level=sandbox_level,
            )
            rc = result.get("returncode", "?")
            recovered = result.get("_recovered", False)
            logger.info(f"[EXEC] Fallback result: recovered={recovered}, rc={rc}")
            if result.get("_recovery_logs"):
                recovered = result.get("_recovered", False)
                self._audit.log_security_event(
                    session_id=session_id,
                    event_type="fallback_recovery",
                    description=f"Fallback recovery {'succeeded' if recovered else 'failed'}",
                    severity="info" if recovered else "warning",
                    details={
                        "tool": self.tool_name,
                        "recovered": recovered,
                        "logs": result.get("_recovery_logs"),
                    },
                )

        logger.info(f"[EXEC] === END rc={rc} ===")
        return result
