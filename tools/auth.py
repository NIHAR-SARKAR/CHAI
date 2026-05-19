"""Authentication testing tools module."""
import logging
from typing import Dict, Any
from models.session import Finding
from tools.base import BaseTool

logger = logging.getLogger(__name__)


class AuthTools(BaseTool):
    @property
    def tool_name(self) -> str:
        return "auth"

    @property
    def description(self) -> str:
        return "Authentication and authorization testing tools"

    async def run_auth(self, session_id: str, target: str, test_type: str = "bypass", **kwargs) -> Dict[str, Any]:
        """Run authentication tests."""
        findings = []

        if test_type == "bypass":
            # Test for common auth bypass patterns
            cmd = f"curl -s -o /dev/null -w '%{{http_code}}' {target}/admin"
            result = await self._execute(cmd, session_id, timeout=30)

            if result.get("returncode") == 0:
                status_code = result.get("stdout", "").strip()
                if status_code in ["200", "301", "302"]:
                    findings.append(Finding(
                        session_id=session_id,
                        attack_type="auth_bypass",
                        confidence=0.7,
                        endpoint=f"{target}/admin",
                        evidence=f"Admin panel accessible without authentication (HTTP {status_code})",
                        status="potential",
                        cvss_score=8.1,
                        severity="high",
                    ))

        elif test_type == "jwt":
            # JWT analysis
            cmd = f"curl -s {target} -I | grep -i authorization"
            result = await self._execute(cmd, session_id, timeout=30)

            if "Bearer" in result.get("stdout", ""):
                findings.append(Finding(
                    session_id=session_id,
                    attack_type="jwt_detected",
                    confidence=1.0,
                    endpoint=target,
                    evidence="JWT token detected in Authorization header",
                    status="confirmed",
                    cvss_score=0.0,
                    severity="info",
                ))

        return {"findings": [f.model_dump() for f in findings], "raw": {test_type: result}}
