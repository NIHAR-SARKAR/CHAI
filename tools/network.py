"""Network testing tools module."""
import logging
from typing import Dict, Any
from models.session import Finding
from tools.base import BaseTool

logger = logging.getLogger(__name__)


class NetworkTools(BaseTool):
    @property
    def tool_name(self) -> str:
        return "network"

    @property
    def description(self) -> str:
        return "Network security testing tools"

    async def run_network(self, session_id: str, target: str, test_type: str = "ssl", **kwargs) -> Dict[str, Any]:
        """Run network security tests."""
        findings = []

        if test_type == "ssl":
            # SSL/TLS scan with testssl.sh
            cmd = f"testssl.sh --fast {target}"
            result = await self._execute(cmd, session_id, timeout=300)

            if result.get("returncode") == 0:
                output = result.get("stdout", "")
                if "not ok" in output.lower() or "vulnerable" in output.lower():
                    findings.append(Finding(
                        session_id=session_id,
                        attack_type="ssl_weakness",
                        confidence=0.85,
                        endpoint=target,
                        evidence="SSL/TLS weaknesses detected by testssl.sh",
                        status="confirmed",
                        cvss_score=5.3,
                        severity="medium",
                    ))

        elif test_type == "headers":
            # Security headers check
            cmd = f"curl -s -I {target}"
            result = await self._execute(cmd, session_id, timeout=30)

            if result.get("returncode") == 0:
                headers = result.get("stdout", "").lower()
                missing_headers = []

                for header in ["strict-transport-security", "content-security-policy", "x-frame-options", "x-content-type-options"]:
                    if header not in headers:
                        missing_headers.append(header)

                if missing_headers:
                    findings.append(Finding(
                        session_id=session_id,
                        attack_type="missing_security_headers",
                        confidence=0.9,
                        endpoint=target,
                        evidence=f"Missing security headers: {', '.join(missing_headers)}",
                        status="confirmed",
                        cvss_score=3.7,
                        severity="low",
                    ))

        return {"findings": [f.model_dump() for f in findings], "raw": {test_type: result}}
