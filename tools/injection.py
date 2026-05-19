"""Injection testing tools module."""
import logging
from typing import Dict, Any
from models.session import Finding
from tools.base import BaseTool
from utils.cvss_calculator import CVSSCalculator

logger = logging.getLogger(__name__)


class InjectionTools(BaseTool):
    @property
    def tool_name(self) -> str:
        return "injection"

    @property
    def description(self) -> str:
        return "Injection vulnerability testing tools"

    async def run_injection(self, session_id: str, target: str, injection_type: str = "sqli", **kwargs) -> Dict[str, Any]:
        """Run injection tests."""
        findings = []

        if injection_type == "sqli":
            # SQLMap scan
            cmd = f"sqlmap -u {target} --batch --level=1 --risk=1 --flush-session"
            result = await self._execute(cmd, session_id, timeout=300)

            if result.get("returncode") == 0:
                if "sqlmap identified" in result.get("stdout", "").lower():
                    findings.append(Finding(
                        session_id=session_id,
                        attack_type="sqli",
                        confidence=0.95,
                        endpoint=target,
                        evidence="SQLMap confirmed SQL injection vulnerability",
                        status="confirmed",
                        cvss_score=9.8,
                        severity="critical",
                    ))

        elif injection_type == "xss":
            # Dalfox scan
            cmd = f"dalfox url {target} --silence"
            result = await self._execute(cmd, session_id, timeout=120)

            if result.get("returncode") == 0:
                if "POC" in result.get("stdout", ""):
                    findings.append(Finding(
                        session_id=session_id,
                        attack_type="xss",
                        confidence=0.9,
                        endpoint=target,
                        evidence="Dalfox confirmed XSS vulnerability",
                        status="confirmed",
                        cvss_score=6.1,
                        severity="medium",
                    ))

        return {"findings": [f.model_dump() for f in findings], "raw": {injection_type: result}}
