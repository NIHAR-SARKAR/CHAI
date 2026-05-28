"""Network testing tools module."""
import logging
from typing import Dict, Any, List
from models.session import Finding
from tools.base import BaseTool

logger = logging.getLogger(__name__)


class NetworkTools(BaseTool):
    @property
    def tool_name(self) -> str:
        return "network"

    @property
    def description(self) -> str:
        return "Network security testing tools (SSL/TLS, headers, port scanning)"

    async def run_network(self, session_id: str, target: str, test_type: str = "ssl", **kwargs) -> Dict[str, Any]:
        """Run network security tests."""
        if test_type == "ssl":
            return await self._run_ssl_test(session_id, target, **kwargs)
        elif test_type == "headers":
            return await self._run_headers_test(session_id, target, **kwargs)
        elif test_type == "port_scan":
            return await self._run_port_scan(session_id, target, **kwargs)
        else:
            return {"findings": [], "raw": {}, "error": f"Unknown test_type: {test_type}"}

    async def _run_ssl_test(self, session_id: str, target: str, **kwargs) -> Dict[str, Any]:
        """SSL/TLS scan with testssl.sh."""
        findings = []
        raw = {}

        cmd = f"testssl.sh --fast {target}"
        result = await self._execute(cmd, session_id, timeout=300)
        raw["testssl"] = result

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
                    remediation="Upgrade to TLS 1.2+ and disable weak cipher suites",
                ))
            else:
                findings.append(Finding(
                    session_id=session_id,
                    attack_type="ssl_strong",
                    confidence=0.9,
                    endpoint=target,
                    evidence="No critical SSL/TLS weaknesses detected",
                    status="confirmed",
                    cvss_score=0.0,
                    severity="info",
                ))

        return {"findings": [f.model_dump() for f in findings], "raw": raw}

    async def _run_headers_test(self, session_id: str, target: str, **kwargs) -> Dict[str, Any]:
        """Comprehensive security headers check."""
        findings = []
        raw = {}

        cmd = f"curl -sI {target}"
        result = await self._execute(cmd, session_id, timeout=30)
        raw["headers"] = result

        if result.get("returncode") == 0:
            headers = result.get("stdout", "").lower()
            required_headers = {
                "strict-transport-security": "HSTS",
                "content-security-policy": "CSP",
                "x-frame-options": "X-Frame-Options",
                "x-content-type-options": "X-Content-Type-Options",
                "referrer-policy": "Referrer-Policy",
                "permissions-policy": "Permissions-Policy",
            }
            missing = []

            for header, display in required_headers.items():
                if header not in headers:
                    missing.append(display)

            if missing:
                findings.append(Finding(
                    session_id=session_id,
                    attack_type="missing_security_headers",
                    confidence=0.9,
                    endpoint=target,
                    evidence=f"Missing security headers: {', '.join(missing)}",
                    status="confirmed",
                    cvss_score=3.7,
                    severity="low",
                    remediation="Add all recommended security headers",
                ))
            else:
                findings.append(Finding(
                    session_id=session_id,
                    attack_type="security_headers",
                    confidence=1.0,
                    endpoint=target,
                    evidence="All recommended security headers present",
                    status="confirmed",
                    cvss_score=0.0,
                    severity="info",
                ))

        return {"findings": [f.model_dump() for f in findings], "raw": raw}

    async def _run_port_scan(self, session_id: str, target: str, **kwargs) -> Dict[str, Any]:
        """Nmap port scan for common services."""
        findings = []
        raw = {}

        host = target.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]
        ports = kwargs.get("ports", "80,443,8080,8443,3000,5000,4000,22,3306,5432,6379,27017")

        cmd = f"nmap -sV -p {ports} {host}"
        result = await self._execute(cmd, session_id, timeout=300)
        raw["nmap"] = result

        if result.get("returncode") == 0:
            from utils.output_parser import OutputParser
            parsed = OutputParser.parse_nmap(result.get("stdout", ""))
            for p in parsed:
                if p.get("state") == "open":
                    findings.append(Finding(
                        session_id=session_id,
                        attack_type="port_discovery",
                        confidence=1.0,
                        endpoint=f"{host}:{p.get('port')}",
                        evidence=f"{p.get('protocol')}/{p.get('port')} {p.get('state')} {p.get('service')}",
                        status="confirmed",
                        cvss_score=0.0,
                        severity="info",
                    ))

        return {"findings": [f.model_dump() for f in findings], "raw": raw}
