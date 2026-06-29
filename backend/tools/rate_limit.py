"""Rate Limiting & DoS Protection testing tools module."""
import logging
import asyncio
from typing import Dict, Any, List
from models.session import Finding
from tools.base import BaseTool

logger = logging.getLogger(__name__)


class RateLimitTools(BaseTool):
    @property
    def tool_name(self) -> str:
        return "rate_limit"

    @property
    def description(self) -> str:
        return "Rate limiting and DoS protection testing"

    async def run_rate_limit(self, session_id: str, target: str, test_type: str = "login", **kwargs) -> Dict[str, Any]:
        """Run rate limiting tests."""
        if test_type == "login":
            return await self._run_login_rate_limit(session_id, target, **kwargs)
        elif test_type == "api":
            return await self._run_api_rate_limit(session_id, target, **kwargs)
        elif test_type == "bypass_headers":
            return await self._run_bypass_headers(session_id, target, **kwargs)
        else:
            return {"findings": [], "raw": {}, "error": f"Unknown test_type: {test_type}"}

    # Task 9.1 – Login Endpoint Rate Limiting
    async def _run_login_rate_limit(self, session_id: str, target: str, **kwargs) -> Dict[str, Any]:
        """Test rate limiting on login endpoint."""
        findings = []
        raw = {}

        login_url = kwargs.get("login_url", f"{target}/auth/login")
        attempts = kwargs.get("attempts", 50)
        username = kwargs.get("username", "test@test.com")

        blocked = False
        block_at = None
        responses = []

        for i in range(1, attempts + 1):
            cmd = (
                f"curl -s -o /dev/null -w '%{{http_code}}' -X POST {login_url} "
                f"-H 'Content-Type: application/json' "
                f"-d '{{\"username\":\"{username}\",\"password\":\"wrong\"}}'"
            )
            result = await self._execute(cmd, session_id, timeout=15)
            code = result.get("stdout", "").strip()
            responses.append(code)

            if code == "429":
                blocked = True
                block_at = i
                break

        raw["responses"] = responses
        raw["blocked"] = blocked
        raw["block_at"] = block_at

        if not blocked:
            findings.append(Finding(
                session_id=session_id,
                attack_type="missing_rate_limit_login",
                confidence=0.9,
                endpoint=login_url,
                evidence=f"No rate limiting after {attempts} failed login attempts",
                status="confirmed",
                cvss_score=5.3,
                severity="medium",
                remediation="Implement rate limiting and account lockout after <=10 failed attempts",
            ))
        else:
            findings.append(Finding(
                session_id=session_id,
                attack_type="rate_limit_login",
                confidence=1.0,
                endpoint=login_url,
                evidence=f"Login rate limited after {block_at} attempts (HTTP 429)",
                status="confirmed",
                cvss_score=0.0,
                severity="info",
            ))

        return {"findings": [f.model_dump() for f in findings], "raw": raw}

    # Task 9.2 – API Endpoint Rate Limiting
    async def _run_api_rate_limit(self, session_id: str, target: str, **kwargs) -> Dict[str, Any]:
        """Test rate limiting on general API endpoints."""
        findings = []
        raw = {}

        token = kwargs.get("token", "")
        api_url = kwargs.get("api_url", f"{target}/api/users")
        attempts = kwargs.get("attempts", 100)

        blocked = False
        block_at = None
        responses = []

        for i in range(1, attempts + 1):
            cmd = (
                f"curl -s -o /dev/null -w '%{{http_code}}' "
                f"-H 'Authorization: Bearer {token}' {api_url}"
            )
            result = await self._execute(cmd, session_id, timeout=15)
            code = result.get("stdout", "").strip()
            responses.append(code)

            if code == "429":
                blocked = True
                block_at = i
                break

            if i % 10 == 0:
                logger.info(f"Rate limit test: {i}/{attempts} requests sent")

        raw["responses"] = responses
        raw["blocked"] = blocked
        raw["block_at"] = block_at

        if not blocked:
            findings.append(Finding(
                session_id=session_id,
                attack_type="missing_rate_limit_api",
                confidence=0.85,
                endpoint=api_url,
                evidence=f"No rate limiting after {attempts} API requests",
                status="confirmed",
                cvss_score=5.3,
                severity="medium",
                remediation="Implement API rate limiting per client/IP/token",
            ))
        else:
            findings.append(Finding(
                session_id=session_id,
                attack_type="rate_limit_api",
                confidence=1.0,
                endpoint=api_url,
                evidence=f"API rate limited after {block_at} requests (HTTP 429)",
                status="confirmed",
                cvss_score=0.0,
                severity="info",
            ))

        return {"findings": [f.model_dump() for f in findings], "raw": raw}

    # Task 9.3 – Rate Limit Bypass via Headers
    async def _run_bypass_headers(self, session_id: str, target: str, **kwargs) -> Dict[str, Any]:
        """Test rate limit bypass using spoofed IP headers."""
        findings = []
        raw = {}

        login_url = kwargs.get("login_url", f"{target}/auth/login")
        attempts = kwargs.get("attempts", 20)
        username = kwargs.get("username", "test@test.com")

        blocked = False
        block_at = None
        responses = []

        for i in range(1, attempts + 1):
            cmd = (
                f"curl -s -o /dev/null -w '%{{http_code}}' -X POST {login_url} "
                f"-H 'Content-Type: application/json' "
                f"-H 'X-Forwarded-For: 10.0.0.{i}' "
                f"-H 'X-Real-IP: 10.0.0.{i}' "
                f"-d '{{\"username\":\"{username}\",\"password\":\"wrong\"}}'"
            )
            result = await self._execute(cmd, session_id, timeout=15)
            code = result.get("stdout", "").strip()
            responses.append(code)

            if code == "429":
                blocked = True
                block_at = i
                break

        raw["responses"] = responses
        raw["blocked"] = blocked
        raw["block_at"] = block_at

        if not blocked:
            findings.append(Finding(
                session_id=session_id,
                attack_type="rate_limit_bypass",
                confidence=0.9,
                endpoint=login_url,
                evidence=f"Rate limit bypassed via IP header spoofing after {attempts} attempts",
                status="confirmed",
                cvss_score=5.3,
                severity="medium",
                remediation="Rate limit by authenticated user/token, not by spoofable IP headers",
            ))
        else:
            findings.append(Finding(
                session_id=session_id,
                attack_type="rate_limit_bypass",
                confidence=1.0,
                endpoint=login_url,
                evidence=f"Rate limit enforced even with spoofed headers (blocked at {block_at})",
                status="confirmed",
                cvss_score=0.0,
                severity="info",
            ))

        return {"findings": [f.model_dump() for f in findings], "raw": raw}
