"""Security Misconfiguration testing tools module."""
import logging
from typing import Dict, Any, List
from models.session import Finding
from tools.base import BaseTool

logger = logging.getLogger(__name__)


class MisconfigTools(BaseTool):
    @property
    def tool_name(self) -> str:
        return "misconfig"

    @property
    def description(self) -> str:
        return "Security misconfiguration testing (CORS, verbose errors, debug endpoints, headers)"

    async def run_misconfig(self, session_id: str, target: str, test_type: str = "cors", **kwargs) -> Dict[str, Any]:
        """Run security misconfiguration tests."""
        if test_type == "cors":
            return await self._run_cors_test(session_id, target, **kwargs)
        elif test_type == "verbose_errors":
            return await self._run_verbose_errors(session_id, target, **kwargs)
        elif test_type == "debug_endpoints":
            return await self._run_debug_endpoints(session_id, target, **kwargs)
        elif test_type == "security_headers":
            return await self._run_security_headers(session_id, target, **kwargs)
        else:
            return {"findings": [], "raw": {}, "error": f"Unknown test_type: {test_type}"}

    # Task 6.1 – CORS Misconfiguration
    async def _run_cors_test(self, session_id: str, target: str, **kwargs) -> Dict[str, Any]:
        """Test CORS policy for misconfigurations."""
        findings = []
        raw = {}

        api_base = kwargs.get("api_base", target)
        token = kwargs.get("token", "")

        # Test arbitrary origin
        cmd_evil = (
            f"curl -sI -H 'Origin: https://evil.com' "
            f"{api_base}/users"
        )
        result_evil = await self._execute(cmd_evil, session_id, timeout=30)
        raw["evil_origin"] = result_evil

        # Test null origin
        cmd_null = (
            f"curl -sI -H 'Origin: null' "
            f"{api_base}/users"
        )
        result_null = await self._execute(cmd_null, session_id, timeout=30)
        raw["null_origin"] = result_null

        # Test with credentials
        cmd_creds = (
            f"curl -sI -H 'Origin: https://evil.com' "
            f"-H 'Authorization: Bearer {token}' "
            f"{api_base}/users"
        )
        result_creds = await self._execute(cmd_creds, session_id, timeout=30)
        raw["with_credentials"] = result_creds

        for test_name, result in [("evil.com", result_evil), ("null", result_null), ("with_credentials", result_creds)]:
            if result.get("returncode") == 0:
                headers = result.get("stdout", "").lower()
                acao = "access-control-allow-origin" in headers
                acc = "access-control-allow-credentials: true" in headers

                if acao and ("evil.com" in headers or "null" in headers):
                    if acc:
                        findings.append(Finding(
                            session_id=session_id,
                            attack_type="cors_misconfiguration",
                            confidence=0.95,
                            endpoint=api_base,
                            evidence=f"CORS reflects arbitrary origin with credentials allowed ({test_name})",
                            status="confirmed",
                            cvss_score=6.1,
                            severity="medium",
                            remediation="Whitelist specific origins; never reflect arbitrary origins with credentials",
                        ))
                    else:
                        findings.append(Finding(
                            session_id=session_id,
                            attack_type="cors_misconfiguration",
                            confidence=0.8,
                            endpoint=api_base,
                            evidence=f"CORS reflects arbitrary origin without credentials ({test_name})",
                            status="confirmed",
                            cvss_score=3.7,
                            severity="low",
                            remediation="Whitelist specific origins instead of reflecting arbitrary ones",
                        ))

        if not findings:
            findings.append(Finding(
                session_id=session_id,
                attack_type="cors_policy",
                confidence=0.9,
                endpoint=api_base,
                evidence="CORS does not reflect arbitrary origins",
                status="confirmed",
                cvss_score=0.0,
                severity="info",
            ))

        return {"findings": [f.model_dump() for f in findings], "raw": raw}

    # Task 6.2 – Verbose Error Messages
    async def _run_verbose_errors(self, session_id: str, target: str, **kwargs) -> Dict[str, Any]:
        """Trigger errors and check for stack traces."""
        findings = []
        raw = {}

        api_base = kwargs.get("api_base", target)
        error_triggers = [
            ("invalid_id", f"{api_base}/users/not-a-valid-id-12345"),
            ("invalid_json", f"{api_base}/users", "-X POST -H 'Content-Type: application/json' -d 'invalid json{{'"),
            ("sqli_like", f"{api_base}/users?id='"),
        ]

        for test_name, url, *extra in error_triggers:
            extra_args = extra[0] if extra else ""
            cmd = f"curl -s {extra_args} {url}"
            result = await self._execute(cmd, session_id, timeout=30)
            raw[test_name] = result

            if result.get("returncode") == 0:
                stdout = result.get("stdout", "").lower()
                stack_indicators = [
                    "traceback", "stack trace", "at ", "line ", "exception",
                    "syntaxerror", "typeerror", "referenceerror", "undefined",
                    "sql", "mysql", "postgres", "sqlite",
                ]
                if any(ind in stdout for ind in stack_indicators):
                    findings.append(Finding(
                        session_id=session_id,
                        attack_type="verbose_errors",
                        confidence=0.85,
                        endpoint=url,
                        evidence=f"Verbose error/stack trace leaked for {test_name}: {stdout[:200]}",
                        status="confirmed",
                        cvss_score=5.3,
                        severity="medium",
                        remediation="Return generic error messages to clients; log details server-side only",
                    ))

        if not findings:
            findings.append(Finding(
                session_id=session_id,
                attack_type="verbose_errors",
                confidence=0.9,
                endpoint=api_base,
                evidence="No stack traces or verbose errors exposed",
                status="confirmed",
                cvss_score=0.0,
                severity="info",
            ))

        return {"findings": [f.model_dump() for f in findings], "raw": raw}

    # Task 6.3 – Debug Endpoints
    async def _run_debug_endpoints(self, session_id: str, target: str, **kwargs) -> Dict[str, Any]:
        """Check for exposed debug and actuator endpoints."""
        findings = []
        raw = {}

        api_base = kwargs.get("api_base", target)
        debug_paths = [
            "/debug", "/actuator", "/actuator/env",
            "/actuator/heapdump", "/metrics", "/info",
            "/health", "/trace", "/.env", "/config",
        ]

        exposed = []
        for path in debug_paths:
            url = f"{api_base}{path}"
            cmd = f"curl -s -o /dev/null -w '%{{http_code}}' {url}"
            result = await self._execute(cmd, session_id, timeout=15)
            raw[path] = result

            if result.get("returncode") == 0:
                code = result.get("stdout", "").strip()
                if code in ["200", "301", "302"]:
                    exposed.append(f"{path} (HTTP {code})")

        if exposed:
            findings.append(Finding(
                session_id=session_id,
                attack_type="debug_endpoints_exposed",
                confidence=0.9,
                endpoint=api_base,
                evidence=f"Debug/actuator endpoints accessible: {', '.join(exposed)}",
                status="confirmed",
                cvss_score=5.3,
                severity="medium",
                remediation="Disable or restrict debug/actuator endpoints in production",
            ))
        else:
            findings.append(Finding(
                session_id=session_id,
                attack_type="debug_endpoints_exposed",
                confidence=0.95,
                endpoint=api_base,
                evidence="No debug/actuator endpoints publicly accessible",
                status="confirmed",
                cvss_score=0.0,
                severity="info",
            ))

        return {"findings": [f.model_dump() for f in findings], "raw": raw}

    # Task 6.4 – Security Headers Check
    async def _run_security_headers(self, session_id: str, target: str, **kwargs) -> Dict[str, Any]:
        """Check for recommended security headers."""
        findings = []
        raw = {}

        cmd = f"curl -sI {target}"
        result = await self._execute(cmd, session_id, timeout=30)
        raw["headers"] = result

        if result.get("returncode") == 0:
            headers = result.get("stdout", "").lower()
            required = [
                "x-frame-options",
                "x-content-type-options",
                "strict-transport-security",
                "permissions-policy",
                "referrer-policy",
                "content-security-policy",
            ]
            missing = [h for h in required if h not in headers]

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
                    remediation="Add all recommended security headers (HSTS, CSP, X-Frame-Options, etc.)",
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
