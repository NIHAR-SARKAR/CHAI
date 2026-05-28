"""Authentication testing tools module."""
import logging
import json
import asyncio
import base64
from typing import Dict, Any, List
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
        if test_type == "bypass":
            return await self._run_bypass_test(session_id, target, **kwargs)
        elif test_type == "jwt":
            return await self._run_jwt_tests(session_id, target, **kwargs)
        elif test_type == "brute_force":
            return await self._run_brute_force_test(session_id, target, **kwargs)
        elif test_type == "password_reset":
            return await self._run_password_reset_test(session_id, target, **kwargs)
        elif test_type == "session_fixation":
            return await self._run_session_fixation_test(session_id, target, **kwargs)
        elif test_type == "privilege_escalation":
            return await self._run_privilege_escalation_test(session_id, target, **kwargs)
        else:
            return {"findings": [], "raw": {}, "error": f"Unknown test_type: {test_type}"}

    # ── Task 2.1 – Default / Weak Credentials ────────────────────────────────

    async def _run_bypass_test(self, session_id: str, target: str, **kwargs) -> Dict[str, Any]:
        """Test for common auth bypass patterns and weak credentials."""
        findings = []
        raw = {}

        # Admin panel accessibility
        admin_cmd = f"curl -s -o /dev/null -w '%{{http_code}}' {target}/admin"
        admin_result = await self._execute(admin_cmd, session_id, timeout=30)
        raw["admin_panel"] = admin_result

        if admin_result.get("returncode") == 0:
            status_code = admin_result.get("stdout", "").strip()
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

        # Weak credentials test (if login endpoint provided)
        login_url = kwargs.get("login_url", f"{target}/auth/login")
        username = kwargs.get("username", "admin@example.com")
        common_passwords = ["admin", "password", "123456", "admin123", "test", "guest"]

        weak_found = []
        for password in common_passwords:
            cmd = (
                f'curl -s -o /dev/null -w "%{{http_code}}" -X POST {login_url} '
                f'-H "Content-Type: application/json" '
                f'-d \'{{"username":"{username}","password":"{password}"}}\''
            )
            result = await self._execute(cmd, session_id, timeout=15)
            if result.get("returncode") == 0:
                code = result.get("stdout", "").strip()
                if code in ["200", "201", "204"]:
                    weak_found.append(password)
                    break  # Stop on first hit to avoid excessive requests

        if weak_found:
            findings.append(Finding(
                session_id=session_id,
                attack_type="weak_credentials",
                confidence=0.95,
                endpoint=login_url,
                evidence=f"Weak password accepted: {weak_found[0]}",
                status="confirmed",
                cvss_score=9.8,
                severity="critical",
                remediation="Enforce strong password policy and MFA",
            ))

        return {"findings": [f.model_dump() for f in findings], "raw": raw}

    # ── Task 2.2 – JWT Token Manipulation ────────────────────────────────────

    async def _run_jwt_tests(self, session_id: str, target: str, **kwargs) -> Dict[str, Any]:
        """Test JWT security including none-algorithm attack."""
        findings = []
        raw = {}

        # Detect JWT in Authorization header
        detect_cmd = f"curl -s {target} -I | grep -i authorization"
        detect_result = await self._execute(detect_cmd, session_id, timeout=30)
        raw["jwt_detected"] = detect_result

        if "Bearer" in detect_result.get("stdout", ""):
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

        # Test none algorithm if token provided
        token = kwargs.get("jwt_token", "")
        if token:
            # Parse token structure
            parts = token.split(".")
            if len(parts) == 3:
                try:
                    header_json = base64.urlsafe_b64decode(parts[0] + "==").decode()
                    header = json.loads(header_json)
                    raw["jwt_header"] = header

                    # Attempt none-alg attack
                    none_header = base64.urlsafe_b64encode(
                        json.dumps({"alg": "none", "typ": "JWT"}).encode()
                    ).decode().rstrip("=")
                    none_token = f"{none_header}.{parts[1]}."

                    test_url = kwargs.get("protected_url", f"{target}/api/users")
                    none_cmd = (
                        f'curl -s -o /dev/null -w "%{{http_code}}" -H "Authorization: Bearer {none_token}" {test_url}'
                    )
                    none_result = await self._execute(none_cmd, session_id, timeout=30)
                    raw["none_alg_test"] = none_result

                    if none_result.get("returncode") == 0:
                        code = none_result.get("stdout", "").strip()
                        if code in ["200", "201", "204"]:
                            findings.append(Finding(
                                session_id=session_id,
                                attack_type="jwt_none_algorithm",
                                confidence=0.95,
                                endpoint=test_url,
                                evidence="JWT 'none' algorithm accepted — token integrity bypass possible",
                                status="confirmed",
                                cvss_score=9.8,
                                severity="critical",
                                remediation="Reject JWT tokens with 'alg: none' on the server side",
                            ))
                except Exception as e:
                    raw["jwt_parse_error"] = str(e)

            # Run jwt_tool if available
            jwt_tool_cmd = f"jwt_tool {token} -X a"
            jwt_result = await self._execute(jwt_tool_cmd, session_id, timeout=60)
            raw["jwt_tool"] = jwt_result

            if jwt_result.get("returncode") == 0:
                stdout = jwt_result.get("stdout", "")
                if "vulnerable" in stdout.lower() or "accepted" in stdout.lower():
                    findings.append(Finding(
                        session_id=session_id,
                        attack_type="jwt_weakness",
                        confidence=0.85,
                        endpoint=target,
                        evidence=f"jwt_tool detected weakness: {stdout[:200]}",
                        status="confirmed",
                        cvss_score=7.5,
                        severity="high",
                        remediation="Validate JWT signature algorithm strictly",
                    ))

        return {"findings": [f.model_dump() for f in findings], "raw": raw}

    # ── Task 2.3 – Brute Force Protection Test ───────────────────────────────

    async def _run_brute_force_test(self, session_id: str, target: str, **kwargs) -> Dict[str, Any]:
        """Test brute-force protection on login endpoint."""
        findings = []
        raw = {}

        login_url = kwargs.get("login_url", f"{target}/auth/login")
        attempts = kwargs.get("attempts", 20)
        username = kwargs.get("brute_username", "test@test.com")
        delay = kwargs.get("delay", 0.2)

        blocked = False
        block_at = None
        responses = []

        for i in range(1, attempts + 1):
            cmd = (
                f'curl -s -o /dev/null -w "%{{http_code}}" -X POST {login_url} '
                f'-H "Content-Type: application/json" '
                f'-d \'{{"username":"{username}","password":"wrongpass"}}\''
            )
            result = await self._execute(cmd, session_id, timeout=15)
            code = result.get("stdout", "").strip()
            responses.append(code)

            if code == "429":
                blocked = True
                block_at = i
                break

            # Small delay between requests
            if delay > 0:
                await asyncio.sleep(delay)

        raw["responses"] = responses
        raw["blocked"] = blocked
        raw["block_at"] = block_at

        if not blocked:
            findings.append(Finding(
                session_id=session_id,
                attack_type="missing_brute_force_protection",
                confidence=0.9,
                endpoint=login_url,
                evidence=f"No rate limiting after {attempts} failed login attempts",
                status="confirmed",
                cvss_score=5.3,
                severity="medium",
                remediation="Implement rate limiting, CAPTCHA, and account lockout after ≤10 attempts",
            ))
        else:
            findings.append(Finding(
                session_id=session_id,
                attack_type="brute_force_protection",
                confidence=1.0,
                endpoint=login_url,
                evidence=f"Rate limiting triggered after {block_at} attempts (HTTP 429)",
                status="confirmed",
                cvss_score=0.0,
                severity="info",
            ))

        return {"findings": [f.model_dump() for f in findings], "raw": raw}

    # ── Task 2.4 – Password Reset Flaws ──────────────────────────────────────

    async def _run_password_reset_test(self, session_id: str, target: str, **kwargs) -> Dict[str, Any]:
        """Test password reset for predictable tokens and reuse."""
        findings = []
        raw = {}

        forgot_url = kwargs.get("forgot_url", f"{target}/auth/forgot-password")
        reset_url = kwargs.get("reset_url", f"{target}/auth/reset-password")
        email = kwargs.get("reset_email", "test@test.com")

        # Request reset token
        forgot_cmd = (
            f'curl -s -X POST {forgot_url} '
            f'-H "Content-Type: application/json" '
            f'-d \'{{"email":"{email}"}}\''
        )
        forgot_result = await self._execute(forgot_cmd, session_id, timeout=30)
        raw["forgot_request"] = forgot_result

        # Check if token appears predictable in response (dev/test environments)
        stdout = forgot_result.get("stdout", "")
        if "token" in stdout.lower() or len(stdout) < 100:
            # If response is very short or contains token, flag it
            findings.append(Finding(
                session_id=session_id,
                attack_type="predictable_reset_token",
                confidence=0.6,
                endpoint=forgot_url,
                evidence="Password reset response may contain or leak token",
                status="potential",
                cvss_score=7.5,
                severity="high",
                remediation="Ensure reset tokens are cryptographically random and not returned in response",
            ))

        # Token reuse test (requires captured token from kwargs)
        captured_token = kwargs.get("captured_token", "")
        if captured_token:
            # First use
            reset_cmd_1 = (
                f'curl -s -X POST {reset_url} '
                f'-H "Content-Type: application/json" '
                f'-d \'{{"token":"{captured_token}","password":"NewPass123!"}}\''
            )
            reset_1 = await self._execute(reset_cmd_1, session_id, timeout=30)
            raw["reset_first_use"] = reset_1

            # Second use (reuse attempt)
            reset_cmd_2 = (
                f'curl -s -X POST {reset_url} '
                f'-H "Content-Type: application/json" '
                f'-d \'{{"token":"{captured_token}","password":"NewPass456!"}}\''
            )
            reset_2 = await self._execute(reset_cmd_2, session_id, timeout=30)
            raw["reset_second_use"] = reset_2

            code_1 = reset_1.get("stdout", "").strip() if reset_1.get("returncode") == 0 else ""
            code_2 = reset_2.get("stdout", "").strip() if reset_2.get("returncode") == 0 else ""

            if code_2 in ["200", "201", "204"]:
                findings.append(Finding(
                    session_id=session_id,
                    attack_type="reset_token_reuse",
                    confidence=0.95,
                    endpoint=reset_url,
                    evidence="Password reset token accepted multiple times",
                    status="confirmed",
                    cvss_score=8.1,
                    severity="high",
                    remediation="Invalidate reset tokens immediately after first use",
                ))
            else:
                findings.append(Finding(
                    session_id=session_id,
                    attack_type="reset_token_reuse",
                    confidence=1.0,
                    endpoint=reset_url,
                    evidence="Reset token correctly rejected on reuse attempt",
                    status="confirmed",
                    cvss_score=0.0,
                    severity="info",
                ))

        return {"findings": [f.model_dump() for f in findings], "raw": raw}

    # ── Task 2.5 – Session Fixation & Cookie Flags ───────────────────────────

    async def _run_session_fixation_test(self, session_id: str, target: str, **kwargs) -> Dict[str, Any]:
        """Verify cookie security flags."""
        findings = []
        raw = {}

        login_url = kwargs.get("login_url", f"{target}/login")
        cmd = f"curl -v -c /tmp/cookies_{session_id}.txt {login_url} 2>&1 | grep -i 'set-cookie'"
        result = await self._execute(cmd, session_id, timeout=30)
        raw["cookie_headers"] = result

        if result.get("returncode") == 0:
            cookies = result.get("stdout", "").lower()
            missing_flags = []

            if "httponly" not in cookies:
                missing_flags.append("HttpOnly")
            if "secure" not in cookies:
                missing_flags.append("Secure")
            if "samesite=strict" not in cookies and "samesite=lax" not in cookies:
                missing_flags.append("SameSite")

            if missing_flags:
                findings.append(Finding(
                    session_id=session_id,
                    attack_type="insecure_cookie_flags",
                    confidence=0.9,
                    endpoint=login_url,
                    evidence=f"Missing cookie flags: {', '.join(missing_flags)}",
                    status="confirmed",
                    cvss_score=5.3,
                    severity="medium",
                    remediation="Set HttpOnly, Secure, and SameSite=Strict on all session cookies",
                ))
            else:
                findings.append(Finding(
                    session_id=session_id,
                    attack_type="secure_cookie_flags",
                    confidence=1.0,
                    endpoint=login_url,
                    evidence="All recommended cookie flags present (HttpOnly, Secure, SameSite)",
                    status="confirmed",
                    cvss_score=0.0,
                    severity="info",
                ))

        return {"findings": [f.model_dump() for f in findings], "raw": raw}

    # ── Task 2.6 – Privilege Escalation ────────────────────────────────────────

    async def _run_privilege_escalation_test(self, session_id: str, target: str, **kwargs) -> Dict[str, Any]:
        """Test if regular user tokens can access admin endpoints."""
        findings = []
        raw = {}

        user_token = kwargs.get("user_token", "")
        if not user_token:
            return {"findings": [], "raw": raw, "error": "user_token required for privilege escalation test"}

        admin_endpoints = kwargs.get("admin_endpoints", ["/admin/users", "/admin/settings", "/api/admin/users"])

        for endpoint in admin_endpoints:
            url = f"{target}{endpoint}"
            cmd = (
                f'curl -s -o /dev/null -w "%{{http_code}}" '
                f'-H "Authorization: Bearer {user_token}" {url}'
            )
            result = await self._execute(cmd, session_id, timeout=30)
            raw[endpoint] = result

            if result.get("returncode") == 0:
                code = result.get("stdout", "").strip()
                if code == "200":
                    findings.append(Finding(
                        session_id=session_id,
                        attack_type="privilege_escalation",
                        confidence=0.95,
                        endpoint=url,
                        evidence=f"Regular user token accessed admin endpoint with HTTP 200",
                        status="confirmed",
                        cvss_score=8.1,
                        severity="high",
                        remediation="Enforce role-based access control (RBAC) on all admin endpoints",
                    ))
                elif code in ["401", "403"]:
                    findings.append(Finding(
                        session_id=session_id,
                        attack_type="privilege_escalation",
                        confidence=1.0,
                        endpoint=url,
                        evidence=f"Admin endpoint correctly rejected regular user token (HTTP {code})",
                        status="confirmed",
                        cvss_score=0.0,
                        severity="info",
                    ))

        return {"findings": [f.model_dump() for f in findings], "raw": raw}
