"""Cross-Site Scripting (XSS) testing tools module."""
import logging
import json
from typing import Dict, Any, List
from models.session import Finding
from tools.base import BaseTool

logger = logging.getLogger(__name__)


class XssTools(BaseTool):
    @property
    def tool_name(self) -> str:
        return "xss"

    @property
    def description(self) -> str:
        return "Cross-Site Scripting (XSS) testing tools"

    async def run_xss(self, session_id: str, target: str, xss_type: str = "reflected", **kwargs) -> Dict[str, Any]:
        """Run XSS tests."""
        if xss_type == "reflected":
            return await self._run_reflected_xss(session_id, target, **kwargs)
        elif xss_type == "stored":
            return await self._run_stored_xss(session_id, target, **kwargs)
        elif xss_type == "dom":
            return await self._run_dom_xss(session_id, target, **kwargs)
        elif xss_type == "header_reflected":
            return await self._run_header_xss(session_id, target, **kwargs)
        elif xss_type == "csp":
            return await self._run_csp_check(session_id, target, **kwargs)
        else:
            return {"findings": [], "raw": {}, "error": f"Unknown xss_type: {xss_type}"}

    # Task 4.1 – Reflected XSS via URL parameters
    async def _run_reflected_xss(self, session_id: str, target: str, **kwargs) -> Dict[str, Any]:
        """Test for reflected XSS in URL parameters."""
        findings = []
        raw = {}

        payloads = [
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "\x22\x27><svg onload=alert(1)>",
            "javascript:alert(1)",
        ]

        search_url = kwargs.get("search_url", f"{target}/search")

        for payload in payloads:
            import urllib.parse
            encoded = urllib.parse.quote(payload)
            cmd = f"curl -s '{search_url}?q={encoded}'"
            result = await self._execute(cmd, session_id, timeout=30)
            raw[payload] = result

            if result.get("returncode") == 0:
                stdout = result.get("stdout", "")
                if "alert(1)" in stdout or payload in stdout:
                    findings.append(Finding(
                        session_id=session_id,
                        attack_type="xss_reflected",
                        confidence=0.9,
                        endpoint=search_url,
                        parameter="q",
                        evidence=f"Reflected XSS confirmed: payload '{payload[:50]}' reflected unescaped",
                        status="confirmed",
                        cvss_score=6.1,
                        severity="medium",
                        remediation="HTML-encode all user input before rendering in the DOM",
                    ))
                    break

        if not findings:
            findings.append(Finding(
                session_id=session_id,
                attack_type="xss_reflected",
                confidence=0.8,
                endpoint=search_url,
                evidence="Reflected XSS payloads not found in response",
                status="potential",
                cvss_score=0.0,
                severity="info",
            ))

        return {"findings": [f.model_dump() for f in findings], "raw": raw}

    # Task 4.2 – Stored XSS via API
    async def _run_stored_xss(self, session_id: str, target: str, **kwargs) -> Dict[str, Any]:
        """Test for stored XSS via API POST data."""
        findings = []
        raw = {}

        token = kwargs.get("token", "")
        comments_url = kwargs.get("comments_url", f"{target}/api/comments")
        payload = "<script>alert(\"StoredXSS\")</script>"

        # Submit payload
        post_cmd = (
            f"curl -s -X POST {comments_url} "
            f'-H "Content-Type: application/json" '
            f'-H "Authorization: Bearer {token}" '
            f'-d \'{"content":"<script>alert(\\"StoredXSS\\")</script>"}\''
        )
        post_result = await self._execute(post_cmd, session_id, timeout=30)
        raw["post_payload"] = post_result

        # Retrieve and check
        get_cmd = (
            f"curl -s -H 'Authorization: Bearer {token}' {comments_url} | grep -i 'script'"
        )
        get_result = await self._execute(get_cmd, session_id, timeout=30)
        raw["get_check"] = get_result

        if get_result.get("returncode") == 0:
            stdout = get_result.get("stdout", "")
            if "script" in stdout.lower() and "alert" in stdout.lower():
                findings.append(Finding(
                    session_id=session_id,
                    attack_type="xss_stored",
                    confidence=0.9,
                    endpoint=comments_url,
                    parameter="content",
                    evidence="Stored XSS payload rendered unescaped in API response",
                    status="confirmed",
                    cvss_score=6.1,
                    severity="medium",
                    remediation="HTML-encode stored content before rendering; use CSP",
                ))
            else:
                findings.append(Finding(
                    session_id=session_id,
                    attack_type="xss_stored",
                    confidence=0.8,
                    endpoint=comments_url,
                    evidence="Stored content appears properly encoded in response",
                    status="confirmed",
                    cvss_score=0.0,
                    severity="info",
                ))

        return {"findings": [f.model_dump() for f in findings], "raw": raw}

    # Task 4.3 – DOM XSS Check
    async def _run_dom_xss(self, session_id: str, target: str, **kwargs) -> Dict[str, Any]:
        """Test for DOM-based XSS using dalfox."""
        findings = []
        raw = {}

        test_url = kwargs.get("test_url", f"{target}/search?q=test")
        dalfox_cmd = f"dalfox url '{test_url}' --silence"
        dalfox_result = await self._execute(dalfox_cmd, session_id, timeout=120)
        raw["dalfox"] = dalfox_result

        if dalfox_result.get("returncode") == 0:
            stdout = dalfox_result.get("stdout", "")
            if "POC" in stdout or "Vulnerable" in stdout:
                findings.append(Finding(
                    session_id=session_id,
                    attack_type="xss_dom",
                    confidence=0.9,
                    endpoint=test_url,
                    evidence="Dalfox confirmed DOM-based XSS vulnerability",
                    status="confirmed",
                    cvss_score=6.1,
                    severity="medium",
                    remediation="Sanitize DOM-manipulating JavaScript; avoid innerHTML with user input",
                ))
            else:
                findings.append(Finding(
                    session_id=session_id,
                    attack_type="xss_dom",
                    confidence=0.7,
                    endpoint=test_url,
                    evidence="Dalfox did not detect DOM XSS",
                    status="potential",
                    cvss_score=0.0,
                    severity="info",
                ))

        return {"findings": [f.model_dump() for f in findings], "raw": raw}

    # Task 4.4 – XSS in HTTP Headers
    async def _run_header_xss(self, session_id: str, target: str, **kwargs) -> Dict[str, Any]:
        """Test if XSS payloads in headers reflect in response."""
        findings = []
        raw = {}

        payload = "<script>alert(1)</script>"
        cmd = (
            f"curl -s -H 'Referer: {payload}' "
            f"-H 'User-Agent: {payload}' "
            f"{target}/"
        )
        result = await self._execute(cmd, session_id, timeout=30)
        raw["header_xss"] = result

        if result.get("returncode") == 0:
            stdout = result.get("stdout", "")
            if payload in stdout or "alert(1)" in stdout:
                findings.append(Finding(
                    session_id=session_id,
                    attack_type="xss_header_reflected",
                    confidence=0.85,
                    endpoint=target,
                    parameter="Referer/User-Agent",
                    evidence="XSS payload reflected from HTTP header into response",
                    status="confirmed",
                    cvss_score=6.1,
                    severity="medium",
                    remediation="Encode all header values before rendering in responses",
                ))
            else:
                findings.append(Finding(
                    session_id=session_id,
                    attack_type="xss_header_reflected",
                    confidence=0.8,
                    endpoint=target,
                    evidence="HTTP header XSS payloads not reflected",
                    status="potential",
                    cvss_score=0.0,
                    severity="info",
                ))

        return {"findings": [f.model_dump() for f in findings], "raw": raw}

    # Task 4.5 – CSP Header Check
    async def _run_csp_check(self, session_id: str, target: str, **kwargs) -> Dict[str, Any]:
        """Validate Content-Security-Policy header."""
        findings = []
        raw = {}

        cmd = f"curl -sI {target} | grep -i 'content-security-policy'"
        result = await self._execute(cmd, session_id, timeout=30)
        raw["csp_header"] = result

        if result.get("returncode") == 0:
            csp = result.get("stdout", "").lower()
            if not csp:
                findings.append(Finding(
                    session_id=session_id,
                    attack_type="missing_csp",
                    confidence=0.95,
                    endpoint=target,
                    evidence="Content-Security-Policy header is missing",
                    status="confirmed",
                    cvss_score=3.7,
                    severity="low",
                    remediation="Deploy a strict CSP header",
                ))
            else:
                weaknesses = []
                if "unsafe-inline" in csp:
                    weaknesses.append("unsafe-inline")
                if "unsafe-eval" in csp:
                    weaknesses.append("unsafe-eval")
                if "*" in csp:
                    weaknesses.append("wildcard (*)")

                if weaknesses:
                    findings.append(Finding(
                        session_id=session_id,
                        attack_type="weak_csp",
                        confidence=0.9,
                        endpoint=target,
                        evidence=f"CSP contains weak directives: {', '.join(weaknesses)}",
                        status="confirmed",
                        cvss_score=5.3,
                        severity="medium",
                        remediation="Remove unsafe-inline, unsafe-eval, and wildcards from CSP",
                    ))
                else:
                    findings.append(Finding(
                        session_id=session_id,
                        attack_type="strong_csp",
                        confidence=1.0,
                        endpoint=target,
                        evidence="CSP header present without unsafe-inline or wildcards",
                        status="confirmed",
                        cvss_score=0.0,
                        severity="info",
                    ))

        return {"findings": [f.model_dump() for f in findings], "raw": raw}
