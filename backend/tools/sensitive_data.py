"""Sensitive Data Exposure testing tools module."""
import logging
import json
import re
from typing import Dict, Any, List
from models.session import Finding
from tools.base import BaseTool

logger = logging.getLogger(__name__)


class SensitiveDataTools(BaseTool):
    @property
    def tool_name(self) -> str:
        return "sensitive_data"

    @property
    def description(self) -> str:
        return "Sensitive data exposure testing (secrets, PII, backups, HTTP/HTTPS)"

    async def run_sensitive_data(self, session_id: str, target: str, test_type: str = "js_secrets", **kwargs) -> Dict[str, Any]:
        """Run sensitive data exposure tests."""
        if test_type == "js_secrets":
            return await self._run_js_secrets(session_id, target, **kwargs)
        elif test_type == "api_overexposure":
            return await self._run_api_overexposure(session_id, target, **kwargs)
        elif test_type == "http_https":
            return await self._run_http_https(session_id, target, **kwargs)
        elif test_type == "git_backup":
            return await self._run_git_backup(session_id, target, **kwargs)
        else:
            return {"findings": [], "raw": {}, "error": f"Unknown test_type: {test_type}"}

    # Task 7.1 – JS Source Code Review for Secrets
    async def _run_js_secrets(self, session_id: str, target: str, **kwargs) -> Dict[str, Any]:
        """Download JS bundles and search for secrets."""
        findings = []
        raw = {}

        # Get JS file URLs from the main page
        cmd_js_urls = (
            f"curl -s {target} | grep -oE 'src=\"[^\"]+\\.js\"' | "
            f"sed 's/src=\"//;s/\"//'"
        )
        result_urls = await self._execute(cmd_js_urls, session_id, timeout=30)
        raw["js_urls"] = result_urls

        secrets_found = []
        patterns = [
            ("api_key", r"api[_-]?key\s*[:=]\s*[\"'][^\"']{16,}[\"']"),
            ("secret", r"secret\s*[:=]\s*[\"'][^\"']{8,}[\"']"),
            ("password", r"password\s*[:=]\s*[\"'][^\"']{4,}[\"']"),
            ("token", r"token\s*[:=]\s*[\"'][^\"']{10,}[\"']"),
            ("private_key", r"private[_-]?key"),
            ("aws_key", r"AKIA[0-9A-Z]{16}"),
            ("mongodb", r"mongodb(\+srv)?://[^\s\"']+"),
        ]

        if result_urls.get("returncode") == 0:
            js_files = [line.strip() for line in result_urls.get("stdout", "").splitlines() if line.strip()]
            for js_file in js_files:
                if not js_file.startswith("http"):
                    js_file = f"{target}{js_file}"

                cmd_content = f"curl -s {js_file}"
                result_content = await self._execute(cmd_content, session_id, timeout=30)
                raw[js_file] = result_content

                if result_content.get("returncode") == 0:
                    content = result_content.get("stdout", "")
                    for secret_type, pattern in patterns:
                        matches = re.findall(pattern, content, re.IGNORECASE)
                        for match in matches[:3]:  # Limit matches per file
                            secrets_found.append(f"{secret_type} in {js_file}: {str(match)[:50]}")

        if secrets_found:
            findings.append(Finding(
                session_id=session_id,
                attack_type="secrets_in_js",
                confidence=0.9,
                endpoint=target,
                evidence=f"Secrets found in JS source: {', '.join(secrets_found[:5])}",
                status="confirmed",
                cvss_score=7.5,
                severity="high",
                remediation="Remove secrets from client-side code; use environment variables and backend proxies",
            ))
        else:
            findings.append(Finding(
                session_id=session_id,
                attack_type="secrets_in_js",
                confidence=0.9,
                endpoint=target,
                evidence="No obvious secrets found in JS source code",
                status="confirmed",
                cvss_score=0.0,
                severity="info",
            ))

        return {"findings": [f.model_dump() for f in findings], "raw": raw}

    # Task 7.2 – API Response Over-exposure
    async def _run_api_overexposure(self, session_id: str, target: str, **kwargs) -> Dict[str, Any]:
        """Check if API responses include sensitive fields."""
        findings = []
        raw = {}

        token = kwargs.get("token", "")
        me_url = kwargs.get("me_url", f"{target}/api/users/me")

        cmd = f"curl -s -H 'Authorization: Bearer {token}' {me_url}"
        result = await self._execute(cmd, session_id, timeout=30)
        raw["api_response"] = result

        if result.get("returncode") == 0:
            try:
                data = json.loads(result.get("stdout", "{}"))
                response_str = json.dumps(data).lower()
                sensitive_fields = [
                    "password", "passwordhash", "secret", "ssn",
                    "creditcard", "cvv", "pin", "apikey", "privatekey",
                ]
                found = [f for f in sensitive_fields if f in response_str]

                if found:
                    findings.append(Finding(
                        session_id=session_id,
                        attack_type="api_overexposure",
                        confidence=0.95,
                        endpoint=me_url,
                        evidence=f"Sensitive fields leaked in API response: {', '.join(found)}",
                        status="confirmed",
                        cvss_score=7.5,
                        severity="high",
                        remediation="Filter sensitive fields from API responses; never return password hashes",
                    ))
                else:
                    findings.append(Finding(
                        session_id=session_id,
                        attack_type="api_overexposure",
                        confidence=0.9,
                        endpoint=me_url,
                        evidence="No sensitive fields found in API response",
                        status="confirmed",
                        cvss_score=0.0,
                        severity="info",
                    ))
            except json.JSONDecodeError:
                findings.append(Finding(
                    session_id=session_id,
                    attack_type="api_overexposure",
                    confidence=0.5,
                    endpoint=me_url,
                    evidence="API response is not valid JSON; manual review needed",
                    status="potential",
                    cvss_score=0.0,
                    severity="info",
                ))

        return {"findings": [f.model_dump() for f in findings], "raw": raw}

    # Task 7.3 – HTTP vs HTTPS
    async def _run_http_https(self, session_id: str, target: str, **kwargs) -> Dict[str, Any]:
        """Test HTTP redirect to HTTPS and HSTS header."""
        findings = []
        raw = {}

        # Extract host from URL
        host = target.replace("https://", "").replace("http://", "").split("/")[0]

        # Test HTTP redirect
        cmd_http = f"curl -sI 'http://{host}' | head -5"
        result_http = await self._execute(cmd_http, session_id, timeout=30)
        raw["http_redirect"] = result_http

        redirects = False
        if result_http.get("returncode") == 0:
            stdout = result_http.get("stdout", "")
            if "301" in stdout or "302" in stdout or "location: https" in stdout.lower():
                redirects = True
                findings.append(Finding(
                    session_id=session_id,
                    attack_type="http_redirect",
                    confidence=1.0,
                    endpoint=f"http://{host}",
                    evidence="HTTP correctly redirects to HTTPS",
                    status="confirmed",
                    cvss_score=0.0,
                    severity="info",
                ))
            else:
                findings.append(Finding(
                    session_id=session_id,
                    attack_type="http_no_redirect",
                    confidence=0.9,
                    endpoint=f"http://{host}",
                    evidence="HTTP does not redirect to HTTPS",
                    status="confirmed",
                    cvss_score=5.3,
                    severity="medium",
                    remediation="Enforce 301 redirect from HTTP to HTTPS on all endpoints",
                ))

        # Check HSTS
        cmd_hsts = f"curl -sI 'https://{host}' | grep -i 'strict-transport'"
        result_hsts = await self._execute(cmd_hsts, session_id, timeout=30)
        raw["hsts"] = result_hsts

        if result_hsts.get("returncode") == 0:
            hsts = result_hsts.get("stdout", "").strip()
            if not hsts:
                findings.append(Finding(
                    session_id=session_id,
                    attack_type="missing_hsts",
                    confidence=0.9,
                    endpoint=f"https://{host}",
                    evidence="HSTS header missing",
                    status="confirmed",
                    cvss_score=3.7,
                    severity="low",
                    remediation="Add Strict-Transport-Security header with max-age >= 31536000",
                ))
            else:
                findings.append(Finding(
                    session_id=session_id,
                    attack_type="hsts_present",
                    confidence=1.0,
                    endpoint=f"https://{host}",
                    evidence=f"HSTS header present: {hsts}",
                    status="confirmed",
                    cvss_score=0.0,
                    severity="info",
                ))

        return {"findings": [f.model_dump() for f in findings], "raw": raw}

    # Task 7.4 – Git / Backup File Exposure
    async def _run_git_backup(self, session_id: str, target: str, **kwargs) -> Dict[str, Any]:
        """Check for exposed git config, .env, and backup files."""
        findings = []
        raw = {}

        sensitive_files = [
            "/.git/config", "/.env", "/.env.local",
            "/backup.sql", "/dump.sql", "/config.bak",
            "/web.config.bak",
        ]

        exposed = []
        for file_path in sensitive_files:
            url = f"{target}{file_path}"
            cmd = f"curl -s -o /dev/null -w '%{{http_code}}' {url}"
            result = await self._execute(cmd, session_id, timeout=15)
            raw[file_path] = result

            if result.get("returncode") == 0:
                code = result.get("stdout", "").strip()
                if code == "200":
                    exposed.append(file_path)

        if exposed:
            findings.append(Finding(
                session_id=session_id,
                attack_type="sensitive_file_exposure",
                confidence=0.95,
                endpoint=target,
                evidence=f"Sensitive files accessible: {', '.join(exposed)}",
                status="confirmed",
                cvss_score=7.5,
                severity="high",
                remediation="Remove or restrict access to .env, .git, and backup files",
            ))
        else:
            findings.append(Finding(
                session_id=session_id,
                attack_type="sensitive_file_exposure",
                confidence=0.95,
                endpoint=target,
                evidence="No sensitive backup/config files publicly accessible",
                status="confirmed",
                cvss_score=0.0,
                severity="info",
            ))

        return {"findings": [f.model_dump() for f in findings], "raw": raw}
