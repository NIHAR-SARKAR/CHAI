"""Reconnaissance tools module."""
import logging
import json
from typing import Dict, Any, List
from models.session import Finding
from tools.base import BaseTool
from utils.output_parser import OutputParser

logger = logging.getLogger(__name__)


class ReconTools(BaseTool):
    @property
    def tool_name(self) -> str:
        return "recon"

    @property
    def description(self) -> str:
        return "Passive and active reconnaissance tools"

    # ── Passive Recon ──────────────────────────────────────────────────────

    async def run_passive(self, session_id: str, target: str, **kwargs) -> Dict[str, Any]:
        """Run passive reconnaissance."""
        findings = []

        # WHOIS lookup
        whois_cmd = f"whois {target}"
        whois_result = await self._execute(whois_cmd, session_id, timeout=60)

        if whois_result.get("returncode") == 0:
            findings.append(Finding(
                session_id=session_id,
                attack_type="whois_lookup",
                confidence=1.0,
                endpoint=target,
                evidence=f"WHOIS data retrieved for {target}",
                status="confirmed",
                cvss_score=0.0,
                severity="info",
            ))

        # DNS enumeration
        dns_cmd = f"dig +short {target}"
        dns_result = await self._execute(dns_cmd, session_id, timeout=60)

        if dns_result.get("returncode") == 0:
            ips = [line.strip() for line in dns_result.get("stdout", "").splitlines() if line.strip()]
            findings.append(Finding(
                session_id=session_id,
                attack_type="dns_enum",
                confidence=1.0,
                endpoint=target,
                evidence=f"DNS records: {', '.join(ips[:5])}",
                status="confirmed",
                cvss_score=0.0,
                severity="info",
            ))

        return {"findings": [f.model_dump() for f in findings], "raw": {"whois": whois_result, "dns": dns_result}}

    # ── Active Recon ───────────────────────────────────────────────────────

    async def run_active(self, session_id: str, target: str, **kwargs) -> Dict[str, Any]:
        """Run comprehensive active reconnaissance."""
        findings: List[Finding] = []
        raw: Dict[str, Any] = {}

        # 1. Technology Fingerprinting
        tech_findings, tech_raw = await self._run_tech_fingerprint(session_id, target)
        findings.extend(tech_findings)
        raw["technology"] = tech_raw

        # 2. API Endpoint Discovery
        api_findings, api_raw = await self._run_api_discovery(session_id, target)
        findings.extend(api_findings)
        raw["api_discovery"] = api_raw

        # 3. Swagger / OpenAPI Exposure
        swagger_findings, swagger_raw = await self._check_swagger_paths(session_id, target)
        findings.extend(swagger_findings)
        raw["swagger_openapi"] = swagger_raw

        # 4. Port & Service Scan
        port_findings, port_raw = await self._run_port_scan(session_id, target)
        findings.extend(port_findings)
        raw["port_scan"] = port_raw

        # 5. Directory & File Bruteforce
        dir_findings, dir_raw = await self._run_dir_bruteforce(session_id, target)
        findings.extend(dir_findings)
        raw["dir_bruteforce"] = dir_raw

        return {"findings": [f.model_dump() for f in findings], "raw": raw}

    # ── Sub-tests ────────────────────────────────────────────────────────────

    async def _run_tech_fingerprint(self, session_id: str, target: str) -> tuple:
        """Task 1.1 – Technology Fingerprinting."""
        findings = []
        raw = {}

        # WhatWeb deep scan
        whatweb_cmd = f"whatweb -a 3 {target}"
        whatweb_result = await self._execute(whatweb_cmd, session_id, timeout=120)
        raw["whatweb"] = whatweb_result

        if whatweb_result.get("returncode") == 0:
            parsed = OutputParser.parse_whatweb(whatweb_result.get("stdout", ""))
            for p in parsed:
                findings.append(Finding(
                    session_id=session_id,
                    attack_type="technology_fingerprint",
                    confidence=0.9,
                    endpoint=target,
                    evidence=f"Technology detected: {p.get('plugin', 'unknown')}",
                    status="confirmed",
                    cvss_score=0.0,
                    severity="info",
                ))

        # curl -I for server headers
        curl_cmd = f"curl -s -I {target}"
        curl_result = await self._execute(curl_cmd, session_id, timeout=30)
        raw["curl_headers"] = curl_result

        if curl_result.get("returncode") == 0:
            headers = curl_result.get("stdout", "").lower()
            server_header = None
            for line in curl_result.get("stdout", "").splitlines():
                if line.lower().startswith("server:"):
                    server_header = line.split(":", 1)[1].strip()
                    break
            if server_header:
                findings.append(Finding(
                    session_id=session_id,
                    attack_type="server_banner",
                    confidence=0.95,
                    endpoint=target,
                    evidence=f"Server banner: {server_header}",
                    status="confirmed",
                    cvss_score=0.0,
                    severity="info",
                ))

        return findings, raw

    async def _run_api_discovery(self, session_id: str, target: str) -> tuple:
        """Task 1.2 – API Endpoint Discovery via ffuf."""
        findings = []
        raw = {}

        api_wordlist = "/usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt"
        ffuf_cmd = (
            f"ffuf -w {api_wordlist} -u {target}/FUZZ "
            f"-mc 200,201,204,301,302,401,403 -json -s"
        )
        ffuf_result = await self._execute(ffuf_cmd, session_id, timeout=180)
        raw["ffuf_api"] = ffuf_result

        discovered = []
        if ffuf_result.get("returncode") == 0:
            for line in ffuf_result.get("stdout", "").strip().splitlines():
                try:
                    entry = json.loads(line)
                    status = entry.get("status", 0)
                    url = entry.get("url", "")
                    discovered.append(f"{url} [{status}]")
                except json.JSONDecodeError:
                    continue

        if discovered:
            findings.append(Finding(
                session_id=session_id,
                attack_type="api_endpoint_discovery",
                confidence=0.85,
                endpoint=target,
                evidence=f"Discovered API endpoints: {', '.join(discovered[:10])}",
                status="confirmed",
                cvss_score=0.0,
                severity="info",
            ))
        else:
            findings.append(Finding(
                session_id=session_id,
                attack_type="api_endpoint_discovery",
                confidence=1.0,
                endpoint=target,
                evidence="No hidden API endpoints discovered",
                status="confirmed",
                cvss_score=0.0,
                severity="info",
            ))

        return findings, raw

    async def _check_swagger_paths(self, session_id: str, target: str) -> tuple:
        """Task 1.3 – Check Swagger / OpenAPI Exposure."""
        findings = []
        raw = {}

        swagger_paths = [
            "/swagger", "/swagger-ui", "/api-docs", "/openapi.json",
            "/v1/docs", "/swagger/index.html", "/v2/api-docs",
            "/api/swagger.json", "/swagger-ui.html",
        ]

        exposed = []
        for path in swagger_paths:
            cmd = f"curl -s -o /dev/null -w '%{{http_code}}' {target}{path}"
            result = await self._execute(cmd, session_id, timeout=15)
            raw[path] = result
            code = result.get("stdout", "").strip()
            if code in ("200", "301", "302"):
                exposed.append(f"{path} (HTTP {code})")

        if exposed:
            findings.append(Finding(
                session_id=session_id,
                attack_type="swagger_exposed",
                confidence=0.9,
                endpoint=target,
                evidence=f"Swagger/OpenAPI docs publicly accessible: {', '.join(exposed)}",
                status="confirmed",
                cvss_score=5.3,
                severity="medium",
                remediation="Disable or restrict access to Swagger/OpenAPI documentation in production",
            ))
        else:
            findings.append(Finding(
                session_id=session_id,
                attack_type="swagger_exposed",
                confidence=1.0,
                endpoint=target,
                evidence="Swagger/OpenAPI docs not publicly accessible",
                status="confirmed",
                cvss_score=0.0,
                severity="info",
            ))

        return findings, raw

    async def _run_port_scan(self, session_id: str, target: str) -> tuple:
        """Task 1.4 – Port & Service Scan."""
        findings = []
        raw = {}

        # Extract host from URL if needed
        host = target.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]

        nmap_cmd = f"nmap -sV -p 80,443,8080,8443,3000,5000,4000 {host}"
        nmap_result = await self._execute(nmap_cmd, session_id, timeout=300)
        raw["nmap"] = nmap_result

        if nmap_result.get("returncode") == 0:
            parsed = OutputParser.parse_nmap(nmap_result.get("stdout", ""))
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

        return findings, raw

    async def _run_dir_bruteforce(self, session_id: str, target: str) -> tuple:
        """Task 1.5 – Directory & File Bruteforce."""
        findings = []
        raw = {}

        wordlist = "/usr/share/seclists/Discovery/Web-Content/common.txt"
        gobuster_cmd = (
            f"gobuster dir -u {target} -w {wordlist} "
            f"-x php,html,js,json -t 30 -q -o /tmp/gobuster_{session_id}.json --format json"
        )
        gobuster_result = await self._execute(gobuster_cmd, session_id, timeout=300)
        raw["gobuster"] = gobuster_result

        discovered = []
        if gobuster_result.get("returncode") == 0:
            # Parse JSON output if available
            import os
            json_path = f"/tmp/gobuster_{session_id}.json"
            if os.path.exists(json_path):
                try:
                    with open(json_path) as f:
                        data = json.load(f)
                        for entry in data.get("results", []):
                            discovered.append(f"{entry.get('Path')} [{entry.get('StatusCode')}]")
                except Exception:
                    pass

        sensitive_patterns = ["admin", "debug", "config", "backup", "env", "internal", "actuator"]
        sensitive_found = [d for d in discovered if any(p in d.lower() for p in sensitive_patterns)]

        if sensitive_found:
            findings.append(Finding(
                session_id=session_id,
                attack_type="sensitive_path_exposed",
                confidence=0.85,
                endpoint=target,
                evidence=f"Sensitive admin/debug paths exposed: {', '.join(sensitive_found[:10])}",
                status="confirmed",
                cvss_score=5.3,
                severity="medium",
                remediation="Restrict access to administrative and debug endpoints",
            ))

        if discovered and not sensitive_found:
            findings.append(Finding(
                session_id=session_id,
                attack_type="directory_bruteforce",
                confidence=0.9,
                endpoint=target,
                evidence=f"Discovered paths: {', '.join(discovered[:10])}",
                status="confirmed",
                cvss_score=0.0,
                severity="info",
            ))

        return findings, raw
