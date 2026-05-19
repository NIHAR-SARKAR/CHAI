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

    async def run_active(self, session_id: str, target: str, **kwargs) -> Dict[str, Any]:
        """Run active reconnaissance."""
        findings = []

        # WhatWeb fingerprinting
        whatweb_cmd = f"whatweb -a 1 {target}"
        whatweb_result = await self._execute(whatweb_cmd, session_id, timeout=120)

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

        return {"findings": [f.model_dump() for f in findings], "raw": {"whatweb": whatweb_result}}
