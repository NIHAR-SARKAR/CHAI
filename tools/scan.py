"""Scanning tools module."""
import logging
import json
from typing import Dict, Any, List
from models.session import Finding
from tools.base import BaseTool
from utils.output_parser import OutputParser
from utils.cvss_calculator import CVSSCalculator

logger = logging.getLogger(__name__)


class ScanTools(BaseTool):
    @property
    def tool_name(self) -> str:
        return "scan"

    @property
    def description(self) -> str:
        return "Vulnerability and port scanning tools"

    async def run_scan(self, session_id: str, target: str, scanner: str = "nuclei", **kwargs) -> Dict[str, Any]:
        """Run vulnerability scan."""
        findings = []

        if scanner == "nuclei":
            cmd = f"nuclei -u {target} -silent -jsonl"
            result = await self._execute(cmd, session_id, timeout=300)

            if result.get("returncode") == 0:
                parsed = OutputParser.parse_nuclei(result.get("stdout", ""))
                for p in parsed:
                    severity = p.get("severity", "info")
                    cvss = CVSSCalculator.from_finding(p.get("template", "unknown"))
                    findings.append(Finding(
                        session_id=session_id,
                        attack_type=p.get("template", "unknown"),
                        confidence=0.8,
                        endpoint=p.get("host", target),
                        evidence=f"Nuclei template: {p.get('template', 'unknown')}, matched: {p.get('matched', '')}",
                        status="confirmed",
                        cvss_score=cvss,
                        severity=severity,
                    ))

        elif scanner == "nmap":
            ports = kwargs.get("ports", "1-65535")
            cmd = f"nmap -sV -p {ports} {target}"
            result = await self._execute(cmd, session_id, timeout=300)

            if result.get("returncode") == 0:
                parsed = OutputParser.parse_nmap(result.get("stdout", ""))
                for p in parsed:
                    findings.append(Finding(
                        session_id=session_id,
                        attack_type="port_discovery",
                        confidence=1.0,
                        endpoint=f"{target}:{p.get('port')}",
                        evidence=f"{p.get('protocol')}/{p.get('port')} {p.get('state')} {p.get('service')}",
                        status="confirmed",
                        cvss_score=0.0,
                        severity="info",
                    ))

        return {"findings": [f.model_dump() for f in findings], "raw": {scanner: result}}
