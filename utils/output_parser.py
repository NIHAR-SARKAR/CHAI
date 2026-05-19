"""Output parsing utilities for security tools."""
import re
import json
from typing import List, Dict, Any, Optional


class OutputParser:
    """Parse output from various security tools."""

    @staticmethod
    def parse_nmap(output: str) -> List[Dict[str, Any]]:
        """Parse nmap output."""
        findings = []
        # Extract open ports
        port_pattern = r"(\d+)/(tcp|udp)\s+(open|filtered|closed)\s+(\S+)"
        for match in re.finditer(port_pattern, output):
            findings.append({
                "port": int(match.group(1)),
                "protocol": match.group(2),
                "state": match.group(3),
                "service": match.group(4),
            })
        return findings

    @staticmethod
    def parse_nuclei(output: str) -> List[Dict[str, Any]]:
        """Parse nuclei JSON output."""
        findings = []
        for line in output.strip().split("\n"):
            try:
                entry = json.loads(line)
                findings.append({
                    "template": entry.get("template-id", ""),
                    "severity": entry.get("info", {}).get("severity", "info"),
                    "host": entry.get("host", ""),
                    "matched": entry.get("matched-at", ""),
                    "extracted": entry.get("extracted-results", []),
                })
            except json.JSONDecodeError:
                continue
        return findings

    @staticmethod
    def parse_sqlmap(output: str) -> List[Dict[str, Any]]:
        """Parse sqlmap output."""
        findings = []
        if "sqlmap identified" in output.lower():
            # Extract injection type
            injection_pattern = r"Parameter \'(.+?)\' is (.+?)\."
            for match in re.finditer(injection_pattern, output):
                findings.append({
                    "parameter": match.group(1),
                    "type": match.group(2),
                    "tool": "sqlmap",
                })
        return findings

    @staticmethod
    def parse_whatweb(output: str) -> List[Dict[str, Any]]:
        """Parse whatweb output."""
        findings = []
        # WhatWeb output format: URL [plugin1][plugin2]...
        plugin_pattern = r"\[([^\]]+)\]"
        for match in re.finditer(plugin_pattern, output):
            findings.append({
                "plugin": match.group(1),
                "tool": "whatweb",
            })
        return findings

    @staticmethod
    def parse_feroxbuster(output: str) -> List[Dict[str, Any]]:
        """Parse feroxbuster JSON output."""
        findings = []
        for line in output.strip().split("\n"):
            try:
                entry = json.loads(line)
                if entry.get("status") in (200, 301, 302, 403, 401):
                    findings.append({
                        "url": entry.get("url", ""),
                        "status": entry.get("status"),
                        "size": entry.get("content_length", 0),
                        "tool": "feroxbuster",
                    })
            except json.JSONDecodeError:
                continue
        return findings

    @staticmethod
    def parse_generic(output: str, tool_name: str) -> List[Dict[str, Any]]:
        """Generic parser for unknown tools."""
        return [{"raw_output": output[:1000], "tool": tool_name}]
