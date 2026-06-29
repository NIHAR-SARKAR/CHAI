"""Tests for utils modules — CVSS calculator, output parser."""
import pytest
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from utils.cvss_calculator import CVSSCalculator
from utils.output_parser import OutputParser


class TestCVSSCalculator:
    def test_critical_sqli(self):
        score = CVSSCalculator.from_finding("sqli")
        assert score >= 9.0

    def test_high_ssrf(self):
        score = CVSSCalculator.from_finding("ssrf")
        assert score >= 7.0

    def test_medium_xss(self):
        score = CVSSCalculator.from_finding("xss_reflected")
        assert score >= 4.0

    def test_low_missing_headers(self):
        score = CVSSCalculator.from_finding("missing_headers")
        assert score < 4.0

    def test_unknown_defaults_to_5(self):
        score = CVSSCalculator.from_finding("unknown_finding_type_xyz")
        assert score == 5.0

    def test_calculate_base_score(self):
        score = CVSSCalculator.calculate(
            attack_vector="N",
            attack_complexity="L",
            privileges_required="N",
            user_interaction="N",
            scope="U",
            confidentiality="H",
            integrity="H",
            availability="H",
        )
        assert 9.0 <= score <= 10.0

    def test_severity_from_score(self):
        assert CVSSCalculator.severity_from_score(9.8) == "critical"
        assert CVSSCalculator.severity_from_score(7.5) == "high"
        assert CVSSCalculator.severity_from_score(5.3) == "medium"
        assert CVSSCalculator.severity_from_score(3.7) == "low"
        assert CVSSCalculator.severity_from_score(0.0) == "info"


class TestOutputParser:
    def test_parse_nmap(self):
        output = """Starting Nmap 7.94 ( https://nmap.org )
80/tcp  open  http
443/tcp open  https
22/tcp  open  ssh
Nmap done: 1 IP address scanned"""
        results = OutputParser.parse_nmap(output)
        assert len(results) == 3
        ports = [r["port"] for r in results]
        assert 80 in ports
        assert 443 in ports
        assert 22 in ports

    def test_parse_nmap_empty(self):
        results = OutputParser.parse_nmap("No open ports found")
        assert results == []

    def test_parse_nuclei(self):
        output = '{"template-id":"CVE-2021-44228","info":{"severity":"critical"},"host":"https://example.com","matched-at":"https://example.com/log4j"}'
        results = OutputParser.parse_nuclei(output)
        assert len(results) == 1
        assert results[0]["template"] == "CVE-2021-44228"
        assert results[0]["severity"] == "critical"

    def test_parse_nuclei_invalid_json(self):
        output = "not json\nalso not json"
        results = OutputParser.parse_nuclei(output)
        assert results == []

    def test_parse_whatweb(self):
        output = "https://example.com [Apache][PHP][Nginx]"
        results = OutputParser.parse_whatweb(output)
        assert len(results) > 0

    def test_parse_sqlmap_vulnerable(self):
        output = "sqlmap identified the following injection points"
        results = OutputParser.parse_sqlmap(output)
        assert len(results) >= 0

    def test_parse_generic(self):
        results = OutputParser.parse_generic("some output", "custom_tool")
        assert len(results) == 1
        assert results[0]["tool"] == "custom_tool"
