"""Analysis tools module."""
import logging
import json
from typing import Dict, Any, List
from models.session import Finding
from tools.base import BaseTool

logger = logging.getLogger(__name__)


class AnalyzeTools(BaseTool):
    @property
    def tool_name(self) -> str:
        return "analyze"

    @property
    def description(self) -> str:
        return "Findings analysis and digest generation"

    async def run_analyze(self, session_id: str, **kwargs) -> Dict[str, Any]:
        """Analyze findings and generate summary."""
        findings = await self._session.get_findings(session_id)

        # Categorize findings
        by_type = {}
        by_severity = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}

        for f in findings:
            attack_type = f.attack_type
            if attack_type not in by_type:
                by_type[attack_type] = []
            by_type[attack_type].append(f)

            severity = f.severity or "info"
            if severity in by_severity:
                by_severity[severity] += 1

        summary = {
            "total_findings": len(findings),
            "by_type": {k: len(v) for k, v in by_type.items()},
            "by_severity": by_severity,
            "confirmed": len([f for f in findings if f.status == "confirmed"]),
            "potential": len([f for f in findings if f.status == "potential"]),
        }

        return {
            "findings": [],
            "raw": {"summary": summary},
            "summary": summary,
        }

    async def build_planner_digest(self, session_id: str) -> Dict[str, Any]:
        """Build a compact digest for the AI planner."""
        session = await self._session.get_session(session_id)
        findings = await self._session.get_findings(session_id)

        # Get already tested items from audit log
        # Simplified: use findings as proxy for tested items
        already_tested = list(set([f.attack_type for f in findings]))

        # Get confirmed findings with high confidence
        confirmed = [
            {
                "attack_type": f.attack_type,
                "endpoint": f.endpoint,
                "severity": f.severity,
                "cvss": f.cvss_score,
            }
            for f in findings
            if f.status == "confirmed" and f.confidence >= 0.7
        ]

        return {
            "target": session.target if session else "unknown",
            "scope": session.scope if session else [],
            "already_tested": already_tested,
            "confirmed_findings": confirmed,
            "total_findings": len(findings),
            "test_type": session.test_type if session else "web_app",
        }
