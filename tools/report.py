"""Report generation tools module."""
import logging
from pathlib import Path
from datetime import datetime
from typing import Dict, Any, Optional
from models.session import Finding
from tools.base import BaseTool

logger = logging.getLogger(__name__)


class ReportTools(BaseTool):
    @property
    def tool_name(self) -> str:
        return "report"

    @property
    def description(self) -> str:
        return "Penetration test report generation"

    async def generate_report(
        self,
        session_id: str,
        format: str = "markdown",
        ai_narrative: Optional[Any] = None,
        **kwargs
    ) -> str:
        """Generate a penetration test report."""
        session = await self._session.get_session(session_id)
        findings = await self._session.get_findings(session_id)

        if not session:
            raise ValueError(f"Session {session_id} not found")

        # Generate report
        if format == "markdown":
            report_path = await self._generate_markdown(session, findings, ai_narrative)
        elif format == "json":
            report_path = await self._generate_json(session, findings, ai_narrative)
        else:
            raise ValueError(f"Unsupported format: {format}")

        return report_path

    async def _generate_markdown(
        self,
        session,
        findings: list,
        ai_narrative: Optional[Any] = None
    ) -> str:
        """Generate Markdown report."""
        reports_dir = Path("/opt/sessions/reports")
        reports_dir.mkdir(parents=True, exist_ok=True)

        report_path = reports_dir / f"{session.session_id}.md"

        # Build report content
        lines = [
            f"# Penetration Test Report",
            f"",
            f"**Target:** {session.target}",
            f"**Test Type:** {session.test_type}",
            f"**Session ID:** {session.session_id}",
            f"**Date:** {session.created_at}",
            f"**Status:** {session.status}",
            f"",
            f"---",
            f"",
        ]

        # AI Narrative
        if ai_narrative:
            lines.extend([
                f"## Executive Summary",
                f"",
                ai_narrative.executive_summary,
                f"",
                f"### Risk Narrative",
                f"",
                ai_narrative.risk_narrative,
                f"",
                f"### Remediation Priorities",
                f"",
            ])
            for i, item in enumerate(ai_narrative.remediation_priorities, 1):
                lines.append(f"{i}. **{item.get('action', 'N/A')}** — {item.get('reason', '')}")
            lines.append("")

        # Findings Summary
        lines.extend([
            f"## Findings Summary",
            f"",
            f"**Total Findings:** {len(findings)}",
            f"",
        ])

        # Group by severity
        severity_order = ["critical", "high", "medium", "low", "info"]
        by_severity = {s: [] for s in severity_order}

        for f in findings:
            severity = f.severity or "info"
            if severity in by_severity:
                by_severity[severity].append(f)

        for severity in severity_order:
            items = by_severity[severity]
            if items:
                lines.extend([
                    f"### {severity.upper()} ({len(items)})",
                    f"",
                ])
                for f in items:
                    lines.extend([
                        f"- **{f.attack_type}** — {f.endpoint}",
                        f"  - Evidence: {f.evidence}",
                        f"  - CVSS: {f.cvss_score or 'N/A'}",
                        f"  - Status: {f.status}",
                        f"",
                    ])

        # Detailed Findings
        lines.extend([
            f"## Detailed Findings",
            f"",
        ])

        for i, f in enumerate(findings, 1):
            lines.extend([
                f"### {i}. {f.attack_type}",
                f"",
                f"- **Endpoint:** {f.endpoint}",
                f"- **Parameter:** {f.parameter or 'N/A'}",
                f"- **Evidence:** {f.evidence}",
                f"- **Severity:** {f.severity or 'N/A'}",
                f"- **CVSS Score:** {f.cvss_score or 'N/A'}",
                f"- **Confidence:** {f.confidence}",
                f"- **Status:** {f.status}",
                f"- **Remediation:** {f.remediation or 'N/A'}",
                f"",
            ])

        # Write report
        report_path.write_text("\n".join(lines))
        logger.info(f"Report generated: {report_path}")

        return str(report_path)

    async def _generate_json(
        self,
        session,
        findings: list,
        ai_narrative: Optional[Any] = None
    ) -> str:
        """Generate JSON report."""
        import json

        reports_dir = Path("/opt/sessions/reports")
        reports_dir.mkdir(parents=True, exist_ok=True)

        report_path = reports_dir / f"{session.session_id}.json"

        report_data = {
            "metadata": {
                "target": session.target,
                "test_type": session.test_type,
                "session_id": session.session_id,
                "created_at": session.created_at,
                "status": session.status,
            },
            "ai_narrative": {
                "executive_summary": ai_narrative.executive_summary if ai_narrative else "",
                "risk_narrative": ai_narrative.risk_narrative if ai_narrative else "",
                "remediation_priorities": ai_narrative.remediation_priorities if ai_narrative else [],
            },
            "findings": [
                {
                    "attack_type": f.attack_type,
                    "endpoint": f.endpoint,
                    "parameter": f.parameter,
                    "evidence": f.evidence,
                    "severity": f.severity,
                    "cvss_score": f.cvss_score,
                    "confidence": f.confidence,
                    "status": f.status,
                    "remediation": f.remediation,
                }
                for f in findings
            ],
            "summary": {
                "total": len(findings),
                "by_severity": {},
            }
        }

        # Count by severity
        for f in findings:
            severity = f.severity or "info"
            report_data["summary"]["by_severity"][severity] = report_data["summary"]["by_severity"].get(severity, 0) + 1

        report_path.write_text(json.dumps(report_data, indent=2))
        logger.info(f"JSON report generated: {report_path}")

        return str(report_path)
