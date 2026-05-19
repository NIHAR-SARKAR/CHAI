"""Proof of Concept generation tools module."""
import logging
from typing import Dict, Any
from models.session import Finding
from tools.base import BaseTool

logger = logging.getLogger(__name__)


class PocTools(BaseTool):
    @property
    def tool_name(self) -> str:
        return "poc"

    @property
    def description(self) -> str:
        return "Proof of Concept generation tools"

    async def run_poc(self, session_id: str, finding_id: str, **kwargs) -> Dict[str, Any]:
        """Generate a proof of concept for a finding."""
        findings = []

        # Get the finding from session manager
        session_findings = await self._session.get_findings(session_id)
        target_finding = None
        for f in session_findings:
            if hasattr(f, 'id') and f.id == finding_id:
                target_finding = f
                break

        if not target_finding:
            return {
                "findings": [],
                "error": f"Finding {finding_id} not found",
                "raw": {},
            }

        # Generate PoC based on finding type
        poc_content = f"""# Proof of Concept

## Finding: {target_finding.attack_type}
## Target: {target_finding.endpoint}
## Evidence: {target_finding.evidence}

### Steps to Reproduce:
1. Access {target_finding.endpoint}
2. Observe the vulnerability

### Impact:
{target_finding.severity or 'Unknown'} severity issue detected.

### Recommendation:
Review and remediate the identified vulnerability.
"""

        findings.append(Finding(
            session_id=session_id,
            attack_type="poc_generated",
            confidence=1.0,
            endpoint=target_finding.endpoint,
            evidence=poc_content,
            status="confirmed",
            cvss_score=0.0,
            severity="info",
        ))

        return {"findings": [f.model_dump() for f in findings], "raw": {"poc": poc_content}}
