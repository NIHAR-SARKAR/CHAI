"""Pydantic schemas for AI planner and execution loop."""
from pydantic import BaseModel, Field
from typing import Any, Optional


class ActionPlan(BaseModel):
    """AI planner output: what to test next."""
    session_id: str
    next_tool: str
    args: dict[str, Any] = Field(default_factory=dict)
    rationale: str = ""
    expected_finding_type: str = ""
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)
    provider_used: str = ""
    tokens_used: int = 0


class EvalResult(BaseModel):
    """AI evaluation output: should we continue?"""
    session_id: str
    should_continue: bool
    reason: str = ""
    priority_findings: list[str] = Field(default_factory=list)
    risk_score: int = Field(default=0, ge=0, le=10)
    provider_used: str = ""
    tokens_used: int = 0


class ReportNarrative(BaseModel):
    """AI-generated report narrative."""
    executive_summary: str = ""
    risk_narrative: str = ""
    remediation_priorities: list[dict] = Field(default_factory=list)
    provider_used: str = ""
    tokens_used: int = 0


class PhaseResult(BaseModel):
    """Result of a single execution phase."""
    findings: list[Any] = Field(default_factory=list)
    critical_count: int = 0
    error: Optional[str] = None


class FinalResult(BaseModel):
    """Final result of an autonomous scan."""
    session_id: str
    phases_completed: int
    total_findings: int
    critical_count: int = 0
    high_count: int = 0
    risk_score: Optional[int] = None
