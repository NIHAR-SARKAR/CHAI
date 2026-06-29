"""Session and Finding data models."""
from datetime import datetime, timezone
from typing import Optional, Any

from pydantic import BaseModel, Field


class Finding(BaseModel):
    """A single security finding discovered during testing."""
    session_id: str
    attack_type: str
    confidence: float = 0.5
    endpoint: str = ""
    parameter: Optional[str] = None
    evidence: str = ""
    status: str = "potential"
    cvss_score: Optional[float] = None
    severity: Optional[str] = None
    remediation: Optional[str] = None
    metadata: dict[str, Any] = Field(default_factory=dict)
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class Session(BaseModel):
    """A penetration testing session."""
    session_id: str
    target: str
    test_type: str = "web_app"
    scope: list[str] = Field(default_factory=list)
    status: str = "initialized"
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    updated_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    findings_count: int = 0
    metadata: dict[str, Any] = Field(default_factory=dict)
