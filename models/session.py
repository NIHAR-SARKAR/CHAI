"""Session and Finding data models."""
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional, Any


@dataclass
class Finding:
    """A single security finding discovered during testing."""
    session_id: str
    attack_type: str
    confidence: float = 0.5
    endpoint: str = ""
    parameter: Optional[str] = None
    evidence: str = ""
    status: str = "potential"  # potential | confirmed | false_positive
    cvss_score: Optional[float] = None
    severity: Optional[str] = None  # critical | high | medium | low | info
    remediation: Optional[str] = None
    metadata: dict = field(default_factory=dict)
    created_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())

    def model_dump(self) -> dict:
        return {
            "session_id": self.session_id,
            "attack_type": self.attack_type,
            "confidence": self.confidence,
            "endpoint": self.endpoint,
            "parameter": self.parameter,
            "evidence": self.evidence,
            "status": self.status,
            "cvss_score": self.cvss_score,
            "severity": self.severity,
            "remediation": self.remediation,
            "metadata": self.metadata,
            "created_at": self.created_at,
        }


@dataclass
class Session:
    """A penetration testing session."""
    session_id: str
    target: str
    test_type: str = "web_app"
    scope: list = field(default_factory=list)
    status: str = "initialized"  # initialized | running | paused | completed | failed
    created_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    updated_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    findings_count: int = 0
    metadata: dict = field(default_factory=dict)
