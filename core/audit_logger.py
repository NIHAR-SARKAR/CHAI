"""Immutable command + AI decision logging."""
import logging
import json
from pathlib import Path
from datetime import datetime
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)


class AuditLogger:
    def __init__(self, log_path: str):
        self._log_path = Path(log_path)
        self._log_path.parent.mkdir(parents=True, exist_ok=True)

        # Set up file handler
        self._file_handler = logging.FileHandler(log_path)
        self._file_handler.setLevel(logging.INFO)
        formatter = logging.Formatter(
            '%(asctime)s | %(levelname)s | %(message)s'
        )
        self._file_handler.setFormatter(formatter)

        # Create dedicated logger for audit
        self._audit_logger = logging.getLogger("audit")
        self._audit_logger.setLevel(logging.INFO)
        self._audit_logger.addHandler(self._file_handler)
        self._audit_logger.propagate = False

    def log_command(
        self,
        session_id: str,
        command: str,
        result: Dict[str, Any],
        user: str = "system",
        metadata: Optional[Dict[str, Any]] = None,
    ):
        """Log a command execution."""
        entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "type": "command",
            "session_id": session_id,
            "user": user,
            "command": command,
            "result": {
                "returncode": result.get("returncode"),
                "duration_ms": result.get("duration_ms"),
                "sandbox_level": result.get("sandbox_level"),
                "timeout": result.get("timeout", False),
            },
            "metadata": metadata or {},
        }
        self._audit_logger.info(json.dumps(entry))

    def log_ai_decision(
        self,
        session_id: str,
        decision_type: str,
        decision: Dict[str, Any],
        provider: str,
        tokens_used: int,
        latency_ms: int,
    ):
        """Log an AI decision."""
        entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "type": "ai_decision",
            "session_id": session_id,
            "decision_type": decision_type,
            "provider": provider,
            "tokens_used": tokens_used,
            "latency_ms": latency_ms,
            "decision": decision,
        }
        self._audit_logger.info(json.dumps(entry))

    def log_security_event(
        self,
        session_id: str,
        event_type: str,
        description: str,
        severity: str = "info",
        details: Optional[Dict[str, Any]] = None,
    ):
        """Log a security event."""
        entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "type": "security_event",
            "session_id": session_id,
            "event_type": event_type,
            "severity": severity,
            "description": description,
            "details": details or {},
        }
        self._audit_logger.info(json.dumps(entry))

    def log_session_event(
        self,
        session_id: str,
        event: str,
        details: Optional[Dict[str, Any]] = None,
    ):
        """Log a session lifecycle event."""
        entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "type": "session",
            "session_id": session_id,
            "event": event,
            "details": details or {},
        }
        self._audit_logger.info(json.dumps(entry))
