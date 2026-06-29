"""Tests for core.audit_logger — logging and secret redaction."""
import pytest
import sys
import os
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from core.audit_logger import AuditLogger, _redact


class TestSecretRedaction:
    def test_redact_api_key(self):
        text = 'api_key: "sk-1234567890abcdef"'
        result = _redact(text)
        assert "sk-1234567890abcdef" not in result
        assert "[REDACTED]" in result

    def test_redact_authorization_bearer(self):
        text = "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.longtoken"
        result = _redact(text)
        assert "eyJhbGciOiJIUzI1NiJ9" not in result
        assert "[REDACTED]" in result

    def test_redact_password(self):
        text = 'password: "supersecret123"'
        result = _redact(text)
        assert "supersecret123" not in result
        assert "[REDACTED]" in result

    def test_redact_token(self):
        text = 'token: "abcdef1234567890"'
        result = _redact(text)
        assert "abcdef1234567890" not in result
        assert "[REDACTED]" in result

    def test_redact_aws_key(self):
        text = "AWS key: AKIAIOSFODNN7EXAMPLE"
        result = _redact(text)
        assert "AKIAIOSFODNN7EXAMPLE" not in result
        assert "[REDACTED_AWS_KEY]" in result

    def test_no_redaction_on_safe_text(self):
        text = "nmap -sV target.com"
        result = _redact(text)
        assert result == text

    def test_redact_secret(self):
        text = 'secret: "my-super-secret-value"'
        result = _redact(text)
        assert "my-super-secret-value" not in result
        assert "[REDACTED]" in result


class TestAuditLogger:
    @pytest.fixture
    def logger(self):
        log_path = os.path.join(tempfile.mkdtemp(), "test_audit.log")
        return AuditLogger(log_path)

    def test_log_command(self, logger):
        logger.log_command(
            session_id="sess-1",
            command="nmap target.com",
            result={"returncode": 0, "duration_ms": 100, "sandbox_level": "firejail", "timeout": False},
        )

    def test_log_command_redacts_secrets(self, logger):
        logger.log_command(
            session_id="sess-1",
            command='curl -H "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.token" target.com',
            result={"returncode": 0, "duration_ms": 100, "sandbox_level": "none", "timeout": False},
        )

    def test_log_ai_decision(self, logger):
        logger.log_ai_decision(
            session_id="sess-1",
            decision_type="plan",
            decision={"next_tool": "recon_passive"},
            provider="openai",
            tokens_used=150,
            latency_ms=2000,
        )

    def test_log_security_event(self, logger):
        logger.log_security_event(
            session_id="sess-1",
            event_type="command_blocked",
            description="Dangerous command blocked",
            severity="warning",
        )

    def test_log_session_event(self, logger):
        logger.log_session_event(
            session_id="sess-1",
            event="initialized",
            details={"target": "example.com"},
        )
