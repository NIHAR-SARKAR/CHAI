"""Tests for models — Pydantic model validation."""
import pytest
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from models.session import Finding, Session
from models.schemas import ActionPlan, EvalResult, ReportNarrative, PhaseResult, FinalResult


class TestFindingModel:
    def test_create_finding(self):
        f = Finding(
            session_id="sess-1",
            attack_type="sqli",
            confidence=0.9,
            endpoint="https://example.com/users",
            parameter="id",
            evidence="SQL error leaked",
            status="confirmed",
            cvss_score=9.8,
            severity="critical",
        )
        assert f.session_id == "sess-1"
        assert f.attack_type == "sqli"
        assert f.confidence == 0.9

    def test_model_dump_keys(self):
        f = Finding(session_id="sess-1", attack_type="xss", confidence=0.8)
        dump = f.model_dump()
        assert "session_id" in dump
        assert "attack_type" in dump
        assert "confidence" in dump
        assert "endpoint" in dump
        assert "parameter" in dump
        assert "evidence" in dump
        assert "status" in dump
        assert "cvss_score" in dump
        assert "severity" in dump
        assert "remediation" in dump
        assert "metadata" in dump
        assert "created_at" in dump

    def test_default_values(self):
        f = Finding(session_id="sess-1", attack_type="test")
        assert f.confidence == 0.5
        assert f.endpoint == ""
        assert f.status == "potential"
        assert f.cvss_score is None
        assert f.severity is None

    def test_created_at_auto_populated(self):
        f = Finding(session_id="sess-1", attack_type="test")
        assert f.created_at is not None
        assert "T" in f.created_at


class TestSessionModel:
    def test_create_session(self):
        s = Session(session_id="sess-1", target="https://example.com")
        assert s.session_id == "sess-1"
        assert s.target == "https://example.com"
        assert s.test_type == "web_app"
        assert s.status == "initialized"

    def test_model_dump(self):
        s = Session(session_id="sess-1", target="https://example.com")
        dump = s.model_dump()
        assert "session_id" in dump
        assert "target" in dump
        assert "status" in dump


class TestActionPlan:
    def test_create_action_plan(self):
        ap = ActionPlan(
            session_id="sess-1",
            next_tool="recon_passive",
            args={"target": "example.com"},
            rationale="Start with recon",
            confidence=0.8,
        )
        assert ap.next_tool == "recon_passive"
        assert ap.confidence == 0.8

    def test_confidence_out_of_range(self):
        with pytest.raises(Exception):
            ActionPlan(session_id="sess-1", next_tool="test", confidence=1.5)


class TestEvalResult:
    def test_create_eval_result(self):
        er = EvalResult(
            session_id="sess-1",
            should_continue=True,
            reason="More testing needed",
            risk_score=5,
        )
        assert er.should_continue is True
        assert er.risk_score == 5

    def test_risk_score_out_of_range(self):
        with pytest.raises(Exception):
            EvalResult(session_id="sess-1", should_continue=True, risk_score=15)


class TestPhaseResult:
    def test_empty_phase(self):
        pr = PhaseResult()
        assert pr.findings == []
        assert pr.critical_count == 0
        assert pr.error is None

    def test_phase_with_error(self):
        pr = PhaseResult(findings=[], critical_count=0, error="Tool failed")
        assert pr.error == "Tool failed"
