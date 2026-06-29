"""Tests for core.ai_planner — LLM response validation, parsing, and timeout recovery."""
import asyncio
import pytest
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from core.ai_planner import AIPlanner, _safe_json_parse, _validate_plan_output, _validate_eval_output
from llm.base_provider import BaseLLMProvider, LLMResponse


class MockConfig:
    """Minimal config stand-in for AIPlanner."""
    class AIPlannerConfig:
        use_graph_prefilter = False
    class LLMConfig:
        max_tokens = 100
        timeout_seconds = 5
        max_retries = 2

    ai_planner = AIPlannerConfig()
    llm = LLMConfig()


class MockGraphDB:
    async def get_attack_chain(self, **kwargs):
        return []


class MockProvider(BaseLLMProvider):
    """Fake LLM provider for testing planner behavior."""
    def __init__(self, responses=None, fail_with=None, delay=None):
        self._responses = responses or []
        self._fail_with = fail_with
        self._delay = delay
        self._call_count = 0

    @property
    def provider_name(self) -> str:
        return "mock_provider"

    async def complete(self, system_prompt, user_message,
                       response_format="json", max_tokens=1000, temperature=0.1) -> LLMResponse:
        self._call_count += 1
        if self._delay:
            await asyncio.sleep(self._delay)
        if self._fail_with:
            raise self._fail_with
        if self._responses:
            return self._responses.pop(0)
        return LLMResponse(
            content='{"next_tool": "recon_passive", "args": {}, "rationale": "mock"}',
            provider="mock_provider",
            model="mock",
            tokens_used=1,
            latency_ms=1,
        )

    async def health_check(self) -> bool:
        return True


class MockFallbackEngine:
    """Fake fallback engine that records search queries."""
    def __init__(self):
        self.searches = []

    async def search_web(self, query, max_results=3):
        self.searches.append(query)
        return [{"title": "Mock result", "href": "http://example.com", "body": "mock body"}]


class TestSafeJsonParse:
    def test_valid_json(self):
        result = _safe_json_parse('{"key": "value"}')
        assert result == {"key": "value"}

    def test_json_with_markdown_fence(self):
        result = _safe_json_parse('```json\n{"key": "value"}\n```')
        assert result == {"key": "value"}

    def test_json_with_plain_fence(self):
        result = _safe_json_parse('```\n{"key": "value"}\n```')
        assert result == {"key": "value"}

    def test_json_with_surrounding_text(self):
        result = _safe_json_parse('Here is the result: {"key": "value"} end')
        assert result == {"key": "value"}

    def test_invalid_json_returns_empty(self):
        result = _safe_json_parse("not json at all")
        assert result == {}

    def test_empty_string_returns_empty(self):
        result = _safe_json_parse("")
        assert result == {}

    def test_nested_json(self):
        result = _safe_json_parse('{"outer": {"inner": 1}}')
        assert result == {"outer": {"inner": 1}}


class TestValidatePlanOutput:
    def test_valid_tool_name_preserved(self):
        data = {"next_tool": "recon_passive", "args": {}, "rationale": "test", "confidence": 0.8}
        result = _validate_plan_output(data, "sess-1")
        assert result.next_tool == "recon_passive"
        assert result.confidence == 0.8

    def test_invalid_tool_name_falls_back(self):
        data = {"next_tool": "nonexistent_tool", "args": {}}
        result = _validate_plan_output(data, "sess-1")
        assert result.next_tool == "recon_passive"

    def test_confidence_clamped_high(self):
        data = {"next_tool": "recon_passive", "args": {}, "confidence": 2.0}
        result = _validate_plan_output(data, "sess-1")
        assert result.confidence == 1.0

    def test_confidence_clamped_low(self):
        data = {"next_tool": "recon_passive", "args": {}, "confidence": -0.5}
        result = _validate_plan_output(data, "sess-1")
        assert result.confidence == 0.0

    def test_non_dict_args_replaced(self):
        data = {"next_tool": "recon_passive", "args": "invalid"}
        result = _validate_plan_output(data, "sess-1")
        assert result.args == {}

    def test_non_numeric_confidence_defaulted(self):
        data = {"next_tool": "recon_passive", "args": {}, "confidence": "high"}
        result = _validate_plan_output(data, "sess-1")
        assert result.confidence == 0.5

    def test_rationale_truncated(self):
        data = {"next_tool": "recon_passive", "args": {}, "rationale": "x" * 1000}
        result = _validate_plan_output(data, "sess-1")
        assert len(result.rationale) <= 500


class TestValidateEvalOutput:
    def test_valid_continue(self):
        data = {"continue": True, "reason": "more to test", "risk_score": 5}
        result = _validate_eval_output(data, "sess-1")
        assert result.should_continue is True
        assert result.risk_score == 5

    def test_risk_score_clamped(self):
        data = {"continue": False, "risk_score": 15}
        result = _validate_eval_output(data, "sess-1")
        assert result.risk_score == 10

    def test_risk_score_negative_clamped(self):
        data = {"continue": False, "risk_score": -1}
        result = _validate_eval_output(data, "sess-1")
        assert result.risk_score == 0

    def test_non_list_priority_findings(self):
        data = {"continue": True, "priority_findings": "not a list"}
        result = _validate_eval_output(data, "sess-1")
        assert result.priority_findings == []

    def test_non_numeric_risk_score(self):
        data = {"continue": False, "risk_score": "high"}
        result = _validate_eval_output(data, "sess-1")
        assert result.risk_score == 0

    def test_reason_truncated(self):
        data = {"continue": False, "reason": "x" * 1000}
        result = _validate_eval_output(data, "sess-1")
        assert len(result.reason) <= 500


class TestAIPlannerTimeoutRecovery:
    @pytest.mark.asyncio
    async def test_plan_returns_safe_fallback_on_timeout(self):
        provider = MockProvider(delay=10)  # exceeds timeout
        fallback = MockFallbackEngine()
        planner = AIPlanner(provider, MockGraphDB(), MockConfig(), fallback_engine=fallback)

        plan = await planner.plan("sess-timeout", 1, {"target": "https://example.com"}, 4)

        assert plan.next_tool == "recon_passive"
        assert plan.session_id == "sess-timeout"
        assert plan.confidence == 0.0
        assert "did not respond" in plan.rationale.lower()
        assert provider._call_count == MockConfig.llm.max_retries
        assert len(fallback.searches) == MockConfig.llm.max_retries

    @pytest.mark.asyncio
    async def test_evaluate_returns_safe_fallback_on_timeout(self):
        provider = MockProvider(delay=10)
        fallback = MockFallbackEngine()
        planner = AIPlanner(provider, MockGraphDB(), MockConfig(), fallback_engine=fallback)

        result = await planner.evaluate("sess-timeout", 1, {
            "top_findings": [],
            "critical_count": 0,
            "high_count": 0,
        })

        assert result.should_continue is True
        assert "continue" in result.reason.lower()
        assert provider._call_count == MockConfig.llm.max_retries
        assert len(fallback.searches) == MockConfig.llm.max_retries

    @pytest.mark.asyncio
    async def test_summarize_returns_safe_fallback_on_timeout(self):
        provider = MockProvider(delay=10)
        fallback = MockFallbackEngine()
        planner = AIPlanner(provider, MockGraphDB(), MockConfig(), fallback_engine=fallback)

        narrative = await planner.summarize_for_report("sess-timeout", {
            "target": "https://example.com",
            "test_type": "web_app",
            "duration_minutes": 5,
            "top_findings": [],
        })

        assert "unavailable" in narrative.executive_summary.lower()
        assert narrative.remediation_priorities == []
        assert provider._call_count == MockConfig.llm.max_retries
        assert len(fallback.searches) == MockConfig.llm.max_retries

    @pytest.mark.asyncio
    async def test_plan_succeeds_when_provider_responds(self):
        provider = MockProvider(responses=[
            LLMResponse(
                content='{"next_tool": "scan_vulnerabilities", "args": {"target": "https://example.com"}, "rationale": "scan it", "confidence": 0.9}',
                provider="mock_provider",
                model="mock",
                tokens_used=5,
                latency_ms=10,
            )
        ])
        fallback = MockFallbackEngine()
        planner = AIPlanner(provider, MockGraphDB(), MockConfig(), fallback_engine=fallback)

        plan = await planner.plan("sess-ok", 1, {"target": "https://example.com"}, 4)

        assert plan.next_tool == "scan_vulnerabilities"
        assert plan.confidence == 0.9
        assert provider._call_count == 1
        assert fallback.searches == []

    @pytest.mark.asyncio
    async def test_plan_retries_then_falls_back_on_provider_error(self):
        provider = MockProvider(fail_with=RuntimeError("boom"))
        fallback = MockFallbackEngine()
        planner = AIPlanner(provider, MockGraphDB(), MockConfig(), fallback_engine=fallback)

        plan = await planner.plan("sess-error", 1, {"target": "https://example.com"}, 4)

        assert plan.next_tool == "recon_passive"
        assert provider._call_count == MockConfig.llm.max_retries
        assert len(fallback.searches) == MockConfig.llm.max_retries
