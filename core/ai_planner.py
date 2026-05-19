"""
AI Planner — calls LLM at three decision boundaries only.
plan()     → LLM call #1: what to test next
evaluate() → LLM call #2: should we continue?
summarize_for_report() → LLM call #3: write the narrative

Between these calls, execution_loop runs locally with no LLM involvement.
"""
import json
import logging
import time
from llm.base_provider import BaseLLMProvider
from llm.prompt_templates import (
    PLAN_SYSTEM, PLAN_USER_TEMPLATE,
    EVALUATE_SYSTEM, EVALUATE_USER_TEMPLATE,
    REPORT_NARRATIVE_SYSTEM, REPORT_NARRATIVE_USER_TEMPLATE,
)
from models.schemas import ActionPlan, EvalResult, ReportNarrative

logger = logging.getLogger(__name__)


class AIPlanner:
    def __init__(self, provider: BaseLLMProvider, graph_db, config):
        self._provider = provider
        self._graph_db = graph_db
        self._use_graph_prefilter = config.ai_planner.use_graph_prefilter
        self._max_tokens = config.llm.max_tokens

    async def plan(self, session_id: str, phase: int, digest: dict, max_phases: int) -> ActionPlan:
        """
        Decide what to test next.
        Consults graph_db first if prefilter enabled (reduces LLM token usage).
        """
        candidate_actions = []
        if self._use_graph_prefilter and digest.get("confirmed_findings"):
            for finding in digest["confirmed_findings"][:3]:  # top 3 only
                try:
                    chains = await self._graph_db.get_attack_chain(
                        entry_attack=finding.get("attack_type", ""),
                        goal="escalate",
                        max_depth=2,
                    )
                    candidate_actions.extend(chains[:3])
                except Exception as e:
                    logger.debug(f"Graph prefilter error: {e}")

        prompt = PLAN_USER_TEMPLATE.format(
            session_id=session_id,
            phase=phase,
            max_phases=max_phases,
            target=digest.get("target", ""),
            scope=json.dumps(digest.get("scope", [])),
            already_tested=json.dumps(digest.get("already_tested", [])),
            confirmed_findings=json.dumps(digest.get("confirmed_findings", [])[:5]),
            candidate_actions=json.dumps(candidate_actions[:5]),
        )

        response = await self._provider.complete(
            system_prompt=PLAN_SYSTEM,
            user_message=prompt,
            response_format="json",
            max_tokens=self._max_tokens,
        )
        data = json.loads(response.content)
        return ActionPlan(
            session_id=session_id,
            next_tool=data["next_tool"],
            args=data.get("args", {}),
            rationale=data.get("rationale", ""),
            expected_finding_type=data.get("expected_finding_type", ""),
            confidence=data.get("confidence", 0.5),
            provider_used=response.provider,
            tokens_used=response.tokens_used,
        )

    async def evaluate(self, session_id: str, phases_done: int, findings_summary: dict) -> EvalResult:
        """Decide whether to continue or stop after a phase."""
        prompt = EVALUATE_USER_TEMPLATE.format(
            session_id=session_id,
            phases_done=phases_done,
            findings_summary=json.dumps(findings_summary.get("top_findings", [])[:5]),
            critical_count=findings_summary.get("critical_count", 0),
            high_count=findings_summary.get("high_count", 0),
        )
        response = await self._provider.complete(
            system_prompt=EVALUATE_SYSTEM,
            user_message=prompt,
            response_format="json",
            max_tokens=500,
        )
        data = json.loads(response.content)
        return EvalResult(
            session_id=session_id,
            should_continue=data.get("continue", False),
            reason=data.get("reason", ""),
            priority_findings=data.get("priority_findings", []),
            risk_score=data.get("risk_score", 0),
            provider_used=response.provider,
            tokens_used=response.tokens_used,
        )

    async def summarize_for_report(self, session_id: str, findings_digest: dict) -> ReportNarrative:
        """Generate executive summary and remediation priorities for the report."""
        prompt = REPORT_NARRATIVE_USER_TEMPLATE.format(
            target=findings_digest.get("target", ""),
            test_type=findings_digest.get("test_type", ""),
            duration=findings_digest.get("duration_minutes", 0),
            findings_digest=json.dumps(findings_digest.get("top_findings", [])[:10]),
        )
        response = await self._provider.complete(
            system_prompt=REPORT_NARRATIVE_SYSTEM,
            user_message=prompt,
            response_format="json",
            max_tokens=self._max_tokens,
        )
        data = json.loads(response.content)
        return ReportNarrative(
            executive_summary=data.get("executive_summary", ""),
            risk_narrative=data.get("risk_narrative", ""),
            remediation_priorities=data.get("remediation_priorities", []),
            provider_used=response.provider,
            tokens_used=response.tokens_used,
        )
