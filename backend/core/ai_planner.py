"""
AI Planner — calls LLM at three decision boundaries only.
plan()     -> LLM call #1: what to test next
evaluate() -> LLM call #2: should we continue?
summarize_for_report() -> LLM call #3: write the narrative

Between these calls, execution_loop runs locally with no LLM involvement.

Graceful degradation:
- Each LLM call is wrapped with a timeout and a DuckDuckGo-assisted recovery loop.
- On timeout or provider failure the planner searches the web for context,
  retries up to 2 times, and returns a safe default so the scan can continue.
"""
import asyncio
import json
import logging
from typing import Any, Dict, List, Optional

from llm.base_provider import BaseLLMProvider, LLMResponse
from llm.prompt_templates import (
    PLAN_SYSTEM, PLAN_USER_TEMPLATE,
    EVALUATE_SYSTEM, EVALUATE_USER_TEMPLATE,
    REPORT_NARRATIVE_SYSTEM, REPORT_NARRATIVE_USER_TEMPLATE,
)
from models.schemas import ActionPlan, EvalResult, ReportNarrative, PlannedTool
from core.execution_loop import TOOL_DISPATCH

logger = logging.getLogger(__name__)

VALID_TOOLS = set(TOOL_DISPATCH.keys())

# Safe defaults used when the LLM is unreachable.
DEFAULT_PLAN_TOOL = "recon_passive"


def _safe_json_parse(content: str, max_retries: int = 2) -> dict:
    """Parse JSON from LLM response, handling common formatting issues."""
    text = content.strip()
    if text.startswith("```json"):
        text = text[len("```json"):]
    if text.startswith("```"):
        text = text[len("```"):]
    if text.endswith("```"):
        text = text[:-3]
    text = text.strip()
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        brace_start = text.find("{")
        brace_end = text.rfind("}")
        if brace_start != -1 and brace_end != -1 and brace_end > brace_start:
            try:
                return json.loads(text[brace_start:brace_end + 1])
            except json.JSONDecodeError:
                pass
        return {}


def _validate_plan_output(data: dict, session_id: str) -> ActionPlan:
    """Validate and sanitize LLM plan output. Supports multi-tool plans."""
    original_tool = data.get("next_tool", "")
    next_tool = original_tool
    if next_tool not in VALID_TOOLS:
        logger.warning(f"[BRAIN validate] INVALID primary tool '{next_tool}' from LLM — "
                         f"not in {len(VALID_TOOLS)} valid tools. "
                         f"Falling back to '{DEFAULT_PLAN_TOOL}'. "
                         f"Valid examples: {sorted(list(VALID_TOOLS))[:5]}...")
        next_tool = DEFAULT_PLAN_TOOL
    else:
        logger.info(f"[BRAIN validate] Primary tool '{next_tool}' is valid")

    args = data.get("args", {})
    if not isinstance(args, dict):
        logger.warning(f"[BRAIN validate] args was not dict (type={type(args).__name__}), resetting to {{}}")
        args = {}
    else:
        logger.info(f"[BRAIN validate] args keys: {list(args.keys())}")
        if "target" not in args:
            logger.warning("[BRAIN validate] args missing 'target' — execution_loop will inject it")

    confidence = data.get("confidence", 0.5)
    try:
        confidence = float(confidence)
        confidence = max(0.0, min(1.0, confidence))
    except (TypeError, ValueError):
        logger.warning(f"[BRAIN validate] Invalid confidence value '{confidence}', defaulting to 0.5")
        confidence = 0.5

    rationale = str(data.get("rationale", ""))[:500]
    expected = str(data.get("expected_finding_type", ""))[:100]

    # Parse multi-tool list from LLM output
    tools_list = []
    raw_tools = data.get("tools", [])
    if isinstance(raw_tools, list) and raw_tools:
        logger.info(f"[BRAIN validate] LLM returned {len(raw_tools)} tools in plan")
        for i, t in enumerate(raw_tools):
            if not isinstance(t, dict):
                logger.warning(f"[BRAIN validate] tools[{i}] is not dict, skipping")
                continue
            tool_name = t.get("next_tool", "")
            if tool_name not in VALID_TOOLS:
                logger.warning(f"[BRAIN validate] tools[{i}] INVALID tool '{tool_name}', skipping")
                continue
            tool_args = t.get("args", {})
            if not isinstance(tool_args, dict):
                tool_args = {}
            if "target" not in tool_args:
                logger.warning(f"[BRAIN validate] tools[{i}] missing 'target' in args — execution_loop will inject it")
            tools_list.append(PlannedTool(
                next_tool=tool_name,
                args=tool_args,
                expected_finding_type=str(t.get("expected_finding_type", ""))[:100],
            ))
    else:
        logger.info("[BRAIN validate] No 'tools' array in LLM output — building single-tool list from next_tool")

    # If no valid tools in the list, build one from the primary next_tool
    if not tools_list:
        if next_tool in VALID_TOOLS:
            tools_list.append(PlannedTool(
                next_tool=next_tool,
                args=args,
                expected_finding_type=expected,
            ))
        else:
            tools_list.append(PlannedTool(
                next_tool=DEFAULT_PLAN_TOOL,
                args={},
                expected_finding_type="information_disclosure",
            ))

    # Ensure the primary next_tool is always in the tools list
    tool_names_in_list = {t.next_tool for t in tools_list}
    if next_tool not in tool_names_in_list:
        tools_list.insert(0, PlannedTool(
            next_tool=next_tool,
            args=args,
            expected_finding_type=expected,
        ))

    logger.info(f"[BRAIN validate] Final plan: {len(tools_list)} tools: "
                 f"{[t.next_tool for t in tools_list]}, "
                 f"rationale='{rationale[:100]}...', confidence={confidence}")

    return ActionPlan(
        session_id=session_id,
        next_tool=next_tool,
        tools=tools_list,
        args=args,
        rationale=rationale,
        expected_finding_type=expected,
        confidence=confidence,
        provider_used=data.get("provider_used", ""),
        tokens_used=data.get("tokens_used", 0),
    )


def _validate_eval_output(data: dict, session_id: str) -> EvalResult:
    """Validate and sanitize LLM evaluate output."""
    risk_score = data.get("risk_score", 0)
    try:
        risk_score = int(risk_score)
        risk_score = max(0, min(10, risk_score))
    except (TypeError, ValueError):
        risk_score = 0

    priority_findings = data.get("priority_findings", [])
    if not isinstance(priority_findings, list):
        priority_findings = []

    return EvalResult(
        session_id=session_id,
        should_continue=bool(data.get("continue", False)),
        reason=str(data.get("reason", ""))[:500],
        priority_findings=[str(f) for f in priority_findings[:20]],
        risk_score=risk_score,
        provider_used=data.get("provider_used", ""),
        tokens_used=data.get("tokens_used", 0),
    )


class AIPlanner:
    def __init__(self, provider: BaseLLMProvider, graph_db, config, fallback_engine=None):
        self._provider = provider
        self._graph_db = graph_db
        self._fallback_engine = fallback_engine
        self._use_graph_prefilter = config.ai_planner.use_graph_prefilter
        self._max_tokens = config.llm.max_tokens
        self._llm_timeout = getattr(config.llm, "timeout_seconds", 30)
        self._max_recovery_attempts = max(1, getattr(config.llm, "max_retries", 2))

    # ------------------------------------------------------------------
    # LLM call wrapper with timeout recovery
    # ------------------------------------------------------------------

    async def _call_llm_with_recovery(
        self,
        session_id: str,
        call_type: str,
        system_prompt: str,
        user_message: str,
        response_format: str = "json",
        max_tokens: int = 1000,
        temperature: float = 0.1,
    ) -> Optional[LLMResponse]:
        """
        Call the LLM with a hard timeout and DuckDuckGo-assisted retry loop.

        On timeout or provider failure the planner searches the web for
        provider/context hints, retries up to config.llm.max_retries times,
        and returns None if recovery fails so the caller can fall back safely.
        """
        last_error: Optional[Exception] = None

        for attempt in range(1, self._max_recovery_attempts + 1):
            logger.info(f"[BRAIN {call_type}] LLM attempt {attempt}/{self._max_recovery_attempts} "
                        f"provider={self._provider.provider_name} timeout={self._llm_timeout}s")
            try:
                response = await asyncio.wait_for(
                    self._provider.complete(
                        system_prompt=system_prompt,
                        user_message=user_message,
                        response_format=response_format,
                        max_tokens=max_tokens,
                        temperature=temperature,
                    ),
                    timeout=self._llm_timeout,
                )
                logger.info(f"[BRAIN {call_type}] LLM responded on attempt {attempt}: "
                            f"provider={response.provider}, latency={response.latency_ms}ms")
                return response
            except asyncio.TimeoutError as e:
                last_error = e
                logger.warning(f"[BRAIN {call_type}] Timeout on attempt {attempt}/{self._max_recovery_attempts}")
                await self._maybe_search_web_for_recovery(
                    call_type=call_type,
                    error_message=f"{self._provider.provider_name} LLM timeout after {self._llm_timeout}s",
                    attempt=attempt,
                )
            except Exception as e:
                last_error = e
                logger.warning(f"[BRAIN {call_type}] Provider error on attempt {attempt}/{self._max_recovery_attempts}: {e}")
                await self._maybe_search_web_for_recovery(
                    call_type=call_type,
                    error_message=f"{self._provider.provider_name} error: {e}",
                    attempt=attempt,
                )

            if attempt < self._max_recovery_attempts:
                backoff = 2 ** (attempt - 1)
                logger.info(f"[BRAIN {call_type}] Backing off {backoff}s before retry")
                await asyncio.sleep(backoff)

        logger.error(f"[BRAIN {call_type}] LLM recovery exhausted after {self._max_recovery_attempts} attempts. "
                     f"Last error: {last_error}")
        return None

    async def _maybe_search_web_for_recovery(
        self,
        call_type: str,
        error_message: str,
        attempt: int,
    ) -> List[Dict[str, Any]]:
        """Use DuckDuckGo to gather context for an LLM failure. Logs results."""
        if self._fallback_engine is None:
            logger.info(f"[BRAIN {call_type}] No fallback engine available — skipping web search")
            return []

        query = f"{error_message} fix workaround"
        logger.info(f"[BRAIN {call_type}] Searching DuckDuckGo (attempt {attempt}): {query}")
        try:
            results = await self._fallback_engine.search_web(query, max_results=3)
            titles = [r.get("title", "") for r in results if r.get("title")]
            logger.info(f"[BRAIN {call_type}] Web search returned {len(results)} results: {titles[:3]}")
            return results
        except Exception as e:
            logger.warning(f"[BRAIN {call_type}] Web search failed: {e}")
            return []

    # ------------------------------------------------------------------
    # Decision APIs
    # ------------------------------------------------------------------

    async def plan(self, session_id: str, phase: int, digest: dict, max_phases: int) -> ActionPlan:
        """Decide what to test next. Validates LLM output against known tools."""
        logger.info(f"[BRAIN plan] === START phase={phase} session={session_id} ===")
        logger.info(f"[BRAIN plan] Digest: target={digest.get('target')}, "
                     f"already_tested={digest.get('already_tested')}, "
                     f"total_findings={digest.get('total_findings')}, "
                     f"confirmed={len(digest.get('confirmed_findings', []))}")

        candidate_actions = []
        if self._use_graph_prefilter and digest.get("confirmed_findings"):
            logger.info(f"[BRAIN plan] Graph prefilter enabled, {len(digest['confirmed_findings'])} confirmed findings")
            for finding in digest["confirmed_findings"][:3]:
                try:
                    chains = await self._graph_db.get_attack_chain(
                        entry_attack=finding.get("attack_type", ""),
                        goal="escalate",
                        max_depth=2,
                    )
                    logger.info(f"[BRAIN plan] Graph chain for {finding.get('attack_type')}: {len(chains)} candidates")
                    candidate_actions.extend(chains[:3])
                except Exception as e:
                    logger.debug(f"[BRAIN plan] Graph prefilter error: {e}")

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
        logger.info(f"[BRAIN plan] Prompt length={len(prompt)} chars")
        logger.debug(f"[BRAIN plan] Full prompt:\n{prompt}")

        response = await self._call_llm_with_recovery(
            session_id=session_id,
            call_type="plan",
            system_prompt=PLAN_SYSTEM,
            user_message=prompt,
            response_format="json",
            max_tokens=self._max_tokens,
        )

        if response is None:
            logger.warning("[BRAIN plan] LLM recovery failed — returning safe fallback plan to continue scan")
            fallback_target = digest.get("target", "")
            return ActionPlan(
                session_id=session_id,
                next_tool=DEFAULT_PLAN_TOOL,
                tools=[
                    PlannedTool(next_tool=DEFAULT_PLAN_TOOL, args={"target": fallback_target} if fallback_target else {}, expected_finding_type="information_disclosure"),
                    PlannedTool(next_tool="test_cors", args={"target": fallback_target} if fallback_target else {}, expected_finding_type="misconfig"),
                    PlannedTool(next_tool="test_security_headers", args={"target": fallback_target} if fallback_target else {}, expected_finding_type="misconfig"),
                ],
                args={"target": fallback_target} if fallback_target else {},
                rationale=(
                    f"Safe fallback plan chosen because the LLM ({self._provider.provider_name}) "
                    f"did not respond within {self._llm_timeout}s after {self._max_recovery_attempts} attempts. "
                    f"Scan continues with low-risk reconnaissance + basic checks."
                ),
                expected_finding_type="information_disclosure",
                confidence=0.0,
                provider_used=self._provider.provider_name,
                tokens_used=0,
            )

        logger.info(f"[BRAIN plan] LLM responded: provider={response.provider}, "
                     f"tokens={response.tokens_used}, latency={response.latency_ms}ms, "
                     f"content_length={len(response.content)}")
        logger.debug(f"[BRAIN plan] Raw LLM response:\n{response.content}")

        data = _safe_json_parse(response.content)
        if not data:
            logger.warning("[BRAIN plan] LLM returned invalid JSON — using fallback")
            data = {"next_tool": DEFAULT_PLAN_TOOL, "tools": [], "args": {}, "rationale": "Fallback due to parse error"}
        else:
            logger.info(f"[BRAIN plan] Parsed JSON keys: {list(data.keys())}")
            logger.info(f"[BRAIN plan] Raw LLM choice: next_tool='{data.get('next_tool')}', "
                         f"args={data.get('args')}, confidence={data.get('confidence')}, "
                         f"rationale='{str(data.get('rationale',''))[:120]}'")

        plan = _validate_plan_output(data, session_id)
        if response:
            plan.tokens_used = response.tokens_used
            plan.input_tokens = response.input_tokens
            plan.output_tokens = response.output_tokens
        logger.info(f"[BRAIN plan] Validated plan: next_tool='{plan.next_tool}', "
                     f"args={plan.args}, confidence={plan.confidence}, "
                     f"expected='{plan.expected_finding_type}', "
                     f"valid={plan.next_tool in VALID_TOOLS}, "
                     f"provider={plan.provider_used}, tokens={plan.tokens_used}")
        logger.info(f"[BRAIN plan] === END phase={phase} ===")
        return plan

    async def evaluate(self, session_id: str, phases_done: int, findings_summary: dict) -> EvalResult:
        """Decide whether to continue or stop after a phase. Validates LLM output."""
        logger.info(f"[BRAIN evaluate] === START phases_done={phases_done} session={session_id} ===")
        logger.info(f"[BRAIN evaluate] findings_summary: "
                     f"critical={findings_summary.get('critical_count')}, "
                     f"high={findings_summary.get('high_count')}, "
                     f"top_findings_count={len(findings_summary.get('top_findings', []))}")

        prompt = EVALUATE_USER_TEMPLATE.format(
            session_id=session_id,
            phases_done=phases_done,
            findings_summary=json.dumps(findings_summary.get("top_findings", [])[:5]),
            critical_count=findings_summary.get("critical_count", 0),
            high_count=findings_summary.get("high_count", 0),
            tools_tested=json.dumps(findings_summary.get("tools_tested", [])),
            tools_remaining=json.dumps(findings_summary.get("tools_remaining", [])),
        )
        logger.info(f"[BRAIN evaluate] Prompt length={len(prompt)} chars")
        logger.debug(f"[BRAIN evaluate] Full prompt:\n{prompt}")

        response = await self._call_llm_with_recovery(
            session_id=session_id,
            call_type="evaluate",
            system_prompt=EVALUATE_SYSTEM,
            user_message=prompt,
            response_format="json",
            max_tokens=500,
        )

        if response is None:
            logger.warning("[BRAIN evaluate] LLM recovery failed — continuing scan with safe default")
            return EvalResult(
                session_id=session_id,
                should_continue=True,
                reason=(
                    f"Evaluation defaulted to continue because the LLM ({self._provider.provider_name}) "
                    f"did not respond within {self._llm_timeout}s after {self._max_recovery_attempts} attempts. "
                    f"Scan proceeds to the next phase."
                ),
                priority_findings=[],
                risk_score=0,
                provider_used=self._provider.provider_name,
                tokens_used=0,
            )

        logger.info(f"[BRAIN evaluate] LLM responded: provider={response.provider}, "
                     f"tokens={response.tokens_used}, latency={response.latency_ms}ms")
        logger.debug(f"[BRAIN evaluate] Raw LLM response:\n{response.content}")

        data = _safe_json_parse(response.content)
        if not data:
            logger.warning("[BRAIN evaluate] LLM returned invalid JSON — defaulting to continue (safer to keep testing)")
            data = {"continue": True, "reason": "Parse error, continuing scan to maximize coverage"}
        else:
            logger.info(f"[BRAIN evaluate] Parsed JSON: continue={data.get('continue')}, "
                         f"reason='{str(data.get('reason',''))[:120]}', "
                         f"risk_score={data.get('risk_score')}")

        result = _validate_eval_output(data, session_id)
        if response:
            result.tokens_used = response.tokens_used
            result.input_tokens = response.input_tokens
            result.output_tokens = response.output_tokens
        logger.info(f"[BRAIN evaluate] Validated result: should_continue={result.should_continue}, "
                     f"reason='{result.reason[:120]}', risk_score={result.risk_score}, "
                     f"provider={result.provider_used}")
        logger.info(f"[BRAIN evaluate] === END phases_done={phases_done} ===")
        return result

    async def summarize_for_report(self, session_id: str, findings_digest: dict) -> ReportNarrative:
        """Generate executive summary and remediation priorities for the report."""
        prompt = REPORT_NARRATIVE_USER_TEMPLATE.format(
            target=findings_digest.get("target", ""),
            test_type=findings_digest.get("test_type", ""),
            duration=findings_digest.get("duration_minutes", 0),
            findings_digest=json.dumps(findings_digest.get("top_findings", [])[:10]),
        )

        response = await self._call_llm_with_recovery(
            session_id=session_id,
            call_type="summarize",
            system_prompt=REPORT_NARRATIVE_SYSTEM,
            user_message=prompt,
            response_format="json",
            max_tokens=self._max_tokens,
        )

        if response is None:
            logger.warning("[BRAIN summarize] LLM recovery failed — returning empty narrative")
            return ReportNarrative(
                executive_summary=(
                    f"Report narrative unavailable because the LLM ({self._provider.provider_name}) "
                    f"did not respond within {self._llm_timeout}s after {self._max_recovery_attempts} attempts."
                ),
                risk_narrative="Unable to generate risk narrative due to LLM timeout/error.",
                remediation_priorities=[],
                provider_used=self._provider.provider_name,
                tokens_used=0,
            )

        data = _safe_json_parse(response.content)
        if not data:
            data = {
                "executive_summary": "Report generation incomplete — LLM output parse error.",
                "risk_narrative": "Unable to generate risk narrative.",
                "remediation_priorities": [],
            }

        remediation = data.get("remediation_priorities", [])
        if not isinstance(remediation, list):
            remediation = []

        narrative = ReportNarrative(
            executive_summary=str(data.get("executive_summary", ""))[:5000],
            risk_narrative=str(data.get("risk_narrative", ""))[:5000],
            remediation_priorities=remediation[:20],
            provider_used=response.provider,
            tokens_used=response.tokens_used,
            input_tokens=response.input_tokens,
            output_tokens=response.output_tokens,
        )
        return narrative
