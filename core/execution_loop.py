"""
Local chain runner. Dispatches tool calls from an ActionPlan without
calling the LLM mid-chain. Only escalates to ai_planner at phase boundaries.

LLM call budget for a 4-phase scan: ~8 calls total.
  Phase 1: plan() + evaluate()   = 2
  Phase 2: plan() + evaluate()   = 2
  Phase 3: plan() + evaluate()   = 2
  Phase 4: plan() + evaluate()   = 2
  Report:  summarize_for_report()= 1 (optional)
  Total:                           9
"""
import logging
import asyncio
from models.schemas import ActionPlan, PhaseResult, FinalResult

logger = logging.getLogger(__name__)

# Map tool names (from LLM output) to actual tool method references
TOOL_DISPATCH = {
    "recon_passive":       ("recon",     "run_passive"),
    "recon_active":        ("recon",     "run_active"),
    "scan_vulnerabilities":("scan",      "run_scan"),
    "test_injection":      ("injection", "run_injection"),
    "test_authentication": ("auth",      "run_auth"),
    "test_network":        ("network",   "run_network"),
    "generate_poc":        ("poc",       "run_poc"),
    "execute_command":     ("exec",      "run_command"),
    "analyze_findings":    ("analyze",   "run_analyze"),
}


class ExecutionLoop:
    def __init__(self, tools_registry: dict, ai_planner, session_manager, config):
        self._tools = tools_registry    # {"recon": ReconTools(), "scan": ScanTools(), ...}
        self._planner = ai_planner
        self._session = session_manager
        self._stop_on_critical = config.ai_planner.stop_on_critical
        self._max_phases = config.ai_planner.max_phases

    async def run_autonomous(self, session_id: str, max_phases: int | None = None) -> FinalResult:
        max_phases = max_phases or self._max_phases
        all_findings = []
        phases_completed = 0

        for phase in range(1, max_phases + 1):
            logger.info(f"[{session_id}] Starting phase {phase}/{max_phases}")

            # Build compact digest for planner (< 500 tokens)
            digest = await self._tools["analyze"].build_planner_digest(session_id)

            # LLM CALL #1: what to do next
            plan = await self._planner.plan(session_id, phase, digest, max_phases)
            await self._session.record_ai_decision(session_id, "plan", plan.model_dump())
            logger.info(f"[{session_id}] Phase {phase} plan: {plan.next_tool} — {plan.rationale}")

            # LOCAL EXECUTION: no LLM here
            phase_result = await self.run_phase(session_id, plan)
            all_findings.extend(phase_result.findings)
            phases_completed = phase

            # Check hard stop conditions locally (no LLM needed)
            if self._stop_on_critical and phase_result.critical_count > 0:
                logger.info(f"[{session_id}] Critical finding — stopping early")
                break

            # LLM CALL #2: should we continue?
            findings_summary = {
                "top_findings": [f.model_dump() if hasattr(f, "model_dump") else f for f in all_findings[-10:]],
                "critical_count": sum(1 for f in all_findings if isinstance(f, dict) and f.get("cvss_score", 0) >= 9.0 or hasattr(f, "cvss_score") and f.cvss_score and f.cvss_score >= 9.0),
                "high_count": sum(1 for f in all_findings if isinstance(f, dict) and 7.0 <= f.get("cvss_score", 0) < 9.0 or hasattr(f, "cvss_score") and f.cvss_score and 7.0 <= f.cvss_score < 9.0),
            }
            eval_result = await self._planner.evaluate(session_id, phase, findings_summary)
            await self._session.record_ai_decision(session_id, "evaluate", eval_result.model_dump())

            if not eval_result.should_continue:
                logger.info(f"[{session_id}] Planner said stop: {eval_result.reason}")
                break

        return FinalResult(
            session_id=session_id,
            phases_completed=phases_completed,
            total_findings=len(all_findings),
            critical_count=sum(1 for f in all_findings if (isinstance(f, dict) and f.get("cvss_score", 0) >= 9.0) or (hasattr(f, "cvss_score") and f.cvss_score and f.cvss_score >= 9.0)),
            high_count=sum(1 for f in all_findings if (isinstance(f, dict) and 7.0 <= f.get("cvss_score", 0) < 9.0) or (hasattr(f, "cvss_score") and f.cvss_score and 7.0 <= f.cvss_score < 9.0)),
        )

    async def run_phase(self, session_id: str, plan: ActionPlan) -> PhaseResult:
        """Execute a single planned action. No LLM calls here."""
        findings = []
        critical_count = 0

        tool_name = plan.next_tool
        if tool_name not in TOOL_DISPATCH:
            logger.warning(f"Unknown tool in plan: {tool_name}")
            return PhaseResult(findings=[], critical_count=0, error=f"Unknown tool: {tool_name}")

        module_key, method_name = TOOL_DISPATCH[tool_name]
        tool_module = self._tools.get(module_key)
        if not tool_module:
            return PhaseResult(findings=[], critical_count=0, error=f"Module not loaded: {module_key}")

        try:
            method = getattr(tool_module, method_name)
            result = await method(session_id=session_id, **plan.args)
            findings = result.get("findings", [])
            critical_count = sum(1 for f in findings if (isinstance(f, dict) and f.get("cvss_score", 0) >= 9.0) or (hasattr(f, "cvss_score") and f.cvss_score and f.cvss_score >= 9.0))
        except Exception as e:
            logger.error(f"Tool execution error [{tool_name}]: {e}")
            return PhaseResult(findings=[], critical_count=0, error=str(e))

        return PhaseResult(findings=findings, critical_count=critical_count)

    async def emergency_stop(self, session_id: str):
        """Kill all running processes for a session."""
        pids = await self._session.get_running_pids(session_id)
        for pid in pids:
            try:
                import os, signal
                os.kill(pid, signal.SIGTERM)
                await asyncio.sleep(2)
                os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        logger.warning(f"[{session_id}] Emergency stop executed")
