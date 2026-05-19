"""
run_autonomous_scan — top-level MCP tool.
External clients (PICO CLAW or any MCP client) call this ONCE
and get a complete pentest result back.
The internal AI planner + execution loop handle everything.
"""
import logging
from core.execution_loop import ExecutionLoop
from core.ai_planner import AIPlanner
from tools.report import ReportTools

logger = logging.getLogger(__name__)


async def run_autonomous_scan(
    session_id: str,
    max_phases: int = 4,
    stop_on_critical: bool = True,
    generate_report: bool = True,
    provider_override: str | None = None,  # e.g. "openrouter" to override per-scan
) -> dict:
    """
    Fully autonomous pentest:
    1. AI plans each phase
    2. Local loop executes tools (no LLM mid-chain)
    3. AI evaluates — continue or stop
    4. Repeat until done or max_phases
    5. Optionally generate AI-narrated report

    Returns: {phases_completed, total_findings, risk_score, report_path?}
    """
    # provider_override allows swapping LLM per-scan without config change
    # (e.g. test with Claude on one scan, GPT-4.1 on another)
    # Implementation: pass to provider_factory when initializing execution_loop

    from app_context import get_context  # singleton holding all initialized objects
    ctx = get_context()

    provider = ctx.provider
    if provider_override:
        from llm.provider_factory import get_provider
        provider = get_provider(ctx.config, provider_override)

    planner = AIPlanner(provider, ctx.graph_db, ctx.config)
    loop = ExecutionLoop(ctx.tools, planner, ctx.session_manager, ctx.config)

    final = await loop.run_autonomous(session_id, max_phases=max_phases)

    report_path = None
    if generate_report:
        digest = await ctx.tools["analyze"].build_planner_digest(session_id)
        narrative = await planner.summarize_for_report(session_id, digest)
        reporter = ReportTools(ctx.session_manager, ctx.process_controller, ctx.safety_policy, ctx.audit_logger)
        report_path = await reporter.generate_report(
            session_id=session_id,
            format="markdown",
            ai_narrative=narrative,
        )

    return {
        "session_id": session_id,
        "phases_completed": final.phases_completed,
        "total_findings": final.total_findings,
        "critical_count": final.critical_count,
        "high_count": final.high_count,
        "risk_score": final.risk_score if hasattr(final, "risk_score") else None,
        "report_path": report_path,
        "status": "complete",
    }
