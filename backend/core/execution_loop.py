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
from models.session import Finding
from web.ws_manager import manager

logger = logging.getLogger(__name__)


def _normalize_finding(session_id: str, data) -> Finding:
    """Convert a Finding model or dict into a persisted Finding."""
    if isinstance(data, Finding):
        return data
    if isinstance(data, dict):
        finding_dict = dict(data)
        finding_dict.setdefault("session_id", session_id)
        return Finding(**finding_dict)
    raise ValueError(f"Unsupported finding type: {type(data)}")

# Map tool names (from LLM output) to actual tool method references
TOOL_DISPATCH = {
    "recon_passive":       ("recon",          "run_passive"),
    "recon_active":        ("recon",          "run_active"),
    "scan_vulnerabilities":("scan",           "run_scan"),
    "test_injection":      ("injection",      "run_injection"),
    "test_authentication":  ("auth",           "run_auth"),
    "test_network":        ("network",        "run_network"),
    "generate_poc":        ("poc",            "run_poc"),
    "execute_command":     ("exec",           "run_command"),
    "analyze_findings":    ("analyze",        "run_analyze"),
    "test_xss":            ("xss",            "run_xss"),
    "test_ssrf":           ("ssrf",           "run_ssrf"),
    "test_idor":           ("access_control", "run_access_control"),
    "test_bola":           ("access_control", "run_access_control"),
    "test_path_traversal": ("access_control", "run_access_control"),
    "test_method_tampering":("access_control","run_access_control"),
    "test_forced_browsing": ("access_control","run_access_control"),
    "test_mass_assignment":("api_security",   "run_api_security"),
    "test_api_versioning": ("api_security",   "run_api_security"),
    "test_graphql":        ("api_security",   "run_api_security"),
    "test_cors":           ("misconfig",      "run_misconfig"),
    "test_verbose_errors": ("misconfig",      "run_misconfig"),
    "test_debug_endpoints":("misconfig",      "run_misconfig"),
    "test_security_headers":("misconfig",     "run_misconfig"),
    "test_rate_limit":     ("rate_limit",     "run_rate_limit"),
    "test_login_rate_limit":("rate_limit",    "run_rate_limit"),
    "test_api_rate_limit": ("rate_limit",     "run_rate_limit"),
    "test_rate_limit_bypass":("rate_limit",   "run_rate_limit"),
    "test_js_secrets":     ("sensitive_data", "run_sensitive_data"),
    "test_api_overexposure":("sensitive_data","run_sensitive_data"),
    "test_http_https":     ("sensitive_data", "run_sensitive_data"),
    "test_git_backup":     ("sensitive_data", "run_sensitive_data"),
    "test_negative_values":("business_logic", "run_business_logic"),
    "test_coupon_abuse":   ("business_logic", "run_business_logic"),
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
        tested_tools: set[str] = set()

        logger.info(f"[LOOP] === AUTONOMOUS SCAN START session={session_id} max_phases={max_phases} ===")

        for phase in range(1, max_phases + 1):
            logger.info(f"[LOOP] --- PHASE {phase}/{max_phases} START ---")

            # Build compact digest for planner (< 500 tokens)
            logger.info(f"[LOOP] Building planner digest for session={session_id}")
            digest = await self._tools["analyze"].build_planner_digest(session_id)
            logger.info(f"[LOOP] Digest built: target={digest.get('target')}, "
                         f"already_tested={digest.get('already_tested')}, "
                         f"confirmed_findings={len(digest.get('confirmed_findings', []))}, "
                         f"total_findings={digest.get('total_findings')}")

            # LLM CALL #1: what to do next
            logger.info(f"[LOOP] Calling AI planner.plan() for phase={phase}")
            plan = await self._planner.plan(session_id, phase, digest, max_phases)
            await self._session.record_ai_decision(session_id, "plan", plan.model_dump())
            logger.info(f"[LOOP] Planner returned: next_tool='{plan.next_tool}', "
                         f"tools_count={len(plan.tools)}, "
                         f"tool_list={[t.next_tool for t in plan.tools]}, "
                         f"confidence={plan.confidence}, "
                         f"rationale='{plan.rationale[:100]}'")

            # LOCAL EXECUTION: run ALL tools in the plan
            logger.info(f"[LOOP] Dispatching {len(plan.tools)} tool(s) for phase={phase}")
            phase_result = await self.run_phase(session_id, plan)
            for t in plan.tools:
                tested_tools.add(t.next_tool)
            all_findings.extend(phase_result.findings)
            phases_completed = phase

            await manager.broadcast(session_id, {
                "type": "progress",
                "findings_count": len(all_findings),
                "session": {"status": "running"},
            })

            logger.info(f"[LOOP] Phase {phase} result: findings={len(phase_result.findings)}, "
                         f"critical={phase_result.critical_count}, "
                         f"error='{str(phase_result.error)[:80] if phase_result.error else 'none'}'")
            if phase_result.findings:
                for i, f in enumerate(phase_result.findings[:3]):
                    attack = f.get("attack_type", "?") if isinstance(f, dict) else getattr(f, "attack_type", "?")
                    sev = f.get("severity", "?") if isinstance(f, dict) else getattr(f, "severity", "?")
                    ep = f.get("endpoint", "?") if isinstance(f, dict) else getattr(f, "endpoint", "?")
                    logger.info(f"[LOOP]   Finding {i+1}: attack_type={attack}, severity={sev}, endpoint={ep}")

            # Check hard stop conditions locally (no LLM needed)
            if self._stop_on_critical and phase_result.critical_count > 0:
                logger.info(f"[LOOP] Critical finding detected — stopping early after phase {phase}")
                break

            # LLM CALL #2: should we continue?
            critical_count = sum(1 for f in all_findings if (isinstance(f, dict) and f.get("cvss_score", 0) >= 9.0) or (hasattr(f, "cvss_score") and f.cvss_score and f.cvss_score >= 9.0))
            high_count = sum(1 for f in all_findings if (isinstance(f, dict) and 7.0 <= f.get("cvss_score", 0) < 9.0) or (hasattr(f, "cvss_score") and f.cvss_score and 7.0 <= f.cvss_score < 9.0))
            findings_summary = {
                "top_findings": [f.model_dump() if hasattr(f, "model_dump") else f for f in all_findings[-10:]],
                "critical_count": critical_count,
                "high_count": high_count,
                "total_findings": len(all_findings),
                "tools_tested": sorted(list(tested_tools)),
                "tools_remaining": sorted(list(set(TOOL_DISPATCH.keys()) - tested_tools)),
            }
            logger.info(f"[LOOP] Calling AI planner.evaluate() with summary: "
                         f"total={len(all_findings)}, critical={critical_count}, high={high_count}, "
                         f"tools_tested={sorted(list(tested_tools))}")

            eval_result = await self._planner.evaluate(session_id, phase, findings_summary)
            await self._session.record_ai_decision(session_id, "evaluate", eval_result.model_dump())
            logger.info(f"[LOOP] Planner evaluate: should_continue={eval_result.should_continue}, "
                         f"reason='{eval_result.reason[:120]}', risk_score={eval_result.risk_score}")

            if not eval_result.should_continue:
                logger.info(f"[LOOP] Planner said stop at phase {phase}: {eval_result.reason}")
                break

            logger.info(f"[LOOP] --- PHASE {phase} END ---")

        logger.info(f"[LOOP] === AUTONOMOUS SCAN END session={session_id} "
                     f"phases={phases_completed}, total_findings={len(all_findings)}, "
                     f"critical={sum(1 for f in all_findings if (isinstance(f, dict) and f.get('cvss_score', 0) >= 9.0) or (hasattr(f, 'cvss_score') and f.cvss_score and f.cvss_score >= 9.0))}, "
                     f"high={sum(1 for f in all_findings if (isinstance(f, dict) and 7.0 <= f.get('cvss_score', 0) < 9.0) or (hasattr(f, 'cvss_score') and f.cvss_score and 7.0 <= f.cvss_score < 9.0))} ===")

        return FinalResult(
            session_id=session_id,
            phases_completed=phases_completed,
            total_findings=len(all_findings),
            critical_count=sum(1 for f in all_findings if (isinstance(f, dict) and f.get("cvss_score", 0) >= 9.0) or (hasattr(f, "cvss_score") and f.cvss_score and f.cvss_score >= 9.0)),
            high_count=sum(1 for f in all_findings if (isinstance(f, dict) and 7.0 <= f.get("cvss_score", 0) < 9.0) or (hasattr(f, "cvss_score") and f.cvss_score and 7.0 <= f.cvss_score < 9.0)),
        )

    async def run_phase(self, session_id: str, plan: ActionPlan) -> PhaseResult:
        """Execute all tools in a planned phase. No LLM calls here."""
        all_findings = []
        total_critical = 0
        last_error = None

        # Use plan.tools list if available, otherwise fall back to single next_tool
        tools_to_run = plan.tools if plan.tools else []
        if not tools_to_run and plan.next_tool:
            from models.schemas import PlannedTool
            tools_to_run = [PlannedTool(next_tool=plan.next_tool, args=plan.args, expected_finding_type=plan.expected_finding_type)]

        logger.info(f"[PHASE] Running {len(tools_to_run)} tool(s) in this phase: {[t.next_tool for t in tools_to_run]}")

        for idx, planned_tool in enumerate(tools_to_run):
            tool_name = planned_tool.next_tool
            args = dict(planned_tool.args) if planned_tool.args else {}
            logger.info(f"[PHASE] Tool {idx+1}/{len(tools_to_run)}: name='{tool_name}', TOOL_DISPATCH={'YES' if tool_name in TOOL_DISPATCH else 'NO'}")

            if tool_name not in TOOL_DISPATCH:
                logger.error(f"[PHASE] Unknown tool in plan: '{tool_name}' — skipping")
                last_error = f"Unknown tool: {tool_name}"
                continue

            module_key, method_name = TOOL_DISPATCH[tool_name]
            tool_module = self._tools.get(module_key)
            logger.info(f"[PHASE] Resolved: module='{module_key}', method='{method_name}', module_loaded={tool_module is not None}")
            if not tool_module:
                logger.error(f"[PHASE] Module not loaded: '{module_key}'")
                last_error = f"Module not loaded: {module_key}"
                continue

            # Inject session target into args if missing
            if "target" not in args:
                try:
                    session = await self._session.get_session(session_id)
                    if session and session.target:
                        args["target"] = session.target
                        logger.info(f"[PHASE] Injected target into args: {session.target}")
                    else:
                        logger.warning(f"[PHASE] Session has no target! session={session}")
                except Exception as e:
                    logger.warning(f"[PHASE] Could not inject target: {e}")
            else:
                logger.info(f"[PHASE] Target already in args: {args['target']}")

            logger.info(f"[PHASE] Calling {module_key}.{method_name}(session_id={session_id}, **{args})")
            try:
                method = getattr(tool_module, method_name)
                result = await method(session_id=session_id, **args)
                logger.info(f"[PHASE] Tool {tool_name} returned: type={type(result).__name__}, keys={list(result.keys()) if isinstance(result, dict) else 'N/A'}")

                findings = result.get("findings", [])
                critical_count = sum(1 for f in findings if (isinstance(f, dict) and f.get("cvss_score", 0) >= 9.0) or (hasattr(f, "cvss_score") and f.cvss_score and f.cvss_score >= 9.0))
                logger.info(f"[PHASE] Extracted {len(findings)} findings, {critical_count} critical")

                for raw in findings:
                    try:
                        finding = _normalize_finding(session_id, raw)
                        await self._session.add_finding(finding)
                    except Exception as e:
                        logger.warning(f"[PHASE] Could not persist finding: {e}")

                all_findings.extend(findings)
                total_critical += critical_count

                raw = result.get("raw", {})
                if raw and isinstance(raw, dict):
                    for k, v in raw.items():
                        if isinstance(v, dict):
                            rc = v.get("returncode", "?")
                            dur = v.get("duration_ms", "?")
                            logger.info(f"[PHASE]   Sub-result '{k}': returncode={rc}, duration={dur}ms")
            except TypeError as te:
                logger.error(f"[PHASE] TypeError calling {tool_name}: {te}")
                logger.error(f"[PHASE]   args passed: {args}")
                last_error = f"TypeError: {te}"
            except Exception as e:
                logger.error(f"[PHASE] Exception calling {tool_name}: {e}")
                last_error = str(e)

        logger.info(f"[PHASE] Phase complete: {len(tools_to_run)} tools ran, {len(all_findings)} total findings, {total_critical} critical")
        return PhaseResult(findings=all_findings, critical_count=total_critical, error=last_error)

    async def emergency_stop(self, session_id: str):
        """Kill all running processes for a session (cross-platform)."""
        pids = await self._session.get_running_pids(session_id)
        import os
        import sys
        for pid in pids:
            try:
                if sys.platform == "win32":
                    os.kill(pid, 1)
                else:
                    import signal
                    os.kill(pid, signal.SIGTERM)
                    await asyncio.sleep(2)
                    try:
                        os.kill(pid, signal.SIGKILL)
                    except (ProcessLookupError, OSError):
                        pass
            except (ProcessLookupError, PermissionError, OSError):
                pass
        logger.warning(f"[{session_id}] Emergency stop executed")
