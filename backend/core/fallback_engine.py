"""Intelligent fallback and self-recovery engine.

When a tool execution fails, this engine:
1. Analyzes the error context (command, stdout, stderr, tool name, platform).
2. Searches the web via DuckDuckGo for troubleshooting steps.
3. Extracts relevant fixes from search results.
4. Applies safe corrective actions (install missing deps, fix configs, etc.).
5. Retries the original operation automatically.
6. Provides detailed logs of the entire recovery process.
"""
import asyncio
import json
import logging
import os
import re
import sys
from pathlib import Path
from typing import Dict, List, Optional, Any

logger = logging.getLogger(__name__)

# ── Try to import DuckDuckGo search (new package name is ddgs; old name duckduckgo-search) ──
_DDGS_AVAILABLE = False
try:
    from ddgs import DDGS
    _DDGS_AVAILABLE = True
except Exception:
    try:
        from duckduckgo_search import DDGS
        _DDGS_AVAILABLE = True
    except Exception:
        logger.warning("DuckDuckGo search package (ddgs / duckduckgo-search) not installed. Web search fallback will use basic HTTP mode.")


class RecoveryLog:
    """Immutable record of a single recovery attempt."""

    def __init__(
        self,
        step: str,
        status: str,  # "attempted", "success", "failed", "skipped"
        details: Dict[str, Any],
        error: str = "",
    ):
        self.step = step
        self.status = status
        self.details = details
        self.error = error

    def to_dict(self) -> Dict[str, Any]:
        return {
            "step": self.step,
            "status": self.status,
            "details": self.details,
            "error": self.error,
        }


class FallbackEngine:
    """
    Self-healing layer that diagnoses tool failures, searches the web for fixes,
    and retries with corrective actions.
    """

    def __init__(
        self,
        config,
        process_controller,
        safety_policy,
        wsl_adapter=None,
        sudo_handler=None,
        max_retries: int = 2,
    ):
        self._config = config
        self._process = process_controller
        self._safety = safety_policy
        self._wsl = wsl_adapter
        self._sudo_handler = sudo_handler
        self._max_retries = max_retries
        self._retry_counts: Dict[str, int] = {}  # key: "session_id:tool_name"
        self._recovery_logs: Dict[str, List[RecoveryLog]] = {}

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def handle_failure(
        self,
        command: str,
        original_result: Dict[str, Any],
        tool_name: str,
        session_id: str,
        timeout: Optional[int] = None,
        sandbox_level: str = "firejail",
    ) -> Dict[str, Any]:
        """
        Main entry point: a tool has failed; try to recover and retry.

        Returns the *retry result* if recovery succeeds, or the original
        result decorated with recovery logs if all attempts fail.
        """
        retry_key = f"{session_id}:{tool_name}:{hash(command) & 0xFFFFFF}"
        current_retry = self._retry_counts.get(retry_key, 0)

        logs: List[RecoveryLog] = []

        # 1. Check retry budget
        if current_retry >= self._max_retries:
            logs.append(
                RecoveryLog(
                    step="retry_budget_check",
                    status="skipped",
                    details={"max_retries": self._max_retries, "current": current_retry},
                    error="Max retries already exhausted",
                )
            )
            return self._decorate_result(original_result, logs)

        self._retry_counts[retry_key] = current_retry + 1

        # 2. Analyze the failure
        analysis = self._analyze_error(command, original_result, tool_name)
        logs.append(
            RecoveryLog(
                step="error_analysis",
                status="success",
                details=analysis,
            )
        )
        logger.info(f"[{session_id}] Fallback analysis: {analysis['category']} — {analysis['summary']}")

        # 3. Web search for fixes
        search_results = await self._search_for_fixes(analysis, tool_name)
        logs.append(
            RecoveryLog(
                step="web_search",
                status="success" if search_results else "failed",
                details={"query_count": len(search_results), "results": [r["title"] for r in search_results[:3]]},
            )
        )

        # 4. Extract corrective actions
        fixes = self._extract_fixes(search_results, analysis)
        logs.append(
            RecoveryLog(
                step="fix_extraction",
                status="success" if fixes else "failed",
                details={"fixes_found": len(fixes), "fixes": fixes},
            )
        )

        # 5. Attempt fixes
        fix_applied = False
        logger.info(f"[{session_id}] Will attempt {len(fixes)} fix(es): {[f.get('type') for f in fixes]}")
        for i, fix in enumerate(fixes):
            fix_type = fix.get("type", "unknown")
            fix_cmd = fix.get("command", "")
            logger.info(f"[{session_id}] Fix {i+1}/{len(fixes)}: type={fix_type}, cmd={fix_cmd[:80]}...")
            success = await self._apply_fix(fix, session_id, logs)
            if success:
                logger.info(f"[{session_id}] Fix {i+1} succeeded — stopping fix loop")
                fix_applied = True
                break
            else:
                logger.info(f"[{session_id}] Fix {i+1} failed — trying next fix")
        if not fix_applied:
            logger.warning(f"[{session_id}] All {len(fixes)} fix(es) failed — recovery unsuccessful")

        # 6. Retry the original command only if a fix was actually applied.
        if fix_applied:
            retry_result = await self._retry_command(
                command=command,
                session_id=session_id,
                timeout=timeout,
                sandbox_level=sandbox_level,
                analysis=analysis,
            )
            logs.append(
                RecoveryLog(
                    step="retry_execution",
                    status="success" if retry_result.get("returncode", -1) == 0 else "failed",
                    details={
                        "returncode": retry_result.get("returncode"),
                        "stdout_preview": retry_result.get("stdout", "")[:200],
                        "stderr_preview": retry_result.get("stderr", "")[:200],
                    },
                )
            )

            if retry_result.get("returncode", -1) == 0:
                logger.info(f"[{session_id}] Fallback recovery succeeded for {tool_name}")
                retry_result["_recovery_logs"] = [log.to_dict() for log in logs]
                retry_result["_recovered"] = True
                return retry_result

        logger.warning(f"[{session_id}] Fallback recovery failed for {tool_name} after all attempts")
        return self._decorate_result(original_result, logs)

    def get_recovery_logs(self, session_id: str) -> List[Dict[str, Any]]:
        """Return all recovery logs for a session."""
        return [log.to_dict() for log in self._recovery_logs.get(session_id, [])]

    async def search_web(
        self,
        query: str,
        max_results: int = 3,
    ) -> List[Dict[str, Any]]:
        """
        Public DuckDuckGo search hook reused by the AI brain layer.
        Returns a list of {title, href, body} dicts.
        """
        return await self._ddg_search(query, max_results=max_results)

    # ------------------------------------------------------------------
    # 1. Error analysis
    # ------------------------------------------------------------------

    def _analyze_error(
        self,
        command: str,
        result: Dict[str, Any],
        tool_name: str,
    ) -> Dict[str, Any]:
        """Categorize the failure and extract key signals."""
        stderr = result.get("stderr", "")
        stdout = result.get("stdout", "")
        returncode = result.get("returncode", -1)
        error_str = result.get("error", "")
        combined = f"{stderr}\n{stdout}\n{error_str}".lower()

        category = "unknown"
        summary = "Unrecognized error pattern"
        missing_tool = None
        config_issue = None

        # Missing binary / command not found
        if any(p in combined for p in ("not found", "command not found", "no such file or directory", "is not recognized")):
            category = "missing_tool"
            summary = "Required binary or dependency is missing"
            missing_tool = self._extract_missing_binary(stderr, command, tool_name)

        # Permission denied
        elif any(p in combined for p in ("permission denied", "access is denied", "operation not permitted")):
            category = "permission_error"
            summary = "Insufficient permissions to execute"

        # Network / connectivity
        elif any(p in combined for p in ("could not resolve", "connection refused", "timeout", "network is unreachable", "no route to host")):
            category = "network_error"
            summary = "Network connectivity issue"

        # Syntax / argument errors
        elif any(p in combined for p in ("unrecognized option", "invalid argument", "bad usage", "unknown flag", "error: unrecognized")):
            category = "syntax_error"
            summary = "Command syntax or flag issue"

        # Config / dependency missing
        elif any(p in combined for p in ("module not found", "no module named", "cannot find module", "library not found", "lib not found", "missing dependency")):
            category = "missing_dependency"
            summary = "Missing runtime dependency or library"
            m = re.search(r"no module named ['\"]?([a-zA-Z0-9_.-]+)", combined, re.I)
            if m:
                missing_tool = m.group(1)

        # Segfault / crash
        elif any(p in combined for p in ("segmentation fault", "segfault", "core dumped", "abort", "assertion failed")):
            category = "crash"
            summary = "Tool crashed during execution"

        # WSL-specific
        elif any(p in combined for p in ("wsl", "the linux subsystem")):
            category = "wsl_error"
            summary = "WSL-related execution issue"

        return {
            "category": category,
            "summary": summary,
            "missing_tool": missing_tool,
            "config_issue": config_issue,
            "returncode": returncode,
            "stderr_preview": stderr[:500],
            "stdout_preview": stdout[:500],
            "platform": sys.platform,
            "wsl_active": self._wsl.is_active() if self._wsl else False,
        }

    def _extract_missing_binary(self, stderr: str, command: str, tool_name: str) -> Optional[str]:
        """
        Try to identify the actual missing binary from stderr or the command.
        Handles formats like 'ffuf: command not found' and 'command not found: ffuf'.
        """
        # Pattern 1: '<binary>: command not found' or '<binary>: not found'
        m = re.search(r"([a-zA-Z0-9_.\-]+)\s*:\s*(?:command)?\s*not found", stderr, re.I)
        if m:
            return m.group(1).strip()

        # Pattern 2: 'command not found: <binary>'
        m = re.search(r"(?:command)?\s*not found\s*:\s*([a-zA-Z0-9_.\-]+)", stderr, re.I)
        if m:
            return m.group(1).strip()

        # Pattern 3: 'no such file or directory: <path/binary>'
        m = re.search(r"no such file or directory\s*:\s*([a-zA-Z0-9_.\-/]+)", stderr, re.I)
        if m:
            return Path(m.group(1)).name.strip()

        # Pattern 4: extract the first word of the command (the invoked binary)
        cmd_first = command.strip().split()[0] if command else ""
        if cmd_first and not cmd_first.startswith(("bash", "sh", "sudo", "wsl")):
            return Path(cmd_first).name.strip()

        return tool_name

    # ------------------------------------------------------------------
    # 2. Web search for fixes
    # ------------------------------------------------------------------

    async def _search_for_fixes(
        self,
        analysis: Dict[str, Any],
        tool_name: str,
    ) -> List[Dict[str, Any]]:
        """Search DuckDuckGo for troubleshooting steps related to the error."""
        queries = self._build_search_queries(analysis, tool_name)
        all_results: List[Dict[str, Any]] = []

        for query in queries:
            try:
                results = await self._ddg_search(query, max_results=3)
                all_results.extend(results)
                await asyncio.sleep(0.5)  # Be polite to DDG
            except Exception as e:
                logger.debug(f"Web search query failed: {query} — {e}")

        return all_results

    def _build_search_queries(
        self,
        analysis: Dict[str, Any],
        tool_name: str,
    ) -> List[str]:
        """Build targeted search queries from the error context."""
        queries = []
        category = analysis["category"]
        missing = analysis.get("missing_tool", "")
        stderr_preview = analysis.get("stderr_preview", "")[:120]

        platform_hint = ""
        if sys.platform == "win32":
            platform_hint = "Windows"
        elif sys.platform == "darwin":
            platform_hint = "macOS"
        else:
            platform_hint = "Linux"

        # Category-specific queries
        if category == "missing_tool" and missing:
            queries.append(f"how to install {missing} on {platform_hint}")
            queries.append(f"{missing} command not found {platform_hint} install")
            if tool_name and tool_name != missing:
                queries.append(f"{tool_name} requires {missing} dependency install")

        elif category == "permission_error":
            queries.append(f"{tool_name} permission denied {platform_hint} fix")

        elif category == "network_error":
            queries.append(f"{tool_name} connection refused timeout troubleshooting")

        elif category == "syntax_error":
            queries.append(f"{tool_name} unrecognized option invalid argument correct usage")

        elif category == "missing_dependency":
            queries.append(f"{missing or tool_name} missing module library install {platform_hint}")

        elif category == "crash":
            queries.append(f"{tool_name} segmentation fault crash fix {platform_hint}")

        elif category == "wsl_error":
            queries.append(f"WSL {tool_name} execution error fix Windows")

        # Fallback: generic error search
        if not queries:
            queries.append(f"{tool_name} error {stderr_preview} {platform_hint}")

        return queries[:3]

    async def _ddg_search(self, query: str, max_results: int = 3) -> List[Dict[str, Any]]:
        """Execute a DuckDuckGo search and return structured results."""
        results = []

        if _DDGS_AVAILABLE:
            try:
                # Run sync DDGS in thread pool to avoid blocking; cap total wait time.
                loop = asyncio.get_running_loop()

                def _search():
                    with DDGS() as ddgs:
                        return ddgs.text(keywords=query, max_results=max_results)

                ddg_results = await asyncio.wait_for(
                    loop.run_in_executor(None, _search),
                    timeout=15,
                )
                for r in ddg_results:
                    results.append({
                        "title": r.get("title", ""),
                        "href": r.get("href", ""),
                        "body": r.get("body", "")[:800],
                    })
            except asyncio.TimeoutError:
                logger.debug(f"DDGS search timed out for query: {query}")
            except Exception as e:
                logger.debug(f"DDGS search error: {e}")
        else:
            # Fallback HTTP search using requests (basic scraping of DDG HTML)
            results = await self._http_search(query, max_results)

        return results

    async def _http_search(self, query: str, max_results: int = 3) -> List[Dict[str, Any]]:
        """Basic HTTP-based DuckDuckGo search when the package is unavailable."""
        import urllib.parse
        import urllib.request

        encoded = urllib.parse.quote_plus(query)
        url = f"https://html.duckduckgo.com/html/?q={encoded}"

        try:
            loop = asyncio.get_running_loop()
            # Run blocking urllib in executor
            def _fetch():
                req = urllib.request.Request(
                    url,
                    headers={
                        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.0",
                        "Accept": "text/html",
                    },
                )
                with urllib.request.urlopen(req, timeout=15) as resp:
                    return resp.read().decode("utf-8", errors="replace")

            html = await asyncio.wait_for(loop.run_in_executor(None, _fetch), timeout=20)

            # Very basic regex extraction of results
            items = []
            # DuckDuckGo HTML result blocks
            result_blocks = re.findall(
                r'<a[^>]*class="result__a"[^>]*href="([^"]*)"[^>]*>(.*?)</a>.*?<a[^>]*class="result__snippet"[^>]*>(.*?)</a>',
                html,
                re.S | re.I,
            )
            for href, title, snippet in result_blocks[:max_results]:
                # Clean HTML tags
                title_clean = re.sub(r"<[^>]+>", "", title)
                snippet_clean = re.sub(r"<[^>]+>", "", snippet)
                items.append({
                    "title": title_clean.strip(),
                    "href": href.strip(),
                    "body": snippet_clean.strip()[:800],
                })
            return items
        except Exception as e:
            logger.debug(f"HTTP search fallback failed: {e}")
            return []

    # ------------------------------------------------------------------
    # 3. Extract fixes from search results
    # ------------------------------------------------------------------

    def _extract_fixes(
        self,
        search_results: List[Dict[str, Any]],
        analysis: Dict[str, Any],
    ) -> List[Dict[str, Any]]:
        """Parse search result text to extract actionable shell commands."""
        fixes = []
        category = analysis["category"]
        missing_tool = analysis.get("missing_tool", "")

        # Pattern-based fix extraction
        # Skip common flags (-y, --yes, -q, etc.) when extracting the package name
        install_patterns = [
            re.compile(r"(?:apt-get|apt|yum|dnf|pacman|brew|apk|pip|pip3|npm|gem)\s+(?:install|add|-S)\s+(?:-[a-zA-Z]+\s+)*([a-zA-Z0-9_.\-]+)", re.I),
            re.compile(r"(?:sudo\s+)?(?:apt-get|apt)\s+install\s+(?:-[a-zA-Z]+\s+)*([a-zA-Z0-9_.\-]+)", re.I),
        ]

        permission_patterns = [
            re.compile(r"chmod\s+([0-7]+)\s+([a-zA-Z0-9_./\-]+)", re.I),
            re.compile(r"chown\s+([a-zA-Z0-9_:.-]+)\s+([a-zA-Z0-9_./\-]+)", re.I),
            re.compile(r"sudo\s+(.+)", re.I),
        ]

        for result in search_results:
            body = result.get("body", "")
            title = result.get("title", "")
            text = f"{title}\n{body}"

            # Install-based fixes — single command, no shell chaining (&& || ;)
            # Safety policy strips chaining operators, which breaks the command.
            for pattern in install_patterns:
                for m in pattern.finditer(text):
                    pkg = m.group(1).strip().split()[0]
                    # Choose command based on platform / WSL
                    if self._wsl and self._wsl.is_active():
                        fix = {
                            "type": "wsl_install_package_root",
                            "package": pkg,
                            "command": f"apt-get install -y {pkg}",
                            "source": result.get("href", ""),
                            "description": f"Install missing package '{pkg}' inside WSL as root",
                        }
                    else:
                        fix = {
                            "type": "install_package",
                            "package": pkg,
                            "command": f"sudo apt-get install -y {pkg}",
                            "source": result.get("href", ""),
                            "description": f"Install missing package '{pkg}'",
                        }
                    if fix not in fixes:
                        fixes.append(fix)

            # Permission fixes
            for pattern in permission_patterns:
                for m in pattern.finditer(text):
                    if "chmod" in m.group(0).lower():
                        fix = {
                            "type": "fix_permission",
                            "command": m.group(0),
                            "source": result.get("href", ""),
                            "description": "Fix file permissions",
                        }
                    elif "chown" in m.group(0).lower():
                        fix = {
                            "type": "fix_ownership",
                            "command": m.group(0),
                            "source": result.get("href", ""),
                            "description": "Fix file ownership",
                        }
                    else:
                        fix = {
                            "type": "sudo_command",
                            "command": m.group(0),
                            "source": result.get("href", ""),
                            "description": "Run with elevated privileges",
                        }
                    if fix not in fixes:
                        fixes.append(fix)

        # If analysis says missing tool and no install fix found, add a generic one
        # NOTE: Never use shell chaining (&& || ;) — safety policy strips them.
        if category == "missing_tool" and missing_tool:
            has_install = any(f["type"] in ("install_package", "wsl_install_package", "wsl_install_package_root") for f in fixes)
            if not has_install:
                if self._wsl and self._wsl.is_active():
                    # WSL: will be run as root via sudo_handler.run_elevated_wsl
                    fixes.insert(0, {
                        "type": "wsl_install_package_root",
                        "package": missing_tool,
                        "command": f"apt-get install -y {missing_tool}",
                        "source": "fallback_heuristic_wsl",
                        "description": f"Install '{missing_tool}' inside WSL as root",
                    })
                else:
                    fixes.insert(0, {
                        "type": "install_package",
                        "package": missing_tool,
                        "command": f"sudo apt-get install -y {missing_tool}",
                        "source": "fallback_heuristic",
                        "description": f"Auto-generated install for missing tool '{missing_tool}'",
                        "timeout": 120,
                    })

        # WSL-specific: if WSL is active and tool missing, ensure a root-elevated fix exists
        if self._wsl and self._wsl.is_active() and category == "missing_tool" and missing_tool:
            has_wsl_root = any(f["type"] == "wsl_install_package_root" for f in fixes)
            if not has_wsl_root:
                fixes.insert(0, {
                    "type": "wsl_install_package_root",
                    "package": missing_tool,
                    "command": f"apt-get install -y {missing_tool}",
                    "source": "wsl_fallback_root",
                    "description": f"Install '{missing_tool}' inside WSL as root (avoids sudo password prompt)",
                })

        return fixes[:5]  # Limit to top 5 fixes

    # ------------------------------------------------------------------
    # 4. Apply fixes
    # ------------------------------------------------------------------

    async def _apply_fix(
        self,
        fix: Dict[str, Any],
        session_id: str,
        logs: List[RecoveryLog],
    ) -> bool:
        """Attempt a single corrective action. Returns True on success."""
        fix_type = fix.get("type", "")
        command = fix.get("command", "")
        if not command:
            return False

        # Install fixes are capped tightly so the MCP client does not cancel the whole request.
        fix_timeout = fix.get("timeout", 120)

        # Validate safety
        logger.info(f"[{session_id}] Validating fix ({fix_type}): {command[:120]}...")
        validation = await self._safety.validate(command, session_id)
        if not validation["approved"]:
            reason = validation.get("reason", "unknown")
            modified = validation.get("modified_command", command)
            logger.warning(f"[{session_id}] Fix ({fix_type}) BLOCKED by safety policy: {reason}. "
                           f"Modified command would be: {modified[:120]}...")
            logs.append(
                RecoveryLog(
                    step=f"apply_fix:{fix_type}",
                    status="skipped",
                    details=fix,
                    error=f"Fix blocked by safety policy: {reason}",
                )
            )
            return False

        validated_cmd = validation.get("modified_command", command)
        if validated_cmd != command:
            logger.info(f"[{session_id}] Fix command modified by safety: '{command[:80]}' -> '{validated_cmd[:80]}'")

        # Execute fix
        try:
            logger.info(f"[{session_id}] Applying fix ({fix_type}): {validated_cmd[:120]}... timeout={fix_timeout}s")
            if fix_type == "wsl_install_package_root" and self._wsl and self._wsl.is_active():
                # Use root elevation if sudo_handler is available
                if hasattr(self, "_sudo_handler") and self._sudo_handler:
                    logger.info(f"[{session_id}] Elevating fix via WSL root")
                    result = await self._sudo_handler.run_elevated_wsl(
                        command=validated_cmd,
                        session_id=f"{session_id}-recovery",
                        timeout=fix_timeout,
                        distro_name=self._wsl._cfg.distro_name,
                    )
                else:
                    logger.warning(f"[{session_id}] No sudo_handler — falling back to regular WSL (may hang on sudo)")
                    result = await self._wsl.run(
                        validated_cmd,
                        session_id=f"{session_id}-recovery",
                        timeout=fix_timeout,
                    )
            elif fix_type in ("install_package", "fix_permission", "fix_ownership", "sudo_command"):
                # Native Linux — use process controller (already has sudo retry logic)
                result = await self._process.run(
                    command=validated_cmd,
                    session_id=f"{session_id}-recovery",
                    timeout=fix_timeout,
                    sandbox_level="none",
                )
            else:
                result = await self._process.run(
                    command=validated_cmd,
                    session_id=f"{session_id}-recovery",
                    timeout=fix_timeout,
                    sandbox_level="none",
                )

            success = result.get("returncode", -1) == 0
            logs.append(
                RecoveryLog(
                    step=f"apply_fix:{fix_type}",
                    status="success" if success else "failed",
                    details={"command": command, "returncode": result.get("returncode")},
                    error=result.get("stderr", "")[:300] if not success else "",
                )
            )
            return success

        except Exception as e:
            logs.append(
                RecoveryLog(
                    step=f"apply_fix:{fix_type}",
                    status="failed",
                    details={"command": command},
                    error=str(e)[:300],
                )
            )
            return False

    # ------------------------------------------------------------------
    # 5. Retry original command
    # ------------------------------------------------------------------

    async def _retry_command(
        self,
        command: str,
        session_id: str,
        timeout: Optional[int],
        sandbox_level: str,
        analysis: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Re-run the original command after attempted fixes."""
        # If WSL is active and the original failure was on Windows, try WSL
        if self._wsl and self._wsl.is_active() and analysis.get("wsl_active"):
            return await self._wsl.run(command, session_id, timeout or 300)

        # Re-validate and execute through normal process controller
        validation = await self._safety.validate(command, session_id)
        if not validation["approved"]:
            return {
                "stdout": "",
                "stderr": f"Retry blocked by safety policy: {validation['reason']}",
                "returncode": -1,
                "blocked": True,
            }

        return await self._process.run(
            command=validation.get("modified_command", command),
            session_id=session_id,
            timeout=timeout or validation.get("max_timeout", 300),
            sandbox_level=sandbox_level,
        )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _decorate_result(
        self,
        original_result: Dict[str, Any],
        logs: List[RecoveryLog],
    ) -> Dict[str, Any]:
        """Attach recovery logs to the original (still-failed) result."""
        decorated = dict(original_result)
        decorated["_recovery_logs"] = [log.to_dict() for log in logs]
        decorated["_recovered"] = False
        return decorated
