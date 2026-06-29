"""CHAI Web API — REST endpoints for the React frontend."""
import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, HTTPException, Query, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from app_context import get_context
from models.session import Finding, Session
from web.ws_manager import manager, log_store

logger = logging.getLogger(__name__)

api_app = FastAPI(title="CHAI Web API", version="2.0.0")

api_app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── Request models ───────────────────────────────────────────────────────────

class CreateSessionBody(BaseModel):
    target: str
    test_type: str = "web_app"
    scope: List[str] = []
    metadata: Dict[str, Any] = {}


class ScanBody(BaseModel):
    session_id: Optional[str] = None
    target: Optional[str] = None
    scope: Optional[List[str]] = None
    max_phases: int = 4
    stop_on_critical: bool = True
    generate_report: bool = True


class CommandBody(BaseModel):
    session_id: str
    command: str
    timeout: Optional[int] = None


class RunToolBody(BaseModel):
    # UI-style dispatch
    session_id: str
    target: Optional[str] = None
    tool_name: Optional[str] = None
    tool_type: Optional[str] = ""
    # Legacy direct dispatch
    tool: Optional[str] = None
    method: Optional[str] = "run"
    args: Optional[Dict[str, Any]] = None


class ReportBody(BaseModel):
    format: str = "markdown"


class EmptyBody(BaseModel):
    pass


# ── Helpers ──────────────────────────────────────────────────────────────────

def _build_tool_args(tool_name: str, tool_type: str, target: str) -> Dict[str, Any]:
    """Map the UI tool picker values to the keyword arguments each tool method expects."""
    args: Dict[str, Any] = {"target": target}
    if not tool_type:
        return args
    if tool_name == "scan_vulnerabilities":
        args["scanner"] = tool_type
    elif tool_name == "test_injection":
        args["injection_type"] = tool_type
    elif tool_name == "test_xss":
        args["xss_type"] = tool_type
    else:
        args["test_type"] = tool_type
    return args


def _get_ctx():
    ctx = get_context()
    if not ctx.is_initialized:
        raise HTTPException(status_code=503, detail="Server not initialized")
    return ctx


def _read_audit_log_entries(session_id: Optional[str] = None) -> List[Dict[str, Any]]:
    """Read entries from the NDJSON audit log file."""
    ctx = _get_ctx()
    log_path = Path(ctx.config.paths.audit_log_path)
    if not log_path.exists():
        return []
    entries = []
    try:
        with open(log_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line.split(" | ")[-1] if " | " in line else line)
                    if session_id is None or entry.get("session_id") == session_id:
                        entries.append(entry)
                except json.JSONDecodeError:
                    continue
    except Exception as e:
        logger.warning(f"Failed to read audit log: {e}")
    return entries


# ── Routes ───────────────────────────────────────────────────────────────────

@api_app.get("/api/health")
async def health():
    ctx = _get_ctx()
    return {"status": "ok", "version": ctx.config.server.version}


@api_app.get("/api/config")
async def get_config():
    ctx = _get_ctx()
    return {
        "server": {
            "name": ctx.config.server.name,
            "version": ctx.config.server.version,
            "transport": ctx.config.server.transport,
        },
        "llm": {
            "active_provider": ctx.config.llm.active_provider,
            "fallback_provider": ctx.config.llm.fallback_provider,
        },
        "ai_planner": {
            "max_phases": ctx.config.ai_planner.max_phases,
            "stop_on_critical": ctx.config.ai_planner.stop_on_critical,
        },
        "wsl": {
            "enabled": ctx.config.wsl.enabled,
            "distro_name": ctx.config.wsl.distro_name,
        },
    }


@api_app.get("/api/sessions")
async def list_sessions():
    ctx = _get_ctx()
    sessions = await ctx.session_manager.list_sessions()
    return {"sessions": [s.model_dump() for s in sessions]}


@api_app.post("/api/sessions")
async def create_session(body: CreateSessionBody):
    ctx = _get_ctx()
    session_id = await ctx.session_manager.create_session(
        target=body.target,
        test_type=body.test_type,
        scope=body.scope,
        metadata=body.metadata,
    )

    # Gather basic server/network info in the background for web targets
    if body.test_type == "web_app":
        import asyncio
        from core.server_info import ServerInfoGatherer

        async def _gather():
            try:
                gatherer = ServerInfoGatherer(ctx.process_controller)
                info = await gatherer.gather(body.target, session_id)
                await ctx.session_manager.update_session_metadata(
                    session_id, {"server_info": info}
                )
            except Exception as e:
                logger.warning(f"Server info gathering failed for {session_id}: {e}")

        asyncio.create_task(_gather())

    return {"session_id": session_id, "target": body.target, "status": "initialized"}


@api_app.get("/api/sessions/{session_id}")
async def get_session(session_id: str):
    ctx = _get_ctx()
    session = await ctx.session_manager.get_session(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    findings = await ctx.session_manager.get_findings(session_id)
    ai_decisions = await ctx.session_manager.get_ai_decisions(session_id)
    token_usage = await ctx.session_manager.get_token_usage(session_id)
    return {
        "session": session.model_dump(),
        "findings": [f.model_dump() for f in findings],
        "ai_decisions": ai_decisions,
        "token_usage": token_usage,
    }


@api_app.post("/api/sessions/{session_id}/stop")
async def stop_session(session_id: str):
    ctx = _get_ctx()
    session = await ctx.session_manager.get_session(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    await ctx.session_manager.update_session_status(session_id, "stopped")
    ctx.audit_logger.log_session_event(session_id, "stop_requested")
    return {"status": "stopped", "session_id": session_id}


@api_app.delete("/api/sessions/{session_id}")
async def delete_session(session_id: str):
    ctx = _get_ctx()
    session = await ctx.session_manager.get_session(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    deleted = await ctx.session_manager.delete_session(session_id)
    if not deleted:
        raise HTTPException(status_code=500, detail="Failed to delete session")
    return {"status": "deleted", "session_id": session_id}


@api_app.get("/api/sessions/{session_id}/findings")
async def get_session_findings(session_id: str, severity: Optional[str] = Query(None)):
    ctx = _get_ctx()
    findings = await ctx.session_manager.get_findings(session_id)
    if severity:
        findings = [f for f in findings if f.severity == severity]
    return {"findings": [f.model_dump() for f in findings]}


@api_app.get("/api/findings")
async def get_all_findings(severity: Optional[str] = Query(None)):
    ctx = _get_ctx()
    findings = await ctx.session_manager.get_all_findings(severity)
    return {"findings": [f.model_dump() for f in findings]}


@api_app.post("/api/scan/autonomous")
async def autonomous_scan(body: ScanBody):
    ctx = _get_ctx()
    from tools.autonomous import run_autonomous_scan

    if body.session_id:
        session = await ctx.session_manager.get_session(body.session_id)
        if not session:
            raise HTTPException(status_code=404, detail="Session not found")
        session_id = body.session_id
    elif body.target:
        session_id = await ctx.session_manager.create_session(
            target=body.target,
            test_type="web_app",
            scope=body.scope or [],
        )
    else:
        raise HTTPException(status_code=422, detail="Either session_id or target is required")

    await ctx.session_manager.update_session_status(session_id, "running")

    # Run asynchronously in background so the endpoint can return immediately
    import asyncio

    async def _run():
        try:
            result = await run_autonomous_scan(
                session_id=session_id,
                max_phases=body.max_phases,
                stop_on_critical=body.stop_on_critical,
                generate_report=body.generate_report,
            )
            final_status = "complete" if result.get("status") == "complete" else "error"
            await ctx.session_manager.update_session_status(session_id, final_status)
            await manager.broadcast(session_id, {
                "type": "complete" if final_status == "complete" else "error",
                "findings_count": result.get("total_findings", 0),
                "session": {"status": final_status},
                "message": result.get("error") if final_status == "error" else None,
            })
        except Exception as e:
            logger.exception(f"Autonomous scan failed for {session_id}")
            await ctx.session_manager.update_session_status(session_id, "error")
            await manager.broadcast(session_id, {
                "type": "error",
                "message": str(e),
                "session": {"status": "error"},
            })

    asyncio.create_task(_run())
    return {
        "session_id": session_id,
        "status": "running",
        "phases_completed": 0,
        "total_findings": 0,
        "critical_count": 0,
        "high_count": 0,
    }


@api_app.post("/api/tools/command")
async def run_command(body: CommandBody):
    ctx = _get_ctx()
    tool = ctx.tools.get("exec")
    if not tool:
        raise HTTPException(status_code=503, detail="Exec tool not available")
    result = await tool.run_command(
        session_id=body.session_id,
        command=body.command,
        timeout=body.timeout,
    )
    return result


@api_app.post("/api/tools/run")
async def run_tool(body: RunToolBody):
    ctx = _get_ctx()

    # New UI-style dispatch: tool_name like "recon_passive" or "test_injection"
    if body.tool_name:
        from core.execution_loop import TOOL_DISPATCH

        if body.tool_name not in TOOL_DISPATCH:
            raise HTTPException(status_code=404, detail=f"Tool '{body.tool_name}' not found")

        module_key, method_name = TOOL_DISPATCH[body.tool_name]
        tool = ctx.tools.get(module_key)
        if not tool:
            raise HTTPException(status_code=503, detail=f"Tool module '{module_key}' not available")
        if not hasattr(tool, method_name):
            raise HTTPException(
                status_code=404,
                detail=f"Method '{method_name}' not found on tool '{module_key}'",
            )

        args = _build_tool_args(body.tool_name, body.tool_type or "", body.target or "")
        method = getattr(tool, method_name)
        try:
            result = await method(session_id=body.session_id, **args)
        except TypeError as e:
            raise HTTPException(status_code=400, detail=f"Invalid arguments: {e}")
        return result

    # Legacy direct dispatch: tool + method + args
    if not body.tool:
        raise HTTPException(status_code=422, detail="Either tool_name or tool is required")

    tool = ctx.tools.get(body.tool)
    if not tool:
        raise HTTPException(status_code=404, detail=f"Tool '{body.tool}' not found")

    method_name = body.method or "run"
    if not hasattr(tool, method_name):
        # Try common prefixes
        candidates = [f"run_{body.tool}", f"test_{body.tool}", method_name]
        for cand in candidates:
            if hasattr(tool, cand):
                method_name = cand
                break
        else:
            raise HTTPException(
                status_code=404,
                detail=f"Method '{method_name}' not found on tool '{body.tool}'",
            )

    method = getattr(tool, method_name)
    try:
        result = await method(session_id=body.session_id, **(body.args or {}))
    except TypeError as e:
        raise HTTPException(status_code=400, detail=f"Invalid arguments: {e}")
    return result


@api_app.post("/api/sessions/{session_id}/report")
async def generate_report(session_id: str, body: Optional[ReportBody] = None):
    ctx = _get_ctx()
    from tools.report import ReportTools

    reporter = ReportTools(
        ctx.session_manager,
        ctx.process_controller,
        ctx.safety_policy,
        ctx.audit_logger,
        getattr(ctx, "fallback_engine", None),
    )
    report_path = await reporter.generate_report(
        session_id=session_id,
        format=body.format if body else "markdown",
    )
    return {"report_path": report_path}


@api_app.get("/api/sessions/{session_id}/report/content")
async def get_report_content(session_id: str):
    ctx = _get_ctx()
    from tools.report import ReportTools

    try:
        reports_dir = ReportTools.REPORTS_DIR
        reports_dir.mkdir(parents=True, exist_ok=True)
        for ext in [".md", ".json"]:
            path = reports_dir / f"{session_id}{ext}"
            if path.exists():
                # Use errors='replace' to avoid crashes on non-UTF-8 bytes
                raw = path.read_bytes()
                content = raw.decode("utf-8", errors="replace")
                return {
                    "content": content,
                    "format": "markdown" if ext == ".md" else "json",
                }
    except Exception as e:
        logger.warning(f"Error reading report for {session_id}: {e}")
        raise HTTPException(status_code=500, detail=f"Error reading report: {e}")
    raise HTTPException(status_code=404, detail="Report not found")


@api_app.get("/api/sessions/{session_id}/report/download")
async def download_report(session_id: str):
    ctx = _get_ctx()
    from tools.report import ReportTools

    reports_dir = ReportTools.REPORTS_DIR
    reports_dir.mkdir(parents=True, exist_ok=True)
    for ext, mime in [(".md", "text/markdown"), (".json", "application/json")]:
        path = reports_dir / f"{session_id}{ext}"
        if path.exists():
            return FileResponse(
                path=str(path),
                media_type=mime,
                filename=f"report-{session_id}{ext}",
            )
    raise HTTPException(status_code=404, detail="Report not found")


@api_app.get("/api/plugins")
async def list_plugins():
    ctx = _get_ctx()
    return {"plugins": ctx.plugin_loader.list_plugins()}


@api_app.get("/api/tools/list")
async def list_tools():
    ctx = _get_ctx()
    tools = []
    for name, tool_instance in ctx.tools.items():
        tools.append({
            "name": name,
            "type": "built_in",
            "class": tool_instance.__class__.__name__,
        })
    plugins = ctx.plugin_loader.list_plugins()
    return {"tools": tools, "plugins": plugins}


@api_app.get("/api/sessions/{session_id}/logs")
async def get_session_logs(session_id: str):
    entries = _read_audit_log_entries(session_id)
    logs = []
    for entry in entries:
        logs.append({
            "timestamp": entry.get("timestamp", ""),
            "level": "INFO",
            "message": json.dumps(entry, default=str),
            "source": entry.get("type", "unknown"),
        })
    return {"logs": logs}


@api_app.get("/api/audit-log")
async def get_audit_log():
    entries = _read_audit_log_entries()
    results = []
    for entry in entries:
        results.append({
            "timestamp": entry.get("timestamp", ""),
            "action": entry.get("type", "unknown"),
            "session_id": entry.get("session_id", ""),
            "details": json.dumps(entry, default=str),
        })
    return {"entries": results}


@api_app.get("/api/sessions/{session_id}/console-logs")
async def get_console_logs(session_id: str, limit: int = Query(500)):
    logs = log_store.read(session_id, limit=limit)
    return {"logs": logs}


@api_app.websocket("/ws/scan/{session_id}")
async def scan_websocket(session_id: str, websocket: WebSocket):
    await manager.connect(session_id, websocket)
    try:
        while True:
            data = await websocket.receive_text()
            if data.strip() == "ping":
                await websocket.send_text("pong")
    except WebSocketDisconnect:
        manager.disconnect(session_id, websocket)
    except Exception:
        manager.disconnect(session_id, websocket)
