"""Main MCP server using FastMCP.
Registers all tools and handles stdio/SSE transport.
"""
import argparse
import asyncio
import logging
import os
import sys
from datetime import datetime
from pathlib import Path
from typing import Any

from mcp.server.fastmcp import FastMCP

from config import load_config
from llm.provider_factory import get_provider_with_fallback
from core.session_manager import SessionManager
from core.safety_policy import SafetyPolicy
from core.process_controller import ProcessController
from core.audit_logger import AuditLogger
from core.ai_planner import AIPlanner
from core.execution_loop import ExecutionLoop
from core.wsl_adapter import WSLAdapter
from core.fallback_engine import FallbackEngine
from core.sudo_handler import SudoHandler
from kb.graph_db import GraphDB
from kb.playbook_loader import PlaybookLoader
from kb.vector_search import VectorSearch
from plugins.plugin_loader import PluginLoader
from tools.recon import ReconTools
from tools.scan import ScanTools
from tools.injection import InjectionTools
from tools.auth import AuthTools
from tools.network import NetworkTools
from tools.poc import PocTools
from tools.exec import ExecTools
from tools.analyze import AnalyzeTools
from tools.report import ReportTools
from tools.xss import XssTools
from tools.ssrf import SsrfTools
from tools.access_control import AccessControlTools
from tools.api_security import ApiSecurityTools
from tools.misconfig import MisconfigTools
from tools.rate_limit import RateLimitTools
from tools.sensitive_data import SensitiveDataTools
from tools.business_logic import BusinessLogicTools
from tools.autonomous import run_autonomous_scan
from app_context import AppContext


# ── Logging Setup ────────────────────────────────────────────────────────────
_LOG_FORMAT = "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s"
_LOG_DATE_FMT = "%Y-%m-%d %H:%M:%S"


def _setup_daily_file_logging(log_dir: str, log_level: str = "info") -> None:
    """
    Configure root logger with:
    - Console handler (stderr) — always active
    - Daily rotating file handler — creates chai-YYYY-MM-DD.log every day
    """
    level = getattr(logging, log_level.upper(), logging.INFO)

    # Ensure log directory exists
    Path(log_dir).mkdir(parents=True, exist_ok=True)

    # Daily filename: chai-2026-06-25.log
    today = datetime.now().strftime("%Y-%m-%d")
    log_file = Path(log_dir) / f"chai-{today}.log"

    # Formatter
    formatter = logging.Formatter(_LOG_FORMAT, datefmt=_LOG_DATE_FMT)

    # Root logger
    root = logging.getLogger()
    root.setLevel(level)

    # Remove existing handlers to avoid duplicates on re-init
    for h in root.handlers[:]:
        root.removeHandler(h)
        h.close()

    # 1. Console handler
    console = logging.StreamHandler(sys.stderr)
    console.setLevel(level)
    console.setFormatter(formatter)
    root.addHandler(console)

    # 2. Daily file handler (creates a new file each calendar day)
    file_handler = logging.FileHandler(str(log_file), mode="a", encoding="utf-8")
    file_handler.setLevel(level)
    file_handler.setFormatter(formatter)
    root.addHandler(file_handler)

    # 3. WebSocket broadcast handler (streams session logs to the UI in real time)
    try:
        from web.ws_manager import manager, WebSocketLogHandler, log_store

        session_log_dir = Path(log_dir) / "session_logs"
        session_log_dir.mkdir(parents=True, exist_ok=True)
        log_store.set_base_dir(str(session_log_dir))

        ws_handler = WebSocketLogHandler(manager, level=level)
        ws_handler.setFormatter(formatter)
        root.addHandler(ws_handler)
        logging.info("WebSocket log handler attached")
    except Exception as e:
        logging.warning(f"Could not attach WebSocket log handler: {e}")

    logging.info(f"Logging configured: console + file={log_file}, level={log_level.upper()}")


# Minimal startup logger (replaced after config loads)
logging.basicConfig(
    level=logging.INFO,
    format=_LOG_FORMAT,
    datefmt=_LOG_DATE_FMT,
    handlers=[logging.StreamHandler(sys.stderr)],
)
logger = logging.getLogger(__name__)

# Initialize MCP server
mcp = FastMCP("chai-mcp-security")

# Global context
_ctx = AppContext()


async def _start_web_server(web_port: int):
    """Start the CHAI web UI on a separate port using FastAPI + uvicorn."""
    import uvicorn
    try:
        from web.api import api_app
    except ModuleNotFoundError:
        logger.warning("Web UI module (web.api) not found. Skipping web server.")
        return
    logger.info(f"Starting CHAI Web UI on port {web_port}")
    config = uvicorn.Config(
        api_app,
        host="0.0.0.0",
        port=web_port,
        log_level="info",
    )
    server = uvicorn.Server(config)
    await server.serve()


async def initialize():
    """Initialize all components."""
    logger.info("Initializing CHAI MCP Security Server v2.0.0")

    # Load configuration (paths relative to backend/ directory)
    backend_dir = Path(__file__).parent
    config = load_config(str(backend_dir / "config.yaml"), str(backend_dir / ".security.yml"))

    # Reconfigure logging with daily file rotation based on config
    # Use the unified CHAI temp directory: <temp>/.chai/logs/
    log_dir = Path(config.paths.audit_log_path).parent
    log_dir.mkdir(parents=True, exist_ok=True)
    _setup_daily_file_logging(str(log_dir), config.server.log_level)

    # Initialize database components
    session_manager = SessionManager(config.paths.session_db)
    await session_manager.initialize()

    graph_db = GraphDB(config.paths.kb_path + "/graph.db")
    await graph_db.initialize()

    # Initialize WSL adapter (Windows cross-platform support)
    wsl_adapter = WSLAdapter(config.wsl)
    if wsl_adapter.is_active():
        logger.info(f"WSL adapter active: distro={config.wsl.distro_name or 'default'}, user={config.wsl.username or 'current'}")
    else:
        logger.info("WSL adapter not active (native Linux or WSL disabled)")

    # Initialize sudo / elevation handler
    sudo_handler = SudoHandler(
        wsl_adapter=wsl_adapter,
        password=config.wsl.password or config.secrets.wsl.get("password", ""),
    )

    # Auto-configure passwordless sudo in WSL when a password is available
    if wsl_adapter.is_active() and config.wsl.username and (config.wsl.password or config.secrets.wsl.get("password")):
        logger.info(f"[SUDO] Attempting to configure passwordless sudo for WSL user '{config.wsl.username}'")
        sudo_ok = await sudo_handler.configure_passwordless_sudo_wsl(
            distro_name=config.wsl.distro_name,
            username=config.wsl.username,
        )
        if sudo_ok:
            logger.info("[SUDO] Passwordless sudo is now configured — future sudo commands will not prompt for a password")
        else:
            logger.warning("[SUDO] Could not configure passwordless sudo; elevated commands will run as root via 'wsl -u root'")

    # Initialize controllers
    process_controller = ProcessController(config, wsl_adapter=wsl_adapter, sudo_handler=sudo_handler)
    safety_policy = SafetyPolicy(config)
    audit_logger = AuditLogger(config.paths.audit_log_path)

    # Initialize fallback / self-recovery engine
    fallback_engine = FallbackEngine(
        config=config,
        process_controller=process_controller,
        safety_policy=safety_policy,
        wsl_adapter=wsl_adapter,
        sudo_handler=sudo_handler,
        max_retries=2,
    )

    # Initialize LLM provider
    provider = await get_provider_with_fallback(config)
    logger.info(f"LLM provider initialized: {provider.provider_name}")

    # Initialize KB components
    playbook_loader = PlaybookLoader(config.paths.kb_path)
    vector_search = VectorSearch(config.paths.kb_path + "/vectors.db")
    await vector_search.initialize()

    # Initialize plugins (with WSL, fallback, and sudo support)
    plugin_loader = PluginLoader(
        config, process_controller, safety_policy, session_manager,
        wsl_adapter=wsl_adapter, fallback_engine=fallback_engine,
        sudo_handler=sudo_handler,
    )
    await plugin_loader.load_all()

    # Initialize tools registry (pass fallback_engine for self-recovery)
    tools = {
        "recon": ReconTools(session_manager, process_controller, safety_policy, audit_logger, fallback_engine),
        "scan": ScanTools(session_manager, process_controller, safety_policy, audit_logger, fallback_engine),
        "injection": InjectionTools(session_manager, process_controller, safety_policy, audit_logger, fallback_engine),
        "auth": AuthTools(session_manager, process_controller, safety_policy, audit_logger, fallback_engine),
        "network": NetworkTools(session_manager, process_controller, safety_policy, audit_logger, fallback_engine),
        "poc": PocTools(session_manager, process_controller, safety_policy, audit_logger, fallback_engine),
        "exec": ExecTools(session_manager, process_controller, safety_policy, audit_logger, fallback_engine),
        "analyze": AnalyzeTools(session_manager, process_controller, safety_policy, audit_logger, fallback_engine),
        "report": ReportTools(session_manager, process_controller, safety_policy, audit_logger, fallback_engine),
        "xss": XssTools(session_manager, process_controller, safety_policy, audit_logger, fallback_engine),
        "ssrf": SsrfTools(session_manager, process_controller, safety_policy, audit_logger, fallback_engine),
        "access_control": AccessControlTools(session_manager, process_controller, safety_policy, audit_logger, fallback_engine),
        "api_security": ApiSecurityTools(session_manager, process_controller, safety_policy, audit_logger, fallback_engine),
        "misconfig": MisconfigTools(session_manager, process_controller, safety_policy, audit_logger, fallback_engine),
        "rate_limit": RateLimitTools(session_manager, process_controller, safety_policy, audit_logger, fallback_engine),
        "sensitive_data": SensitiveDataTools(session_manager, process_controller, safety_policy, audit_logger, fallback_engine),
        "business_logic": BusinessLogicTools(session_manager, process_controller, safety_policy, audit_logger, fallback_engine),
    }

    # Store in context
    _ctx.initialize(
        config=config,
        provider=provider,
        session_manager=session_manager,
        process_controller=process_controller,
        safety_policy=safety_policy,
        audit_logger=audit_logger,
        graph_db=graph_db,
        playbook_loader=playbook_loader,
        plugin_loader=plugin_loader,
        tools=tools,
        fallback_engine=fallback_engine,
        wsl_adapter=wsl_adapter,
        sudo_handler=sudo_handler,
    )

    logger.info("Server initialization complete")


# ─── MCP TOOLS ───────────────────────────────────────────────────────────────

@mcp.tool()
async def initialize_session(
    target: str,
    test_type: str = "web_app",
    scope: list[str] | None = None,
    metadata: dict[str, Any] | None = None,
) -> dict:
    """Initialize a new penetration testing session."""
    session_id = await _ctx.session_manager.create_session(
        target=target,
        test_type=test_type,
        scope=scope or [],
        metadata=metadata or {},
    )
    await _ctx.session_manager.update_session_status(session_id, "running")
    _ctx.audit_logger.log_session_event(session_id, "initialized", {"target": target, "test_type": test_type})
    return {"session_id": session_id, "target": target, "status": "initialized"}


@mcp.tool()
async def run_recon(
    session_id: str,
    target: str,
    recon_type: str = "passive",
) -> dict:
    """Run reconnaissance tools."""
    tool = _ctx.tools["recon"]
    if recon_type == "passive":
        result = await tool.run_passive(session_id=session_id, target=target)
    else:
        result = await tool.run_active(session_id=session_id, target=target)
    return result


@mcp.tool()
async def scan_vulnerabilities(
    session_id: str,
    target: str,
    scanner: str = "nuclei",
    ports: str = "1-65535",
) -> dict:
    """Run vulnerability scanning."""
    tool = _ctx.tools["scan"]
    result = await tool.run_scan(session_id=session_id, target=target, scanner=scanner, ports=ports)
    return result


@mcp.tool()
async def test_injection(
    session_id: str,
    target: str,
    injection_type: str = "sqli",
) -> dict:
    """Run injection vulnerability tests."""
    tool = _ctx.tools["injection"]
    result = await tool.run_injection(session_id=session_id, target=target, injection_type=injection_type)
    return result


@mcp.tool()
async def test_authentication(
    session_id: str,
    target: str,
    test_type: str = "bypass",
) -> dict:
    """Run authentication tests."""
    tool = _ctx.tools["auth"]
    result = await tool.run_auth(session_id=session_id, target=target, test_type=test_type)
    return result


@mcp.tool()
async def test_network(
    session_id: str,
    target: str,
    test_type: str = "ssl",
) -> dict:
    """Run network security tests."""
    tool = _ctx.tools["network"]
    result = await tool.run_network(session_id=session_id, target=target, test_type=test_type)
    return result


@mcp.tool()
async def test_xss(
    session_id: str,
    target: str,
    xss_type: str = "reflected",
) -> dict:
    """Run Cross-Site Scripting (XSS) tests. Types: reflected, stored, dom, header_reflected, csp."""
    tool = _ctx.tools["xss"]
    result = await tool.run_xss(session_id=session_id, target=target, xss_type=xss_type)
    return result


@mcp.tool()
async def test_ssrf(
    session_id: str,
    target: str,
) -> dict:
    """Run Server-Side Request Forgery (SSRF) tests."""
    tool = _ctx.tools["ssrf"]
    result = await tool.run_ssrf(session_id=session_id, target=target)
    return result


@mcp.tool()
async def test_access_control(
    session_id: str,
    target: str,
    test_type: str = "idor",
) -> dict:
    """Run broken access control tests. Types: idor, bola, path_traversal, method_tampering, forced_browsing."""
    tool = _ctx.tools["access_control"]
    result = await tool.run_access_control(session_id=session_id, target=target, test_type=test_type)
    return result


@mcp.tool()
async def test_api_security(
    session_id: str,
    target: str,
    test_type: str = "mass_assignment",
) -> dict:
    """Run API security tests. Types: mass_assignment, api_versioning, graphql_introspection."""
    tool = _ctx.tools["api_security"]
    result = await tool.run_api_security(session_id=session_id, target=target, test_type=test_type)
    return result


@mcp.tool()
async def test_misconfig(
    session_id: str,
    target: str,
    test_type: str = "cors",
) -> dict:
    """Run security misconfiguration tests. Types: cors, verbose_errors, debug_endpoints, security_headers."""
    tool = _ctx.tools["misconfig"]
    result = await tool.run_misconfig(session_id=session_id, target=target, test_type=test_type)
    return result


@mcp.tool()
async def test_rate_limit(
    session_id: str,
    target: str,
    test_type: str = "login",
) -> dict:
    """Run rate limiting tests. Types: login, api, bypass_headers."""
    tool = _ctx.tools["rate_limit"]
    result = await tool.run_rate_limit(session_id=session_id, target=target, test_type=test_type)
    return result


@mcp.tool()
async def test_sensitive_data(
    session_id: str,
    target: str,
    test_type: str = "js_secrets",
) -> dict:
    """Run sensitive data exposure tests. Types: js_secrets, api_overexposure, http_https, git_backup."""
    tool = _ctx.tools["sensitive_data"]
    result = await tool.run_sensitive_data(session_id=session_id, target=target, test_type=test_type)
    return result


@mcp.tool()
async def test_business_logic(
    session_id: str,
    target: str,
    test_type: str = "negative_values",
) -> dict:
    """Run business logic flaw tests. Types: negative_values, coupon_abuse."""
    tool = _ctx.tools["business_logic"]
    result = await tool.run_business_logic(session_id=session_id, target=target, test_type=test_type)
    return result


@mcp.tool()
async def generate_poc(
    session_id: str,
    finding_id: str,
) -> dict:
    """Generate proof of concept for a finding."""
    tool = _ctx.tools["poc"]
    result = await tool.run_poc(session_id=session_id, finding_id=finding_id)
    return result


@mcp.tool()
async def execute_command(
    session_id: str,
    command: str,
    timeout: int = 300,
) -> dict:
    """Execute a custom command with safety validation."""
    tool = _ctx.tools["exec"]
    result = await tool.run_command(session_id=session_id, command=command, timeout=timeout)
    return result


@mcp.tool()
async def analyze_findings(
    session_id: str,
) -> dict:
    """Analyze and summarize findings."""
    tool = _ctx.tools["analyze"]
    result = await tool.run_analyze(session_id=session_id)
    return result


@mcp.tool()
async def generate_report(
    session_id: str,
    format: str = "markdown",
) -> dict:
    """Generate penetration test report."""
    tool = _ctx.tools["report"]
    report_path = await tool.generate_report(session_id=session_id, format=format)
    return {"report_path": report_path, "format": format}


@mcp.tool()
async def run_autonomous_scan_tool(
    session_id: str,
    max_phases: int = 20,
    stop_on_critical: bool = True,
    generate_report: bool = True,
    provider_override: str | None = None,
) -> dict:
    """
    Run fully autonomous penetration test.
    The AI planner decides what to test, executes tools, and generates a report.
    """
    return await run_autonomous_scan(
        session_id=session_id,
        max_phases=max_phases,
        stop_on_critical=stop_on_critical,
        generate_report=generate_report,
        provider_override=provider_override,
    )


@mcp.tool()
async def run_plugin(
    session_id: str,
    plugin_name: str,
    target: str,
    args: dict[str, Any] | None = None,
) -> dict:
    """Run a loaded plugin."""
    plugin = _ctx.plugin_loader.get(plugin_name)
    if not plugin:
        return {"error": f"Plugin '{plugin_name}' not found", "available": _ctx.plugin_loader.list_plugins()}

    result = await plugin.run(
        session_id=session_id,
        target=target,
        args=args or {},
        process_controller=_ctx.process_controller,
        safety_policy=_ctx.safety_policy,
        session_manager=_ctx.session_manager,
        fallback_engine=getattr(_ctx, "fallback_engine", None),
        sudo_handler=getattr(_ctx, "sudo_handler", None),
    )

    return {
        "success": result.success,
        "findings": [f.model_dump() for f in result.findings],
        "duration_ms": result.duration_ms,
        "error": result.error,
    }


@mcp.tool()
async def list_plugins() -> dict:
    """List all loaded plugins."""
    return {"plugins": _ctx.plugin_loader.list_plugins()}

@mcp.tool()
async def list_all_tools() -> dict:
    """List all available tools, plugins, and their metadata."""
    
    # Built-in tools from _ctx.tools (each is a BaseTool instance)
    built_in_tools = []
    for name, tool_instance in _ctx.tools.items():
        built_in_tools.append({
            "name": name,
            "type": "built_in",
            "description": getattr(tool_instance, 'description', 'No description'),
            "class": tool_instance.__class__.__name__,
        })
    
    # Plugins from _ctx.plugin_loader
    plugins = _ctx.plugin_loader.list_plugins()
    
    # Also include the high-level autonomous scan capability
    capabilities = [
        {"name": "run_autonomous_scan", "type": "orchestrator", "description": "Full autonomous pentest with AI planner"},
        {"name": "initialize_session", "type": "session", "description": "Create new pentest session"},
        {"name": "get_session_status", "type": "session", "description": "Check session status and findings"},
        {"name": "emergency_stop", "type": "session", "description": "Emergency stop all processes"},
    ]
    
    return {
        "built_in_tools": built_in_tools,
        "plugins": plugins,
        "session_tools": capabilities,
        "total_count": len(built_in_tools) + len(plugins) + len(capabilities)
    }


@mcp.tool()
async def get_session_status(session_id: str) -> dict:
    """Get session status and findings."""
    session = await _ctx.session_manager.get_session(session_id)
    findings = await _ctx.session_manager.get_findings(session_id)
    ai_decisions = await _ctx.session_manager.get_ai_decisions(session_id)

    if not session:
        return {"error": f"Session {session_id} not found"}

    return {
        "session": {
            "session_id": session.session_id,
            "target": session.target,
            "test_type": session.test_type,
            "status": session.status,
            "findings_count": session.findings_count,
            "created_at": session.created_at,
        },
        "findings": [f.model_dump() for f in findings],
        "ai_decisions": ai_decisions,
    }


@mcp.tool()
async def emergency_stop(session_id: str) -> dict:
    """Emergency stop all processes for a session."""
    loop = ExecutionLoop(_ctx.tools, None, _ctx.session_manager, _ctx.config)
    await loop.emergency_stop(session_id)
    await _ctx.session_manager.update_session_status(session_id, "stopped")
    _ctx.audit_logger.log_session_event(session_id, "emergency_stop")
    return {"status": "stopped", "session_id": session_id}


# ─── MAIN ────────────────────────────────────────────────────────────────────
async def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--transport", choices=["stdio", "sse", "streamable-http"], default=None)
    parser.add_argument("--web-port", type=int, default=None, help="Web UI port (default: from config)")
    parser.add_argument("--no-web", action="store_true", help="Disable web UI")
    args, _ = parser.parse_known_args()
    
    await initialize()
    
    transport = args.transport or os.environ.get("MCP_TRANSPORT") or _ctx.config.server.transport
    web_enabled = _ctx.config.server.web_enabled and not args.no_web
    web_port = args.web_port or _ctx.config.server.web_port

    tasks = []

    if transport == "stdio":
        if web_enabled:
            tasks.append(asyncio.create_task(_start_web_server(web_port)))
            logger.info(f"Web UI available at http://localhost:{web_port}")
        logger.info("Starting MCP server with stdio transport")
        await mcp.run_stdio_async()
    
    elif transport in ("streamable-http", "sse"):
        if transport == "sse":
            logger.warning("Transport 'sse' requested — using 'streamable-http' (same protocol)")

        mcp_port = _ctx.config.server.sse_port
        logger.info(f"Starting MCP Streamable HTTP server on port {mcp_port}")

        import uvicorn

        app = mcp.streamable_http_app()
        mcp_config = uvicorn.Config(
            app,
            host="0.0.0.0",
            port=mcp_port,
            log_level="info"
        )
        mcp_server = uvicorn.Server(mcp_config)

        if web_enabled:
            tasks.append(asyncio.create_task(_start_web_server(web_port)))
            logger.info(f"Web UI available at http://localhost:{web_port}")

        if tasks:
            tasks.append(asyncio.create_task(mcp_server.serve()))
            await asyncio.gather(*tasks)
        else:
            await mcp_server.serve()

    else:
        raise ValueError(f"Unknown transport: {transport}")


if __name__ == "__main__":
    asyncio.run(main())
