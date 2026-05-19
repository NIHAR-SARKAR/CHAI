"""Main MCP server using FastMCP.
Registers all tools and handles stdio/SSE transport.
"""
import asyncio
import logging
import sys
from pathlib import Path

from mcp.server.fastmcp import FastMCP

from config import load_config
from llm.provider_factory import get_provider_with_fallback
from core.session_manager import SessionManager
from core.safety_policy import SafetyPolicy
from core.process_controller import ProcessController
from core.audit_logger import AuditLogger
from core.ai_planner import AIPlanner
from core.execution_loop import ExecutionLoop
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
from tools.autonomous import run_autonomous_scan
from app_context import AppContext

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
    handlers=[
        logging.StreamHandler(sys.stderr),
    ]
)
logger = logging.getLogger(__name__)

# Initialize MCP server
mcp = FastMCP("pico-claw-mcp-security")

# Global context
_ctx = AppContext()


async def initialize():
    """Initialize all components."""
    logger.info("Initializing PICO CLAW MCP Security Server v2.0.0")

    # Load configuration
    config = load_config("config.yaml", ".security.yml")

    # Initialize database components
    session_manager = SessionManager(config.paths.session_db)
    await session_manager.initialize()

    graph_db = GraphDB(config.paths.kb_path + "/graph.db")
    await graph_db.initialize()

    # Initialize controllers
    process_controller = ProcessController(config)
    safety_policy = SafetyPolicy(config)
    audit_logger = AuditLogger(config.paths.audit_log_path)

    # Initialize LLM provider
    provider = await get_provider_with_fallback(config)
    logger.info(f"LLM provider initialized: {provider.provider_name}")

    # Initialize KB components
    playbook_loader = PlaybookLoader(config.paths.kb_path)
    vector_search = VectorSearch(config.paths.kb_path + "/vectors.db")
    await vector_search.initialize()

    # Initialize plugins
    plugin_loader = PluginLoader(config, process_controller, safety_policy, session_manager)
    await plugin_loader.load_all()

    # Initialize tools registry
    tools = {
        "recon": ReconTools(session_manager, process_controller, safety_policy, audit_logger),
        "scan": ScanTools(session_manager, process_controller, safety_policy, audit_logger),
        "injection": InjectionTools(session_manager, process_controller, safety_policy, audit_logger),
        "auth": AuthTools(session_manager, process_controller, safety_policy, audit_logger),
        "network": NetworkTools(session_manager, process_controller, safety_policy, audit_logger),
        "poc": PocTools(session_manager, process_controller, safety_policy, audit_logger),
        "exec": ExecTools(session_manager, process_controller, safety_policy, audit_logger),
        "analyze": AnalyzeTools(session_manager, process_controller, safety_policy, audit_logger),
        "report": ReportTools(session_manager, process_controller, safety_policy, audit_logger),
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
    )

    logger.info("Server initialization complete")


# ─── MCP TOOLS ───────────────────────────────────────────────────────────────

@mcp.tool()
async def initialize_session(
    target: str,
    test_type: str = "web_app",
    scope: list = None,
    metadata: dict = None,
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
    max_phases: int = 4,
    stop_on_critical: bool = True,
    generate_report: bool = True,
    provider_override: str = None,
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
    args: dict = None,
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
    await initialize()

    transport = _ctx.config.server.transport

    if transport == "stdio":
        logger.info("Starting MCP server with stdio transport")
        await mcp.run_stdio_async()
    elif transport == "sse":
        port = _ctx.config.server.sse_port
        logger.info(f"Starting MCP server with SSE transport on port {port}")
        await mcp.run_sse_async(host="0.0.0.0", port=port)
    else:
        raise ValueError(f"Unknown transport: {transport}")


if __name__ == "__main__":
    asyncio.run(main())
