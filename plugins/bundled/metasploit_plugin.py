"""
Metasploit Framework plugin.
Tier 3 — disabled by default due to high risk.
"""
import logging
from plugins.plugin_base import PentestPlugin, PluginMetadata, PluginResult
from models.session import Finding

logger = logging.getLogger(__name__)


class MetasploitPlugin(PentestPlugin):

    @property
    def metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="metasploit",
            display_name="Metasploit Framework",
            version="6.4.0",
            description="Advanced penetration testing framework with exploit modules",
            tier="tier3",
            requires_binary="msfconsole",
            requires_network=True,
            tags=["exploit", "post-exploit", "framework", "tier3"],
        )

    async def run(self, session_id, target, args, process_controller, safety_policy, session_manager) -> PluginResult:
        import time
        resource_script = args.get("resource_script", "")
        module = args.get("module", "")
        options = args.get("options", {})

        if resource_script:
            command = f"msfconsole -q -r {resource_script}"
        elif module:
            opts_str = " ".join([f"{k}={v}" for k, v in options.items()])
            command = f"msfconsole -q -x 'use {module}; set {opts_str}; run; exit'"
        else:
            return PluginResult(
                success=False,
                findings=[],
                raw_output="",
                error="Either resource_script or module must be specified",
            )

        # Validate through safety policy
        policy_result = await safety_policy.validate(command, session_id)
        if not policy_result["approved"]:
            return PluginResult(
                success=False, findings=[], raw_output="",
                error=f"Blocked by safety policy: {policy_result['reason']}"
            )

        start = time.monotonic()
        result = await process_controller.run(
            command=policy_result.get("modified_command", command),
            session_id=session_id,
            timeout=args.get("timeout", 600),
            sandbox_level="firejail",
            max_ram_mb=512,
        )
        duration_ms = int((time.monotonic() - start) * 1000)

        # Parse metasploit output for sessions/findings
        findings = []
        output = result.get("stdout", "")

        if "Meterpreter session" in output or "Session " in output:
            findings.append(Finding(
                session_id=session_id,
                attack_type="exploit_success",
                confidence=1.0,
                endpoint=target,
                evidence="Metasploit session opened successfully",
                status="confirmed",
                cvss_score=9.8,
                severity="critical",
            ))

        return PluginResult(
            success=result.get("returncode") == 0,
            findings=findings,
            raw_output=output,
            duration_ms=duration_ms,
        )
