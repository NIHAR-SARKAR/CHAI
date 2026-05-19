"""
Feroxbuster directory bruteforcer plugin.
Demonstrates the plugin pattern — copy this as a template for new plugins.
"""
import json
import logging
from plugins.plugin_base import PentestPlugin, PluginMetadata, PluginResult
from models.session import Finding

logger = logging.getLogger(__name__)


class FeroxbusterPlugin(PentestPlugin):

    @property
    def metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="feroxbuster",
            display_name="Feroxbuster Directory Bruteforcer",
            version="2.10.0",
            description="Fast, recursive content discovery tool written in Rust",
            tier="tier2",
            requires_binary="feroxbuster",
            requires_network=True,
            tags=["web", "recon", "bruteforce", "directory"],
        )

    async def run(self, session_id, target, args, process_controller, safety_policy, session_manager) -> PluginResult:
        import time
        wordlist = args.get("wordlist", "/usr/share/seclists/Discovery/Web-Content/common.txt")
        threads = args.get("threads", 10)
        depth = args.get("depth", 2)

        command = (
            f"feroxbuster -u {target} -w {wordlist} -t {threads} -d {depth} "
            f"--silent --json --no-state"
        )

        # ALWAYS validate through safety policy first
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
            timeout=args.get("timeout", 120),
            sandbox_level="firejail",
            max_ram_mb=200,
        )
        duration_ms = int((time.monotonic() - start) * 1000)

        findings = []
        for line in result.get("stdout", "").splitlines():
            try:
                entry = json.loads(line)
                if entry.get("status") in (200, 301, 302, 403):
                    findings.append(Finding(
                        session_id=session_id,
                        attack_type="directory_discovery",
                        confidence=0.9,
                        endpoint=entry.get("url", ""),
                        parameter=None,
                        evidence=f"HTTP {entry.get('status')} — {entry.get('url')}",
                        status="confirmed",
                        cvss_score=None,
                    ))
            except json.JSONDecodeError:
                pass

        return PluginResult(
            success=result.get("returncode") == 0,
            findings=findings,
            raw_output=result.get("stdout", ""),
            duration_ms=duration_ms,
        )
