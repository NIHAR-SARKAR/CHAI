"""
Burp Suite Professional API plugin.
Requires Burp Pro with API enabled.
"""
from ast import Import
import json
import logging
import requests
from plugins.plugin_base import PentestPlugin, PluginMetadata, PluginResult
from models.session import Finding
logger = logging.getLogger(__name__)


class BurpApiPlugin(PentestPlugin):

    @property
    def metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="burp_api",
            display_name="Burp Suite Pro API",
            version="2024.1",
            description="Interact with Burp Suite Professional via REST API",
            tier="tier2",
            requires_binary="curl",  # Used for API calls
            requires_network=True,
            tags=["web", "scan", "burp", "api"],
        )

    async def run(self, session_id, target, args, process_controller, safety_policy, session_manager) -> PluginResult:
        import time
        api_base = args.get("api_base", "http://localhost:3004")
        api_key = args.get("api_key", "")
        action = args.get("action", "scan")

        if action == "scan":
            payload = json.dumps({"urls": [target]})
            command = f"curl -s -X POST {api_base}/v0.1/scan -H 'Content-Type: application/json' -d '{payload}'"
        elif action == "results":
            command = f"curl -s {api_base}/v0.1/scan/issues"
        else:
            return PluginResult(
                success=False,
                findings=[],
                raw_output="",
                error=f"Unknown action: {action}",
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
            timeout=args.get("timeout", 120),
            sandbox_level="firejail",
            max_ram_mb=128,
        )
        duration_ms = int((time.monotonic() - start) * 1000)

        findings = []
        try:
            import json
            data = json.loads(result.get("stdout", "{}"))
            if isinstance(data, list):
                for issue in data:
                    severity = issue.get("severity", "info").lower()
                    cvss = {"high": 7.5, "medium": 5.3, "low": 3.7, "info": 0}.get(severity, 0)
                    findings.append(Finding(
                        session_id=session_id,
                        attack_type=issue.get("issue_type", "unknown"),
                        confidence=0.9,
                        endpoint=issue.get("url", target),
                        evidence=issue.get("issue_detail", ""),
                        status="confirmed",
                        cvss_score=cvss,
                        severity=severity,
                    ))
        except (json.JSONDecodeError, Exception) as e:
            logger.debug(f"Failed to parse Burp API response: {e}")

        return PluginResult(
            success=result.get("returncode") == 0,
            findings=findings,
            raw_output=result.get("stdout", ""),
            duration_ms=duration_ms,
        )
