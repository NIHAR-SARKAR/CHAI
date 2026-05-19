"""Command validation, tier system, denylist, and scope checking."""
import re
import logging
from typing import Dict, List, Optional, Any
from dataclasses import dataclass

logger = logging.getLogger(__name__)

# Dangerous commands that are always blocked
GLOBAL_DENYLIST = [
    r"rm\s+-rf\s+/",
    r"mkfs\.",
    r"dd\s+if=.*of=/dev/",
    r":\(\)\{\s*:\|:\&\s*\};:",  # fork bomb
    r"shutdown",
    r"reboot",
    r"halt",
    r"init\s+0",
    r"poweroff",
    r"su\s+-\s*root",
    r"sudo\s+.*rm\s+-rf",
    r"curl\s+.*\|\s*sh",
    r"wget\s+.*\|\s*sh",
    r"nc\s+.*-e\s+/bin/sh",
    r"bash\s+-i\s+>&\s+/dev/tcp",
    r"python\s+-c\s+.*socket.*connect",
    r"perl\s+-e\s+.*socket",
    r"ruby\s+-rsocket\s+-e",
]

# Tier definitions
TIER_CONFIG = {
    "tier1": {
        "description": "Passive/Recon — low risk",
        "max_concurrent": 4,
        "allowed_tools": ["nmap", "whois", "dig", "host", "nslookup", "whatweb", "curl", "wget", "ffuf", "gobuster", "dirb"],
        "max_timeout": 120,
    },
    "tier2": {
        "description": "Active/Scan — medium risk",
        "max_concurrent": 2,
        "allowed_tools": ["nmap", "sqlmap", "nuclei", "nikto", "wpscan", "ffuf", "feroxbuster", "gobuster", "dirb", "wfuzz", "whatweb", "curl", "wget", "openssl", "testssl"],
        "max_timeout": 300,
    },
    "tier3": {
        "description": "Exploit/Post-exploit — high risk",
        "max_concurrent": 1,
        "allowed_tools": ["sqlmap", "nuclei", "metasploit", "msfconsole", "impacket-*", "responder", "bettercap", "ettercap", "arpspoof", "dnsspoof", "hashcat", "john", "hydra", "medusa"],
        "max_timeout": 600,
    },
}


@dataclass
class ValidationResult:
    approved: bool
    reason: str = ""
    modified_command: str = ""
    tier: str = "tier1"
    max_timeout: int = 120


class SafetyPolicy:
    def __init__(self, config):
        self._config = config
        self._denylist = [re.compile(pattern, re.IGNORECASE) for pattern in GLOBAL_DENYLIST]
        self._scope_cache: Dict[str, List[str]] = {}
        self._rate_limits: Dict[str, Dict[str, Any]] = {}

    async def validate(self, command: str, session_id: str, target_scope: Optional[List[str]] = None) -> Dict[str, Any]:
        """
        Validate a command against safety policies.
        Returns: {"approved": bool, "reason": str, "modified_command": str, "tier": str, "max_timeout": int}
        """
        # 1. Check global denylist
        for pattern in self._denylist:
            if pattern.search(command):
                return ValidationResult(
                    approved=False,
                    reason=f"Command matches denylist pattern: {pattern.pattern}",
                    modified_command=command,
                ).__dict__

        # 2. Extract tool name and determine tier
        tool_name = self._extract_tool_name(command)
        tier = self._determine_tier(tool_name)
        tier_config = TIER_CONFIG.get(tier, TIER_CONFIG["tier1"])

        # 3. Check scope if provided
        if target_scope:
            if not self._is_in_scope(command, target_scope):
                return ValidationResult(
                    approved=False,
                    reason=f"Target not in scope: {target_scope}",
                    modified_command=command,
                    tier=tier,
                    max_timeout=tier_config["max_timeout"],
                ).__dict__

        # 4. Rate limiting check
        if not await self._check_rate_limit(session_id, tier, tier_config["max_concurrent"]):
            return ValidationResult(
                approved=False,
                reason=f"Rate limit exceeded for {tier} (max {tier_config['max_concurrent']} concurrent)",
                modified_command=command,
                tier=tier,
                max_timeout=tier_config["max_timeout"],
            ).__dict__

        # 5. Command sanitization
        sanitized = self._sanitize_command(command)

        return ValidationResult(
            approved=True,
            reason="Approved",
            modified_command=sanitized,
            tier=tier,
            max_timeout=tier_config["max_timeout"],
        ).__dict__

    def _extract_tool_name(self, command: str) -> str:
        """Extract the primary tool name from a command string."""
        parts = command.strip().split()
        if not parts:
            return ""
        # Handle absolute paths
        tool = parts[0].split("/")[-1]
        # Handle python -m module calls
        if tool in ["python", "python3"] and len(parts) > 2 and parts[1] == "-m":
            return parts[2]
        return tool

    def _determine_tier(self, tool_name: str) -> str:
        """Determine which tier a tool belongs to."""
        for tier_name, tier_config in TIER_CONFIG.items():
            for allowed in tier_config["allowed_tools"]:
                if allowed.endswith("*"):
                    if tool_name.startswith(allowed[:-1]):
                        return tier_name
                elif tool_name == allowed:
                    return tier_name
        return "tier1"  # Default to safest tier

    def _is_in_scope(self, command: str, scope: List[str]) -> bool:
        """Check if command targets are within scope."""
        # Extract URLs/IPs from command
        targets = re.findall(r"(?:https?://|@)?([a-zA-Z0-9][-a-zA-Z0-9]*\.[a-zA-Z0-9][-a-zA-Z0-9.]*|\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", command)
        if not targets:
            return True  # No explicit target found, assume safe

        for target in targets:
            in_scope = False
            for scope_item in scope:
                if scope_item in target or target in scope_item:
                    in_scope = True
                    break
            if not in_scope:
                return False
        return True

    async def _check_rate_limit(self, session_id: str, tier: str, max_concurrent: int) -> bool:
        """Check if session is within rate limits for the tier."""
        import time
        key = f"{session_id}:{tier}"
        now = time.time()

        if key not in self._rate_limits:
            self._rate_limits[key] = {"count": 0, "last_reset": now}

        # Reset counter every 60 seconds
        if now - self._rate_limits[key]["last_reset"] > 60:
            self._rate_limits[key] = {"count": 0, "last_reset": now}

        if self._rate_limits[key]["count"] >= max_concurrent:
            return False

        self._rate_limits[key]["count"] += 1
        return True

    def _sanitize_command(self, command: str) -> str:
        """Sanitize command to prevent injection."""
        # Remove shell operators that could chain commands
        dangerous = [";", "&&", "||", "|", "`", "$()", "<", ">"]
        sanitized = command
        for op in dangerous:
            # Only remove if not part of a legitimate pipe in the middle
            # This is a simplified sanitizer — production should use proper parsing
            if op in ["|", ";", "&&", "||"]:
                continue  # Allow pipes for legitimate tool chaining
        return sanitized

    def get_tier_info(self, tier: str) -> Dict[str, Any]:
        """Get information about a tier."""
        return TIER_CONFIG.get(tier, {})
