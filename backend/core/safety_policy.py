"""Command validation, tier system, denylist, and scope checking."""
import re
import ipaddress
import logging
from typing import Dict, List, Optional, Any
from dataclasses import dataclass

logger = logging.getLogger(__name__)

GLOBAL_DENYLIST = [
    r"rm\s+-rf\s+/",
    r"mkfs\.",
    r"dd\s+if=.*of=/dev/",
    r":\(\)\{\s*:\|:\&\s*\};:",
    r"\bsu\s+-\s*root\b",
    r"\bsudo\s+.*rm\s+-rf",
    r"\bshutdown\b",
    r"\breboot\b",
    r"\bhalt\b",
    r"\binit\s+0\b",
    r"\bpoweroff\b",
    r"curl\s+.*\|\s*(ba)?sh",
    r"wget\s+.*\|\s*(ba)?sh",
    r"nc\s+.*-e\s+/bin/(ba)?sh",
    r"bash\s+-i\s+>&\s+/dev/tcp",
    r"python[23]?\s+-c\s+.*socket.*connect",
    r"perl\s+-e\s+.*socket",
    r"ruby\s+-rsocket\s+-e",
    r"\$\([^)]*\)",
    r"`[^`]+`",
    r"/etc/shadow",
    r"/etc/passwd",
    r"\bcrontab\b",
    r"\bchmod\s+[0-7]*77[0-7]*\b",
    r"\bchown\b",
]

SHELL_INJECTION_PATTERNS = [
    re.compile(r"\$\([^)]*\)"),
    re.compile(r"`[^`]+`"),
    re.compile(r"\b(eval|exec)\b"),
    re.compile(r"/etc/(passwd|shadow|hosts)\b"),
    re.compile(r"\bcrontab\b"),
    re.compile(r"\bchmod\s+[0-7]*77[0-7]*\b"),
    re.compile(r"\bchown\b"),
]

ALLOWED_PIPE_TOOLS = {
    "grep", "awk", "sed", "sort", "uniq", "head", "tail",
    "cut", "tr", "wc", "tee", "jq", "xargs",
}

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
        """Check if command targets are within scope using proper domain/IP matching."""
        targets = re.findall(
            r"(?:https?://|@)?([a-zA-Z0-9][-a-zA-Z0-9]*\.[a-zA-Z0-9][-a-zA-Z0-9.]*|\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})",
            command,
        )
        if not targets:
            return True

        for target in targets:
            if self._target_matches_scope(target, scope):
                continue
            return False
        return True

    def _target_matches_scope(self, target: str, scope: List[str]) -> bool:
        """Check if a single target matches any scope item with proper domain/IP semantics."""
        target_is_ip = self._is_ip_address(target)

        for scope_item in scope:
            if "/" in scope_item and target_is_ip:
                if self._ip_in_cidr_scope(target, scope_item):
                    return True
                continue

            scope_is_ip = self._is_ip_address(scope_item)

            if target_is_ip and scope_is_ip:
                if self._ip_in_scope(target, scope_item):
                    return True
            elif target_is_ip or scope_is_ip:
                continue
            else:
                if self._domain_in_scope(target, scope_item):
                    return True

        return False

    @staticmethod
    def _is_ip_address(value: str) -> bool:
        try:
            ipaddress.ip_address(value)
            return True
        except ValueError:
            return False

    @staticmethod
    def _ip_in_scope(target_ip: str, scope_ip: str) -> bool:
        try:
            t = ipaddress.ip_address(target_ip)
            s = ipaddress.ip_address(scope_ip)
            if isinstance(t, type(s)):
                return t == s
        except ValueError:
            pass
        return target_ip == scope_ip

    @staticmethod
    def _ip_in_cidr_scope(target_ip: str, cidr: str) -> bool:
        try:
            network = ipaddress.ip_network(cidr, strict=False)
            return ipaddress.ip_address(target_ip) in network
        except ValueError:
            return False

    @staticmethod
    def _domain_in_scope(target: str, scope_item: str) -> bool:
        target_lower = target.lower().rstrip(".")
        scope_lower = scope_item.lower().rstrip(".")
        if target_lower == scope_lower:
            return True
        if target_lower.endswith("." + scope_lower):
            return True
        if scope_lower.startswith("*."):
            wildcard_base = scope_lower[2:]
            if target_lower == wildcard_base or target_lower.endswith("." + wildcard_base):
                return True
        return False

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
        """Sanitize command to prevent injection while preserving legitimate tool usage."""
        for pattern in SHELL_INJECTION_PATTERNS:
            if pattern.search(command):
                logger.warning(f"Shell injection pattern detected and blocked: {pattern.pattern}")
                return ""

        sanitized = self._remove_shell_chaining(command)
        sanitized = self._remove_redirections(sanitized)
        return sanitized.strip()

    def _remove_shell_chaining(self, command: str) -> str:
        """Remove dangerous shell chaining operators while preserving safe pipes."""
        result = command
        result = re.sub(r'\s*;\s*', ' ', result)
        result = re.sub(r'\s*&&\s*', ' ', result)
        result = re.sub(r'\s*\|\|\s*', ' ', result)

        if '|' in result:
            parts = result.split('|')
            safe_parts = []
            for part in parts:
                stripped = part.strip()
                if not stripped:
                    continue
                tool_name = self._extract_tool_name(stripped)
                if tool_name in ALLOWED_PIPE_TOOLS:
                    safe_parts.append(stripped)
                else:
                    logger.warning(f"Pipe to unapproved tool blocked: {tool_name}")
            if safe_parts and len(safe_parts) == len(parts):
                result = ' | '.join(safe_parts)
            elif safe_parts:
                result = safe_parts[0]
            else:
                result = parts[0].strip() if parts else command

        return result

    @staticmethod
    def _remove_redirections(command: str) -> str:
        """Remove file redirections that could write to sensitive locations."""
        result = re.sub(r'\s*>\s*/dev/', ' ', command)
        result = re.sub(r'\s*>>\s*/dev/', ' ', result)
        result = re.sub(r'\s*<\s*/etc/', ' ', result)
        return result

    def get_tier_info(self, tier: str) -> Dict[str, Any]:
        """Get information about a tier."""
        return TIER_CONFIG.get(tier, {})
