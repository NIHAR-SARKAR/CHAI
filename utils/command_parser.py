"""Command parsing utilities."""
import re
import shlex
from typing import List, Dict, Any, Optional, Tuple


class CommandParser:
    """Parse and analyze shell commands."""

    @staticmethod
    def parse(command: str) -> Dict[str, Any]:
        """Parse a command string into structured components."""
        try:
            tokens = shlex.split(command)
        except ValueError:
            # Fallback for malformed commands
            tokens = command.split()

        if not tokens:
            return {"tool": "", "args": [], "flags": {}, "raw": command}

        tool = tokens[0]
        args = []
        flags = {}
        i = 1

        while i < len(tokens):
            token = tokens[i]
            if token.startswith("--"):
                # Long flag
                if "=" in token:
                    key, value = token[2:].split("=", 1)
                    flags[key] = value
                elif i + 1 < len(tokens) and not tokens[i + 1].startswith("-"):
                    flags[token[2:]] = tokens[i + 1]
                    i += 1
                else:
                    flags[token[2:]] = True
            elif token.startswith("-") and len(token) > 1:
                # Short flag(s)
                if len(token) == 2:
                    flag_char = token[1]
                    if i + 1 < len(tokens) and not tokens[i + 1].startswith("-"):
                        flags[flag_char] = tokens[i + 1]
                        i += 1
                    else:
                        flags[flag_char] = True
                else:
                    # Combined short flags like -abc
                    for char in token[1:]:
                        flags[char] = True
            else:
                args.append(token)
            i += 1

        return {
            "tool": tool,
            "args": args,
            "flags": flags,
            "raw": command,
        }

    @staticmethod
    def extract_targets(command: str) -> List[str]:
        """Extract target URLs/IPs from a command."""
        # URL pattern
        url_pattern = r"https?://[^\s"']+"
        urls = re.findall(url_pattern, command)

        # IP pattern
        ip_pattern = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
        ips = re.findall(ip_pattern, command)

        # Domain pattern
        domain_pattern = r"\b[a-zA-Z0-9][-a-zA-Z0-9]*\.[a-zA-Z]{2,}\b"
        domains = re.findall(domain_pattern, command)

        return list(set(urls + ips + domains))

    @staticmethod
    def is_safe(command: str, allowed_tools: List[str]) -> Tuple[bool, str]:
        """Check if a command only uses allowed tools."""
        parsed = CommandParser.parse(command)
        tool = parsed["tool"].split("/")[-1]  # Handle absolute paths

        if tool not in allowed_tools:
            return False, f"Tool '{tool}' not in allowed list"

        return True, "OK"
