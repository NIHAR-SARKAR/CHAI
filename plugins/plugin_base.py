"""
Base class for all pentest tool plugins.
To add a new tool: subclass PentestPlugin, implement run() and metadata.
Drop the file into plugins/external/ or plugins/bundled/.
No changes to core application required.
"""
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any
from models.session import Finding


@dataclass
class PluginMetadata:
    name: str                    # e.g. "feroxbuster"
    display_name: str            # e.g. "Feroxbuster Directory Bruteforcer"
    version: str                 # e.g. "2.10.0"
    description: str
    tier: str                    # "tier1" | "tier2" | "tier3"
    requires_binary: str         # e.g. "feroxbuster"
    requires_network: bool = True
    tags: list[str] = field(default_factory=list)   # ["web", "recon", "bruteforce"]


@dataclass
class PluginResult:
    success: bool
    findings: list[Finding]
    raw_output: str
    error: str | None = None
    duration_ms: int = 0


class PentestPlugin(ABC):
    """
    All plugins inherit this. The plugin_loader discovers subclasses
    automatically — no registration needed.
    """

    @property
    @abstractmethod
    def metadata(self) -> PluginMetadata:
        """Return static metadata about this plugin."""
        ...

    @abstractmethod
    async def run(
        self,
        session_id: str,
        target: str,
        args: dict[str, Any],
        process_controller,      # injected by loader
        safety_policy,           # injected by loader
        session_manager,         # injected by loader
    ) -> PluginResult:
        """
        Execute the tool. Must:
        1. Validate command through safety_policy before execution
        2. Execute via process_controller (never subprocess directly)
        3. Parse output and return PluginResult with Finding objects
        """
        ...

    async def is_available(self) -> bool:
        """Check if the required binary exists on the system."""
        import shutil
        return shutil.which(self.metadata.requires_binary) is not None
