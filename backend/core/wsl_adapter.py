"""WSL (Windows Subsystem for Linux) adapter for cross-platform execution.

Provides:
- WSL detection and availability checks
- Windows-to-WSL path conversion
- Command wrapping for WSL execution with optional user/distro targeting
- Environment variable and working-directory translation
"""
import asyncio
import logging
import os
import re
import shlex
import shutil
import sys
from pathlib import Path
from typing import Dict, Optional, Any

logger = logging.getLogger(__name__)


class WSLConfig:
    """WSL configuration container (mirrors dataclass style)."""

    def __init__(
        self,
        enabled: bool = False,
        distro_name: str = "",
        username: str = "",
        password: str = "",
        ssh_key_path: str = "",
        os_details: str = "",
        use_ssh: bool = False,
        auto_install_missing: bool = False,
        mount_path_prefix: str = "/mnt",
        default_shell: str = "bash",
    ):
        self.enabled = enabled
        self.distro_name = distro_name
        self.username = username
        self.password = password
        self.ssh_key_path = ssh_key_path
        self.os_details = os_details
        self.use_ssh = use_ssh
        self.auto_install_missing = auto_install_missing
        self.mount_path_prefix = mount_path_prefix
        self.default_shell = default_shell


class WSLAdapter:
    """
    Adapts Linux-oriented pentest commands for execution inside WSL on Windows.

    Responsibilities:
    1. Detect whether the host is Windows and whether WSL is installed.
    2. Convert Windows-style paths (C:\foo) to WSL paths (/mnt/c/foo).
    3. Wrap raw shell commands so they execute inside the chosen WSL distro.
    4. Translate environment variables and working directories.
    5. Support optional SSH-based execution for remote WSL instances.
    """

    def __init__(self, wsl_config: Optional[WSLConfig] = None):
        self._cfg = wsl_config or WSLConfig()
        self._wsl_exe = self._find_wsl_binary()

    # ------------------------------------------------------------------
    # Detection helpers
    # ------------------------------------------------------------------

    @staticmethod
    def is_windows() -> bool:
        return sys.platform == "win32"

    @staticmethod
    def is_wsl_available() -> bool:
        """Check if the `wsl` (or `wsl.exe`) binary is reachable."""
        return bool(shutil.which("wsl") or shutil.which("wsl.exe"))

    @staticmethod
    def is_inside_wsl() -> bool:
        """Detect if we are *already* running inside a WSL environment."""
        try:
            with open("/proc/version", "r", encoding="utf-8") as f:
                return "microsoft" in f.read().lower()
        except (OSError, IOError):
            return False

    def is_active(self) -> bool:
        """
        Return True when CHAI should route commands through WSL.
        Active only when:
        - WSL config says enabled
        - Host is Windows (not already inside WSL)
        - WSL binary is available on PATH
        """
        if not self._cfg.enabled:
            return False
        if self.is_inside_wsl():
            return False
        if not self.is_windows():
            return False
        return self.is_wsl_available()

    # ------------------------------------------------------------------
    # Path conversion
    # ------------------------------------------------------------------

    def to_wsl_path(self, windows_path: str) -> str:
        """Convert a Windows absolute path to a WSL /mnt path."""
        if not windows_path:
            return windows_path
        # Already WSL-style?
        if windows_path.startswith("/") and not windows_path.startswith("//"):
            return windows_path
        # UNC paths — unsupported, return as-is with a warning
        if windows_path.startswith("\\\\"):
            logger.warning(f"UNC path not supported for WSL translation: {windows_path}")
            return windows_path
        # Letter-drive paths: C:\Users\foo → /mnt/c/Users/foo
        match = re.match(r"^([A-Za-z]):([\\/].*)$", windows_path)
        if match:
            drive = match.group(1).lower()
            rest = match.group(2).replace("\\", "/")
            return f"{self._cfg.mount_path_prefix}/{drive}{rest}"
        # Relative paths with backslashes
        if "\\" in windows_path:
            return windows_path.replace("\\", "/")
        return windows_path

    def translate_command_paths(self, command: str) -> str:
        r"""Replace all Windows absolute paths inside a command string with WSL equivalents.

        IMPORTANT: Must NOT touch URLs (https://, http://, ftp://, etc.).
        Only converts true Windows drive-letter paths like C:\Users\foo.
        """
        # Use negative lookbehind to ensure the drive letter is NOT preceded
        # by another letter — this prevents matching "s:" inside "https://".
        # Also require a path separator after the colon (\ or /).
        pattern = re.compile(r"(?<![a-zA-Z])([A-Za-z]):([\\/][^\s\"']*)")

        def replacer(m):
            drive = m.group(1).lower()
            rest = m.group(2).replace("\\", "/")
            return f"{self._cfg.mount_path_prefix}/{drive}{rest}"

        translated = pattern.sub(replacer, command)
        if translated != command:
            logger.info(f"[WSL] Path translation: '{command[:120]}' -> '{translated[:120]}'")
        return translated

    # ------------------------------------------------------------------
    # Command wrapping
    # ------------------------------------------------------------------

    def wrap_command(
        self,
        command: str,
        working_dir: Optional[str] = None,
        env_vars: Optional[Dict[str, str]] = None,
    ) -> str:
        """
        Wrap a raw Linux shell command so it runs inside WSL.

        Steps:
        1. Translate any Windows paths in the command string.
        2. Translate working_dir if provided.
        3. Prepend `cd <dir> &&` if working_dir is set.
        4. Export env_vars if provided.
        5. Build the final `wsl.exe -d <distro> -u <user> <shell> -c '<cmd>'` string.
        """
        translated_cmd = self.translate_command_paths(command)

        # Build inner shell script
        inner_parts = []

        # Working directory
        if working_dir:
            wsl_cwd = self.to_wsl_path(working_dir)
            inner_parts.append(f"cd '{wsl_cwd}'")

        # Environment variables
        if env_vars:
            for key, value in env_vars.items():
                # Translate any paths in env values too
                translated_val = self.translate_command_paths(value)
                inner_parts.append(f'export {key}="{translated_val}"')

        # The actual command
        inner_parts.append(translated_cmd)

        inner_script = " && ".join(inner_parts)

        # Build wsl.exe invocation
        parts = [self._wsl_exe]
        if self._cfg.distro_name:
            parts.extend(["-d", self._cfg.distro_name])
        if self._cfg.username:
            parts.extend(["-u", self._cfg.username])

        shell = self._cfg.default_shell or "bash"
        parts.extend([shell, "-c", inner_script])

        wrapped = " ".join(f'"{p}"' if " " in p else p for p in parts)
        logger.info(f"[WSL] Wrapped command: {wrapped[:250]}...")
        return wrapped

    # ------------------------------------------------------------------
    # Public helpers used by ProcessController
    # ------------------------------------------------------------------

    async def run(
        self,
        command: str,
        session_id: str,
        timeout: int,
        working_dir: Optional[str] = None,
        env_vars: Optional[Dict[str, str]] = None,
    ) -> Dict[str, Any]:
        """
        Execute a command inside WSL using asyncio subprocess.
        Returns the same shape as ProcessController.run().
        """
        import time

        # Wrap with the Linux timeout utility so the inner WSL process self-terminates.
        # Killing the outer wsl.exe Windows process does not always terminate the
        # Linux child, which can cause asyncio.wait_for to hang past its deadline.
        effective_command = command
        if timeout and timeout > 0:
            effective_command = f"timeout {timeout} bash -c {shlex.quote(command)}"

        wrapped = self.wrap_command(effective_command, working_dir, env_vars)
        logger.info(f"[{session_id}] WSL Executing: {wrapped[:200]}...")

        start_time = time.monotonic()
        try:
            # On Windows we use the default event loop policy which supports subprocess
            process = await asyncio.create_subprocess_shell(
                wrapped,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            pid = process.pid
            try:
                stdout, stderr = await asyncio.wait_for(
                    process.communicate(),
                    timeout=timeout,
                )
                duration_ms = int((time.monotonic() - start_time) * 1000)
                return {
                    "stdout": stdout.decode("utf-8", errors="replace"),
                    "stderr": stderr.decode("utf-8", errors="replace"),
                    "returncode": process.returncode,
                    "duration_ms": duration_ms,
                    "pid": pid,
                    "command": command,
                    "sandbox_level": "wsl",
                }
            except asyncio.TimeoutError:
                try:
                    process.kill()
                    await process.wait()
                except (ProcessLookupError, OSError):
                    pass
                duration_ms = int((time.monotonic() - start_time) * 1000)
                logger.warning(f"[{session_id}] WSL command timed out after {timeout}s")
                return {
                    "stdout": "",
                    "stderr": f"WSL command timed out after {timeout} seconds",
                    "returncode": -1,
                    "duration_ms": duration_ms,
                    "pid": pid,
                    "command": command,
                    "sandbox_level": "wsl",
                    "timeout": True,
                }

        except Exception as e:
            duration_ms = int((time.monotonic() - start_time) * 1000)
            logger.error(f"[{session_id}] WSL command execution failed: {e}")
            return {
                "stdout": "",
                "stderr": str(e),
                "returncode": -1,
                "duration_ms": duration_ms,
                "pid": -1,
                "command": command,
                "sandbox_level": "wsl",
                "error": str(e),
            }

    def _find_wsl_binary(self) -> str:
        """Locate the best WSL executable on this system."""
        candidates = ["wsl.exe", "wsl"]
        for cand in candidates:
            path = shutil.which(cand)
            if path:
                return path
        return "wsl.exe"  # fallback

    async def install_package(self, package_name: str, sudo_handler=None) -> bool:
        """Attempt to install a missing package inside WSL via the default package manager.
        Uses root elevation if available to avoid interactive sudo password prompts."""
        if not self.is_active():
            return False

        install_cmd = (
            f"apt-get update && apt-get install -y {package_name} || "
            f"apk add {package_name} || "
            f"yum install -y {package_name} || "
            f"pacman -S --noconfirm {package_name}"
        )

        # If we have a sudo_handler, run as root to avoid password prompts
        if sudo_handler:
            logger.info(f"[WSL] Installing '{package_name}' as root via sudo_handler")
            result = await sudo_handler.run_elevated_wsl(
                command=install_cmd,
                session_id="wsl-install",
                timeout=120,
                distro_name=self._cfg.distro_name,
            )
        else:
            # Fallback: try non-interactive sudo (fails fast if password needed)
            cmd = f"sudo -n {install_cmd}"
            result = await self.run(cmd, session_id="wsl-install", timeout=120)

        success = result.get("returncode") == 0
        if success:
            logger.info(f"[WSL] Package '{package_name}' installed successfully")
        else:
            logger.warning(f"[WSL] Package install failed for '{package_name}': {result.get('stderr', '')[:200]}")
        return success

    async def check_tool_available(self, tool_name: str) -> bool:
        """Check whether a Linux binary exists inside the WSL environment."""
        if not self.is_active():
            return False
        result = await self.run(
            f"which {tool_name}",
            session_id="wsl-check",
            timeout=10,
        )
        return result["returncode"] == 0 and result["stdout"].strip()
