"""Sudo / elevation handler for cross-platform privilege management.

Handles the password-interactive sudo problem by:
1. Detecting password prompts in command output
2. Running commands as root in WSL (bypasses sudo)
3. Auto-configuring passwordless sudo when possible
4. Injecting passwords via stdin for native Linux when configured
"""
import asyncio
import logging
import re
import sys
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)

SUDO_PASSWORD_PATTERNS = [
    re.compile(r"\[sudo\] password for", re.I),
    re.compile(r"password:", re.I),
    re.compile(r"sudo:\s*a password is required", re.I),
    re.compile(r"sudo:\s*3 incorrect password attempts", re.I),
    re.compile(r"sorry, try again", re.I),
    re.compile(r"authentication failure", re.I),
    re.compile(r"permission denied.*sudo", re.I),
]


class SudoHandler:
    """
    Handles privilege elevation across platforms.

    Strategy:
    - WSL: Use 'wsl -u root' to run as root directly (no sudo needed)
    - Native Linux: Try 'sudo -n' first (non-interactive, fails fast)
      If password is configured, retry with 'echo pass | sudo -S'
    """

    def __init__(self, wsl_adapter=None, password: str = ""):
        self._wsl = wsl_adapter
        self._password = password
        self._wsl_sudoers_configured = False

    # ── Detection ──────────────────────────────────────────────────────────────

    @staticmethod
    def is_sudo_password_prompt(stderr: str, stdout: str = "") -> bool:
        """Check if output contains a sudo password prompt."""
        combined = f"{stderr}\n{stdout}"
        for pattern in SUDO_PASSWORD_PATTERNS:
            if pattern.search(combined):
                return True
        return False

    @staticmethod
    def needs_sudo(command: str) -> bool:
        """Heuristic: does this command likely need root privileges?"""
        cmd_lower = command.strip().lower()
        # Direct sudo usage
        if cmd_lower.startswith("sudo "):
            return True
        # Commands that commonly need root
        root_commands = [
            "apt-get install", "apt install", "yum install", "dnf install",
            "pacman -s", "apk add",
            "nmap -ss", "nmap -su", "nmap -sa",  # raw socket scans (lowercase)
            "masscan", "zmap",
            "iptables", "nft",
            "tcpdump", "wireshark",
        ]
        for rc in root_commands:
            if rc in cmd_lower:
                return True
        return False

    # ── WSL elevation ────────────────────────────────────────────────────────

    async def run_elevated_wsl(
        self,
        command: str,
        session_id: str,
        timeout: int,
        distro_name: str = "",
        working_dir: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Run a command as root inside WSL, completely bypassing sudo."""
        if not self._wsl:
            return {
                "stdout": "",
                "stderr": "WSL adapter not available for elevated execution",
                "returncode": -1,
                "error": "No WSL adapter",
            }

        wsl_exe = self._wsl._wsl_exe
        parts = [wsl_exe]
        if distro_name:
            parts.extend(["-d", distro_name])
        parts.extend(["-u", "root"])  # Run as root

        shell = self._wsl._cfg.default_shell or "bash"
        parts.extend([shell, "-c", command])
        wrapped = " ".join(f'"{p}"' if " " in p else p for p in parts)

        logger.info(f"[SUDO] Running as root in WSL: {wrapped[:200]}...")

        import time
        start_time = time.monotonic()
        try:
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
                    "sandbox_level": "wsl_root",
                }
            except asyncio.TimeoutError:
                try:
                    process.kill()
                    await process.wait()
                except (ProcessLookupError, OSError):
                    pass
                duration_ms = int((time.monotonic() - start_time) * 1000)
                return {
                    "stdout": "",
                    "stderr": f"Root WSL command timed out after {timeout}s",
                    "returncode": -1,
                    "duration_ms": duration_ms,
                    "pid": pid,
                    "command": command,
                    "sandbox_level": "wsl_root",
                    "timeout": True,
                }
        except Exception as e:
            duration_ms = int((time.monotonic() - start_time) * 1000)
            return {
                "stdout": "",
                "stderr": str(e),
                "returncode": -1,
                "duration_ms": duration_ms,
                "pid": -1,
                "command": command,
                "sandbox_level": "wsl_root",
                "error": str(e),
            }

    async def configure_passwordless_sudo_wsl(self, distro_name: str = "", username: str = "") -> bool:
        """
        Configure passwordless sudo for the given WSL user.
        This requires running as root to edit /etc/sudoers or adding a file to /etc/sudoers.d/
        """
        if not username:
            logger.info("[SUDO] No WSL username configured — skipping passwordless sudo setup")
            return False

        logger.info(f"[SUDO] Configuring passwordless sudo for WSL user '{username}'")

        # Build a command that adds the user to sudoers with NOPASSWD
        sudoers_line = f"{username} ALL=(ALL) NOPASSWD:ALL"
        cmd = (
            f"echo '{sudoers_line}' > /etc/sudoers.d/chai-{username} && "
            f"chmod 440 /etc/sudoers.d/chai-{username} && "
            f"visudo -c"
        )

        result = await self.run_elevated_wsl(
            command=cmd,
            session_id="wsl-sudo-setup",
            timeout=30,
            distro_name=distro_name,
        )

        if result.get("returncode") == 0:
            logger.info(f"[SUDO] Passwordless sudo configured for '{username}' in WSL")
            self._wsl_sudoers_configured = True
            return True
        else:
            logger.warning(f"[SUDO] Failed to configure passwordless sudo: {result.get('stderr', '')[:200]}")
            return False

    # ── Native Linux elevation ───────────────────────────────────────────────

    async def run_with_password_linux(
        self,
        command: str,
        session_id: str,
        timeout: int,
        working_dir: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Run a command with sudo, injecting the password via stdin."""
        if not self._password:
            return {
                "stdout": "",
                "stderr": "Command requires sudo but no password is configured in .security.yml",
                "returncode": -1,
                "error": "sudo_password_missing",
            }

        # Use sudo -S to read password from stdin
        sudo_cmd = f"echo '{self._password}' | sudo -S -p '' {command}"
        logger.info(f"[SUDO] Running with password injection (masked): sudo -S {command[:100]}...")

        import time
        start_time = time.monotonic()
        try:
            process = await asyncio.create_subprocess_shell(
                sudo_cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=working_dir,
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
                    "sandbox_level": "sudo_password",
                }
            except asyncio.TimeoutError:
                try:
                    process.kill()
                    await process.wait()
                except (ProcessLookupError, OSError):
                    pass
                duration_ms = int((time.monotonic() - start_time) * 1000)
                return {
                    "stdout": "",
                    "stderr": f"Sudo password command timed out after {timeout}s",
                    "returncode": -1,
                    "duration_ms": duration_ms,
                    "pid": pid,
                    "command": command,
                    "sandbox_level": "sudo_password",
                    "timeout": True,
                }
        except Exception as e:
            duration_ms = int((time.monotonic() - start_time) * 1000)
            return {
                "stdout": "",
                "stderr": str(e),
                "returncode": -1,
                "duration_ms": duration_ms,
                "pid": -1,
                "command": command,
                "sandbox_level": "sudo_password",
                "error": str(e),
            }

    # ── Auto-elevation retry ─────────────────────────────────────────────────

    async def run_with_elevation(
        self,
        command: str,
        session_id: str,
        timeout: int,
        process_controller,
        distro_name: str = "",
        working_dir: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Smart elevation runner:
        1. Try normal execution first
        2. If sudo password prompt detected:
           a) On WSL → retry as root
           b) On native Linux with password → retry with sudo -S
           c) On native Linux without password → return clear error
        3. Return result with elevation metadata
        """
        # Step 1: Try normal execution
        result = await process_controller.run(
            command=command,
            session_id=session_id,
            timeout=timeout,
            sandbox_level="none",
            working_dir=working_dir,
        )

        # Step 2: Check for password prompt
        if not self.is_sudo_password_prompt(result.get("stderr", ""), result.get("stdout", "")):
            return result

        logger.warning(f"[SUDO] Password prompt detected for '{command[:80]}...'")

        # Step 3a: WSL — run as root
        if self._wsl and self._wsl.is_active():
            logger.info("[SUDO] Retrying as root in WSL")
            root_result = await self.run_elevated_wsl(
                command=command,
                session_id=session_id,
                timeout=timeout,
                distro_name=distro_name or self._wsl._cfg.distro_name,
                working_dir=working_dir,
            )
            root_result["_elevation_method"] = "wsl_root"
            root_result["_elevation_reason"] = "sudo_password_prompt"
            return root_result

        # Step 3b: Native Linux with password configured
        if self._password and sys.platform != "win32":
            logger.info("[SUDO] Retrying with password injection")
            pw_result = await self.run_with_password_linux(
                command=command,
                session_id=session_id,
                timeout=timeout,
                working_dir=working_dir,
            )
            pw_result["_elevation_method"] = "sudo_password_injected"
            pw_result["_elevation_reason"] = "sudo_password_prompt"
            return pw_result

        # Step 3c: No password available
        logger.error("[SUDO] Command needs sudo but no password or WSL root available")
        result["_elevation_error"] = (
            "Command requires sudo privileges. "
            "Configure passwordless sudo for the user, or add the password to .security.yml, "
            "or run CHAI inside WSL with auto_install_missing enabled."
        )
        return result
