"""firejail/cgroups/chroot wrapper for safe command execution."""
import asyncio
import logging
import os
import signal
import time
from pathlib import Path
from typing import Dict, Optional, Any

logger = logging.getLogger(__name__)


class ProcessController:
    def __init__(self, config):
        self._config = config
        self._sandbox_user = config.paths.sandbox_user
        self._firejail_profile = config.paths.firejail_profile
        self._max_ram_mb = config.sandbox.max_ram_mb
        self._max_cpu_percent = config.sandbox.max_cpu_percent
        self._default_timeout = config.sandbox.command_timeout

    async def run(
        self,
        command: str,
        session_id: str,
        timeout: Optional[int] = None,
        sandbox_level: str = "firejail",
        max_ram_mb: Optional[int] = None,
        working_dir: Optional[str] = None,
        env_vars: Optional[Dict[str, str]] = None,
    ) -> Dict[str, Any]:
        """
        Execute a command with sandboxing and resource limits.

        Args:
            command: The command to execute
            session_id: Session ID for tracking
            timeout: Command timeout in seconds (default from config)
            sandbox_level: "none", "firejail", "cgroups", or "chroot"
            max_ram_mb: Max RAM in MB (default from config)
            working_dir: Working directory for the command
            env_vars: Additional environment variables

        Returns:
            Dict with stdout, stderr, returncode, duration_ms, pid
        """
        timeout = timeout or self._default_timeout
        max_ram_mb = max_ram_mb or self._max_ram_mb

        # Build the wrapped command based on sandbox level
        wrapped_cmd = self._wrap_command(command, sandbox_level, max_ram_mb)

        logger.info(f"[{session_id}] Executing: {wrapped_cmd[:200]}...")

        start_time = time.monotonic()

        try:
            # Create subprocess
            env = os.environ.copy()
            if env_vars:
                env.update(env_vars)

            process = await asyncio.create_subprocess_shell(
                wrapped_cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=working_dir,
                env=env,
                preexec_fn=self._preexec_fn if sandbox_level == "cgroups" else None,
            )

            # Record PID for session tracking
            pid = process.pid

            # Wait for completion with timeout
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
                    "sandbox_level": sandbox_level,
                }

            except asyncio.TimeoutError:
                # Kill the process on timeout
                try:
                    process.send_signal(signal.SIGTERM)
                    await asyncio.sleep(2)
                    if process.returncode is None:
                        process.kill()
                        await process.wait()
                except ProcessLookupError:
                    pass

                duration_ms = int((time.monotonic() - start_time) * 1000)
                logger.warning(f"[{session_id}] Command timed out after {timeout}s")

                return {
                    "stdout": "",
                    "stderr": f"Command timed out after {timeout} seconds",
                    "returncode": -1,
                    "duration_ms": duration_ms,
                    "pid": pid,
                    "command": command,
                    "sandbox_level": sandbox_level,
                    "timeout": True,
                }

        except Exception as e:
            duration_ms = int((time.monotonic() - start_time) * 1000)
            logger.error(f"[{session_id}] Command execution failed: {e}")
            return {
                "stdout": "",
                "stderr": str(e),
                "returncode": -1,
                "duration_ms": duration_ms,
                "pid": -1,
                "command": command,
                "sandbox_level": sandbox_level,
                "error": str(e),
            }

    def _wrap_command(self, command: str, sandbox_level: str, max_ram_mb: int) -> str:
        """Wrap command with sandboxing."""
        if sandbox_level == "none":
            return command

        elif sandbox_level == "firejail":
            profile = self._firejail_profile
            if not Path(profile).exists():
                logger.warning(f"Firejail profile not found: {profile}, using default")
                profile = "default"

            return (
                f"firejail --profile={profile} "
                f"--rlimit-as={max_ram_mb * 1024 * 1024} "
                f"--private-tmp "
                f"--netfilter "
                f"--nosound "
                f"--novideo "
                f"--quiet "
                f"-- {command}"
            )

        elif sandbox_level == "cgroups":
            # Use systemd-run or cgexec for cgroup-based limits
            return (
                f"systemd-run --scope --property=MemoryMax={max_ram_mb}M "
                f"--property=CPUQuota={self._max_cpu_percent}% "
                f"--collect --quiet -- {command}"
            )

        elif sandbox_level == "chroot":
            # Chroot sandbox (requires pre-setup chroot environment)
            chroot_dir = "/var/chroot/pentest"
            return f"chroot {chroot_dir} /bin/sh -c '{command}'"

        else:
            logger.warning(f"Unknown sandbox level: {sandbox_level}, using none")
            return command

    def _preexec_fn(self):
        """Function to run in child process before exec (for cgroups)."""
        import resource
        # Set memory limit
        resource.setrlimit(resource.RLIMIT_AS, (self._max_ram_mb * 1024 * 1024, resource.RLIM_INFINITY))
        # Set CPU time limit (5 minutes)
        resource.setrlimit(resource.RLIMIT_CPU, (300, 300))
        # Set max file size (100MB)
        resource.setrlimit(resource.RLIMIT_FSIZE, (104857600, resource.RLIM_INFINITY))

    async def kill_session_processes(self, session_id: str, pids: list):
        """Kill all processes associated with a session."""
        for pid in pids:
            try:
                os.kill(pid, signal.SIGTERM)
                await asyncio.sleep(1)
                try:
                    os.kill(pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            except ProcessLookupError:
                pass
            except PermissionError:
                logger.warning(f"Permission denied killing PID {pid}")
