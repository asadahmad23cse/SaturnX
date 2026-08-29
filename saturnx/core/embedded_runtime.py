"""Embedded Kali runtime used by hosted SaturnX deployments.

The desktop server deliberately launches a separate Kali container through a
local Docker daemon. Managed hosting already runs SaturnX inside that Kali
image, so creating another container is unnecessary and generally unavailable.
This manager preserves the DockerManager tool contract while executing inside
the service container itself.
"""

from __future__ import annotations

import asyncio
import logging
import os
import shlex
import shutil
import signal
import time
import uuid
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace

from saturnx.core.docker_manager import DockerManager, ExecResult, _StreamCapture
from saturnx.core.security import redact_secrets, reject_control_chars
from saturnx.core.tool_catalog import required_backends
from saturnx.output.banners import strip_known_banners
from saturnx.output.filters import apply_tool_filter
from saturnx.output.sanitizer import escape_display_controls, sanitize
from saturnx.output.truncator import truncate_output

logger = logging.getLogger("saturnx.embedded")


class EmbeddedRuntimeManager(DockerManager):
    """Run SaturnX commands directly inside its hosted Kali service image."""

    requires_unprivileged_nmap = True

    def __init__(self, config, *args, **kwargs) -> None:
        embedded_project_root = Path(
            os.getenv("SATURNX_EMBEDDED_PROJECT_ROOT", "/app")
        ).resolve()
        if not embedded_project_root.is_dir():
            raise RuntimeError(
                "Hosted project root is missing: " f"{embedded_project_root}"
            )
        # DockerManager fingerprints source inputs during construction. In a
        # packaged install its inferred project root is site-packages, while
        # the complete, immutable build context lives at /app in this image.
        config = replace(config, project_root=embedded_project_root)
        super().__init__(config, *args, **kwargs)
        if not self._config.skip_metasploit:
            raise ValueError(
                "The embedded hosted runtime currently requires SKIP_METASPLOIT=true."
            )

    @property
    def network_mode(self) -> str:
        return "host"

    def _activate_workspace(self) -> None:
        """Point the stable in-image workspace path at the active session."""
        workspace_link = Path("/opt/workspace")
        target = self.workspace_path
        target.mkdir(parents=True, exist_ok=True)
        if workspace_link.is_symlink():
            workspace_link.unlink()
        elif workspace_link.exists():
            if workspace_link.resolve() == target.resolve():
                return
            # This path is image-owned and contains only build-time scaffolding.
            # User artifacts live below the configured session root instead.
            shutil.rmtree(workspace_link)
        workspace_link.symlink_to(target, target_is_directory=True)

    async def start_container(self) -> None:
        """Validate the embedded toolchain and activate the session workspace."""
        if self._container is not None and self._ready:
            return
        missing = [
            backend
            for backend in required_backends(self._config.installed_capabilities)
            if shutil.which(backend) is None
        ]
        if missing:
            raise RuntimeError(
                "Hosted Kali image is missing required backends: "
                + ", ".join(missing)
            )
        await asyncio.to_thread(self._activate_workspace)
        self._generation += 1
        self._container = SimpleNamespace(
            id=f"embedded-{self._session_id}",
            name=f"saturnx-{self._session_id}",
            status="running",
        )
        self._bootstrapped = True
        self._ready = True
        self._operator_stopped = False
        self._shutting_down = False
        await asyncio.to_thread(
            self._workspace.mark_active,
            self._session_id,
            self._generation,
        )
        self._notify_generation_changed()
        logger.info("Embedded Kali runtime is ready.")

    async def ensure_ready(self) -> None:
        await self._wait_for_startup()
        await self._ensure_container_running()

    async def _ensure_container_running(self, wait_for_startup: bool = True) -> None:
        if wait_for_startup:
            await self._wait_for_startup()
        if self._operator_stopped:
            raise RuntimeError(
                "Embedded runtime was stopped; start a new session to resume."
            )
        if self._container is None or not self._ready:
            raise RuntimeError("Embedded runtime is not running.")

    async def health_ok(self) -> bool:
        if self._shutting_down or self._operator_stopped:
            return True
        return self._container is not None and self._ready

    async def _recover_container(self, reason: str) -> dict:
        async with self._get_recovery_lock():
            if self._shutting_down or self._operator_stopped:
                raise RuntimeError("Embedded runtime recovery is disabled during shutdown.")
            await self.start_container()
            return {
                "container_recovered": True,
                "old_session_id": self._session_id,
                "session_id": self._session_id,
                "recovery_reason": reason,
                "recovery_mode": "embedded-reactivation",
                "workspace_preserved": True,
            }

    async def stop_container(self) -> None:
        if self._container is None:
            return
        self._container = None
        self._bootstrapped = False
        self._ready = False
        self._ready_task = None
        try:
            await asyncio.to_thread(
                self._workspace.mark_inactive,
                self._session_id,
                self._generation,
            )
        except ValueError:
            pass

    async def reattach_container(self) -> str:
        await self.start_container()
        return "embedded-reactivation"

    async def exec_command(
        self,
        cmd: str,
        timeout: int | None = None,
        workdir: str | None = None,
        env: dict[str, str] | None = None,
        clean_output: bool = True,
        max_output_chars: int = 8000,
        tool_name: str = "",
        compact_output: bool = True,
        preserve_raw: bool = False,
        require_ready: bool = True,
        sensitive_values: tuple[str, ...] | list[str] = (),
    ) -> ExecResult:
        """Execute a bounded process group in the hosted Kali container."""
        if require_ready:
            await self.ensure_ready()
        else:
            await self._ensure_container_running(wait_for_startup=False)

        requested_timeout = timeout or self._config.default_timeout
        ceiling = self._config.max_exec_timeout or requested_timeout
        effective_timeout = min(requested_timeout, ceiling)
        secret_values = [*sensitive_values, self._config.msf_password]
        for key, value in (env or {}).items():
            if any(
                marker in key.lower()
                for marker in ("password", "token", "secret", "proxy", "cookie", "auth")
            ):
                secret_values.append(str(value))
        safe_cmd = escape_display_controls(redact_secrets(cmd, secret_values))
        process_env = os.environ.copy()
        process_env.update({str(key): str(value) for key, value in (env or {}).items()})

        capture_limit = self._config.max_captured_output_bytes
        capture_token = uuid.uuid4().hex
        await asyncio.to_thread(
            self._workspace.ensure_directory,
            self._session_id,
            "/opt/workspace/logs",
        )

        def capture(kind: str) -> _StreamCapture:
            path = f"/opt/workspace/logs/exec_{capture_token}_{kind}.bin"
            return _StreamCapture(
                capture_limit,
                artifact_opener=lambda: self._workspace.open_exclusive_writer(
                    self._session_id,
                    path,
                ),
                artifact_container=path,
            )

        stdout_capture = capture("stdout")
        stderr_capture = capture("stderr")
        start = time.monotonic()
        process = await asyncio.create_subprocess_exec(
            "bash",
            "-c",
            cmd,
            cwd=workdir,
            env=process_env,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            start_new_session=True,
        )

        async def pump(reader, destination: _StreamCapture) -> None:
            try:
                while True:
                    chunk = await reader.read(64 * 1024)
                    if not chunk:
                        return
                    destination.append(chunk)
            finally:
                destination.finish()

        stdout_task = asyncio.create_task(pump(process.stdout, stdout_capture))
        stderr_task = asyncio.create_task(pump(process.stderr, stderr_capture))
        timed_out = False
        terminated = False
        try:
            await asyncio.wait_for(process.wait(), timeout=effective_timeout)
        except TimeoutError:
            timed_out = True
            try:
                os.killpg(process.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            try:
                await asyncio.wait_for(process.wait(), timeout=2)
            except TimeoutError:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                await process.wait()
            terminated = process.returncode is not None
        await asyncio.gather(stdout_task, stderr_task)

        stdout_raw = stdout_capture.value()
        stderr_raw = stderr_capture.value()
        duration = round(time.monotonic() - start, 2)
        stdout = stdout_raw.decode("utf-8", errors="replace")
        stderr = stderr_raw.decode("utf-8", errors="replace")
        if timed_out:
            stderr = (
                f"{stderr.rstrip()}\nCommand timed out after {effective_timeout}s"
            ).lstrip()

        output_filtered = False
        filter_notes: list[str] = []
        if clean_output:
            before = (stdout, stderr)
            stdout, stderr = sanitize(stdout), sanitize(stderr)
            if tool_name:
                stdout = strip_known_banners(stdout, tool_name)
                stderr = strip_known_banners(stderr, tool_name)
                if compact_output:
                    filtered = apply_tool_filter(stdout, tool_name)
                    stdout = filtered.text
                    if filtered.changed:
                        filter_notes.append(f"{filtered.note} on stdout")
            output_filtered = before != (stdout, stderr)

        raw_artifact = ""
        if preserve_raw or output_filtered or timed_out:
            timestamp = datetime.now(UTC).strftime("%Y%m%d_%H%M%S_%f")
            raw_artifact = f"/opt/workspace/logs/exec_raw_{timestamp}.txt"
            payload = (
                f"$ {safe_cmd}\n\n[stdout]\n"
                + stdout_raw.decode("utf-8", errors="replace")
                + "\n\n[stderr]\n"
                + stderr_raw.decode("utf-8", errors="replace")
            )
            await self._write_file_internal(raw_artifact, payload)

        response_budget = min(
            self._config.max_inline_response_chars,
            max(0, int(max_output_chars)) * 2,
        )
        stdout_limit = min(max_output_chars, max(0, response_budget * 2 // 3))
        stderr_limit = min(max_output_chars, max(0, response_budget - stdout_limit))
        stdout_artifact = stdout_capture.artifact_path
        stderr_artifact = stderr_capture.artifact_path
        stdout, stdout_truncated = truncate_output(
            stdout,
            max_chars=stdout_limit,
            artifact_path=stdout_artifact or raw_artifact,
        )
        stderr, stderr_truncated = truncate_output(
            stderr,
            max_chars=stderr_limit,
            artifact_path=stderr_artifact or raw_artifact,
        )
        truncated = stdout_truncated or stderr_truncated
        inline_chars = len(stdout) + len(stderr)
        return ExecResult(
            exit_code=int(process.returncode if process.returncode is not None else -1),
            stdout=stdout,
            stderr=stderr,
            duration_seconds=duration,
            command=safe_cmd,
            truncated=truncated,
            artifact=stdout_artifact or stderr_artifact or raw_artifact,
            raw_artifact=raw_artifact,
            stdout_artifact=stdout_artifact,
            stderr_artifact=stderr_artifact,
            filter_notes=filter_notes,
            output_filtered=output_filtered,
            output_complete=not truncated and not timed_out,
            evidence_complete=not timed_out,
            stdout_truncated=stdout_truncated,
            stderr_truncated=stderr_truncated,
            stdout_chars=len(stdout_raw.decode("utf-8", errors="replace")),
            stderr_chars=len(stderr_raw.decode("utf-8", errors="replace")),
            stdout_bytes=stdout_capture.total_bytes,
            stderr_bytes=stderr_capture.total_bytes,
            inline_stdout_chars=len(stdout),
            inline_stderr_chars=len(stderr),
            estimated_inline_tokens=(inline_chars + 3) // 4,
            status="timeout" if timed_out else "",
            timed_out=timed_out,
            timeout_seconds=effective_timeout if timed_out else None,
            terminated=terminated,
            partial_output=bool(timed_out and (stdout_raw or stderr_raw)),
        )

    async def exec_argv(self, argv: list[str], **kwargs) -> ExecResult:
        if not argv:
            raise ValueError("argv must contain at least one argument")
        quoted = [
            shlex.quote(reject_control_chars(str(value), label=f"argv[{index}]"))
            for index, value in enumerate(argv)
        ]
        return await self.exec_command(" ".join(quoted), **kwargs)
