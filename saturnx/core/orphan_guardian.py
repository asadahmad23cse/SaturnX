"""Detached exact-owner cleanup for abruptly terminated STDIO MCP servers."""

from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

from docker.errors import APIError, DockerException, NotFound

import docker
from saturnx.core.docker_manager import _is_process_running, _process_start_token


def _owner_is_live(pid: int, token: str) -> bool:
    if not _is_process_running(pid):
        return False
    current = _process_start_token(pid)
    # A transient inability to obtain creation time must preserve the container.
    return not current or current == token


def _labels_match(container, expected: dict[str, str]) -> bool:
    container.reload()
    labels = (
        getattr(container, "attrs", {})
        .get("Config", {})
        .get("Labels", {})
        or {}
    )
    return all(labels.get(key) == value for key, value in expected.items())


def guard(
    *,
    container_id: str,
    owner_pid: int,
    owner_start_token: str,
    project_hash: str,
    workspace_hash: str,
    instance_id: str,
    cleanup_signal: str = "",
) -> int:
    """Remove one exactly labeled container after its exact owner disappears."""
    expected = {
        "saturnx.managed": "true",
        "saturnx.project_root_hash": project_hash,
        "saturnx.workspace_root_hash": workspace_hash,
        "saturnx.instance_id": instance_id,
        "saturnx.owner_pid": str(owner_pid),
        "saturnx.owner_start_token": owner_start_token,
    }
    signal_path = Path(cleanup_signal) if cleanup_signal else None
    while _owner_is_live(owner_pid, owner_start_token) and not (
        signal_path is not None and signal_path.is_file()
    ):
        # Graceful STDIO shutdown windows can be only a few seconds. Keep the
        # signal response prompt while the exact-owner checks remain cheap.
        time.sleep(0.25 if signal_path is not None else 2)

    # Docker Desktop may be restarting at exactly the same time as the client.
    # Retry for two minutes, but never broaden ownership or container selection.
    for _attempt in range(60):
        try:
            client = docker.from_env()
            container = client.containers.get(container_id)
            if not _labels_match(container, expected):
                return 3
            # Normalize legacy containers before stopping them so an historical
            # unless-stopped policy cannot recreate the port leak.
            container.update(restart_policy={"Name": "no"})
            try:
                container.stop(timeout=1)
            except APIError:
                # A stopped container has already released its host ports.
                pass
            container.remove(force=True)
            if signal_path is not None:
                signal_path.unlink(missing_ok=True)
            return 0
        except NotFound:
            if signal_path is not None:
                signal_path.unlink(missing_ok=True)
            return 0
        except DockerException:
            time.sleep(2)
    return 4


def main() -> int:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--container-id", required=True)
    parser.add_argument("--owner-pid", required=True, type=int)
    parser.add_argument("--owner-start-token", required=True)
    parser.add_argument("--project-hash", required=True)
    parser.add_argument("--workspace-hash", required=True)
    parser.add_argument("--instance-id", required=True)
    parser.add_argument("--cleanup-signal", default="")
    args = parser.parse_args()
    return guard(
        container_id=args.container_id,
        owner_pid=args.owner_pid,
        owner_start_token=args.owner_start_token,
        project_hash=args.project_hash,
        workspace_hash=args.workspace_hash,
        instance_id=args.instance_id,
        cleanup_signal=args.cleanup_signal,
    )


if __name__ == "__main__":
    sys.exit(main())
