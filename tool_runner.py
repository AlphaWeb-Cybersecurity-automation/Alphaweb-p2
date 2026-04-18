from __future__ import annotations

import asyncio
import os
import shlex
import subprocess
from dataclasses import dataclass
from typing import Callable, Dict, List, Optional, Tuple

from config import Settings
from validators import SUPPORTED_TOOLS, validate_args_string


@dataclass(frozen=True)
class ToolRunResult:
    raw_output: str


def _split_args(args: str) -> List[str]:
    """
    Split args without invoking a shell.

    We rely on `shlex.split` for handling quoted segments.
    """

    if not args:
        return []
    return shlex.split(args, posix=True)


def _docker_run_cmd(
    *,
    tool_name: str,
    args: str,
    target: str,
    settings: Settings,
) -> Tuple[List[str], Optional[Tuple[str, str]]]:
    """
    Build docker run command args.

    Returns:
      (cmd, john_mount) where john_mount is (host_path, container_path) if used.
    """

    args = validate_args_string(args)
    args_tokens = _split_args(args)

    cmd: List[str] = ["docker", "run", "--rm"]

    john_mount: Optional[Tuple[str, str]] = None

    # Special case: "john" expects wordlist/hash input via a /data volume.
    if tool_name == "john":
        basename = os.path.basename(target)
        host_data_dir_spec = settings.HOST_DATA_DIR

        # Two supported mount styles:
        # 1) host_path: mount an absolute host path
        # 2) volume:<name>: mount a Docker named volume
        is_named_volume = host_data_dir_spec.startswith("volume:")

        if is_named_volume:
            volume_name = host_data_dir_spec.split("volume:", 1)[1].strip()
            if not volume_name:
                raise ValueError("HOST_DATA_DIR is volume: but has no volume name.")

            # Validate input exists inside the orchestrator container filesystem
            # (where docker-compose bind mounts or mounts the named volume to /app/data).
            local_lookup_dir = os.path.abspath(settings.JOHN_LOCAL_DATA_DIR)
            host_file = os.path.join(local_lookup_dir, basename)
            if not os.path.isfile(host_file):
                raise FileNotFoundError(
                    f"john input file not found: {host_file}. "
                    f"Ensure the file exists and the orchestrator mounts it to {local_lookup_dir}."
                )

            john_mount = (f"volume:{volume_name}", settings.CONTAINER_DATA_DIR)
            cmd += ["-v", f"{volume_name}:{settings.CONTAINER_DATA_DIR}:ro"]
        else:
            if settings.JOHN_WORDLIST_MOUNT_MODE == "container_path":
                # Non-standard mode; expects docker daemon can access the container path directly.
                host_data_dir_abs = os.path.abspath(settings.CONTAINER_DATA_DIR)
            else:
                host_data_dir_abs = os.path.abspath(host_data_dir_spec)

            host_file = os.path.join(host_data_dir_abs, basename)
            if not os.path.isfile(host_file):
                raise FileNotFoundError(
                    f"john input file not found: {host_file}. "
                    f"Place your wordlist/hash in {host_data_dir_abs} and pass the filename."
                )

            john_mount = (host_data_dir_abs, settings.CONTAINER_DATA_DIR)
            cmd += ["-v", f"{host_data_dir_abs}:{settings.CONTAINER_DATA_DIR}:ro"]

        container_target = os.path.join(settings.CONTAINER_DATA_DIR, basename)
        cmd.append(settings.get_tool_image(tool_name))
        if args_tokens:
            cmd += args_tokens
        cmd.append(container_target)
        return cmd, john_mount

    cmd.append(settings.get_tool_image(tool_name))

    # Special case: tcpdump typically takes flags then an interface/target.
    if tool_name == "tcpdump":
        if args_tokens:
            cmd += args_tokens
        cmd.append(target)
        return cmd, None

    # Default execution: <args> <target>
    if args_tokens:
        cmd += args_tokens
    cmd.append(target)
    return cmd, None


def _build_run_cmd(tool_name: str, args: str, target: str, settings: Settings) -> List[str]:
    cmd, _john_mount = _docker_run_cmd(
        tool_name=tool_name,
        args=args,
        target=target,
        settings=settings,
    )
    return cmd


ToolRunCmdBuilder = Callable[[str, str, Settings], List[str]]


def build_cmd_generic(tool_name: str, args: str, target: str, settings: Settings) -> List[str]:
    return _build_run_cmd(tool_name=tool_name, args=args, target=target, settings=settings)


# Tool registry: tool name -> function that builds the docker command.
TOOL_COMMAND_BUILDERS: Dict[str, ToolRunCmdBuilder] = {
    tool: (lambda a, t, s, _tool=tool: build_cmd_generic(_tool, a, t, s))
    for tool in SUPPORTED_TOOLS
}


def _run_cmd_override(tool_name: str, args: str, target: str, settings: Settings) -> List[str]:
    # Currently all tools share the same builder,
    # but the registry keeps it extensible and lets you add
    # per-tool command shaping cleanly.
    return _build_run_cmd(tool_name=tool_name, args=args, target=target, settings=settings)


# Example explicit overrides (kept for readability/extension).
TOOL_COMMAND_BUILDERS["john"] = lambda a, t, s: _run_cmd_override("john", a, t, s)
TOOL_COMMAND_BUILDERS["tcpdump"] = lambda a, t, s: _run_cmd_override("tcpdump", a, t, s)


def _tool_timeout_seconds(tool_name: str, settings: Settings) -> int:
    # Sensible defaults; override globally via TOOL_EXECUTION_TIMEOUT_SECS.
    if settings.TOOL_EXECUTION_TIMEOUT_SECS:
        return settings.TOOL_EXECUTION_TIMEOUT_SECS
    # fallback (should never be hit)
    return 900


def run_tool_sync(*, tool_name: str, args: str, target: str, settings: Settings) -> ToolRunResult:
    if tool_name not in SUPPORTED_TOOLS:
        raise ValueError(f"Unsupported tool: {tool_name}")

    timeout_secs = _tool_timeout_seconds(tool_name, settings)

    builder = TOOL_COMMAND_BUILDERS.get(tool_name)
    if not builder:
        raise ValueError(f"No docker command builder registered for tool: {tool_name}")

    cmd = builder(args, target, settings)

    proc = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=timeout_secs,
        env=os.environ.copy(),
    )
    out = (proc.stdout or "") + (proc.stderr or "")
    if not out.strip():
        out = proc.stdout or proc.stderr or ""

    return ToolRunResult(raw_output=out)


async def run_tool(
    *,
    tool_name: str,
    args: str,
    target: str,
    settings: Settings,
) -> ToolRunResult:
    return await asyncio.to_thread(
        run_tool_sync,
        tool_name=tool_name,
        args=args,
        target=target,
        settings=settings,
    )

