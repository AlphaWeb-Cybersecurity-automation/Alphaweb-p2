from __future__ import annotations

import re
from typing import Optional

from pydantic import BaseModel, ConfigDict, Field


SUPPORTED_TOOLS = [
    "nmap",
    "masscan",
    "nikto",
    "sqlmap",
    "ffuf",
    "gobuster",
    "john",
    "hydra",
    "curl",
    "tcpdump",
]


class ExecuteRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tool: str
    args: str = ""
    target: str = Field(min_length=1, max_length=4096)


class ExecuteResponse(BaseModel):
    tool_used: str
    raw_output: str


_FORBIDDEN_IN_TARGET = re.compile(r"[;\|&`$<>\"\']")
_FORBIDDEN_IN_ARGS = re.compile(r"[;\|&`$<>\"\r\n]")


def validate_tool_name(tool: str) -> str:
    tool = (tool or "").strip()
    if tool not in SUPPORTED_TOOLS:
        raise ValueError(f"Unsupported tool: {tool!r}")
    return tool


def _validate_no_whitespace(s: str, field_name: str) -> None:
    if any(ch.isspace() for ch in s):
        raise ValueError(f"{field_name} must not contain whitespace.")


def validate_target(target: str, tool: str, *, john_filename_only: bool = False) -> str:
    """
    Target validation for safety:
    - Reject whitespace and shell metacharacters.
    - Apply tool-specific restrictions for the special 'john' file target.
    """

    target = (target or "").strip()
    if not target:
        raise ValueError("target is empty.")

    if _FORBIDDEN_IN_TARGET.search(target):
        raise ValueError("target contains forbidden characters.")

    _validate_no_whitespace(target, "target")

    if tool == "john":
        # For john we interpret `target` as a filename inside the mounted /data directory.
        # That keeps the orchestrator from accepting arbitrary host paths.
        basename = target
        if john_filename_only:
            if "/" in basename or "\\" in basename:
                raise ValueError("john target must be a simple filename.")
        if not re.match(r"^[A-Za-z0-9_.-]{1,255}$", basename):
            raise ValueError("john target must be a safe filename.")
        return basename

    if tool == "tcpdump":
        # tcpdump target is usually an interface name.
        if not re.match(r"^[A-Za-z0-9_.:-]{1,64}$", target):
            raise ValueError("tcpdump target must look like an interface name.")
        return target

    # Generic host / URL / CIDR-ish validation for network tools.
    # We allow common URL characters but disallow spaces.
    if len(target) > 2048:
        raise ValueError("target is too long.")

    # If it looks like a URL, be a bit stricter.
    if "://" in target:
        m = re.match(r"^https?://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]+$", target)
        if not m:
            raise ValueError("target URL contains invalid characters.")
        return target

    # Otherwise accept common host/IP/CIDR patterns (without whitespace already enforced).
    m = re.match(
        r"^[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]+$",
        target,
    )
    if not m:
        raise ValueError("target contains invalid characters.")
    return target


def validate_args_string(args: Optional[str]) -> str:
    args = (args or "").strip()
    if not args:
        return ""

    if len(args) > 8192:
        raise ValueError("args is too long.")

    # For safety we prevent the most common shell injection metacharacters.
    if _FORBIDDEN_IN_ARGS.search(args):
        raise ValueError("args contains forbidden characters.")

    # No newlines (also covered by forbidden regex, but keep the message clear).
    if "\n" in args or "\r" in args:
        raise ValueError("args must not contain newlines.")

    return args


def parse_and_validate_execute_request(req: ExecuteRequest) -> ExecuteRequest:
    tool = validate_tool_name(req.tool)
    args = validate_args_string(req.args)
    target = validate_target(
        req.target,
        tool,
        john_filename_only=True,
    )

    return ExecuteRequest(tool=tool, args=args, target=target)

