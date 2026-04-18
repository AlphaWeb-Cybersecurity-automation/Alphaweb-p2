from __future__ import annotations

import os
from typing import Dict, Optional


class Settings:
    """
    Lightweight settings wrapper (env-based).

    We intentionally avoid heavy config dependencies to keep the project easy to run
    in minimal environments.
    """

    # FastAPI / container
    ORCHESTRATOR_HOST: str = os.getenv("ORCHESTRATOR_HOST", "0.0.0.0")
    ORCHESTRATOR_PORT: int = int(os.getenv("ORCHESTRATOR_PORT", "8000"))

    # Tool images
    # Default expects images tagged exactly by tool name:
    #   nmap -> image "nmap"
    # You can override per-tool mapping via TOOL_IMAGES_JSON.
    TOOL_IMAGE_PREFIX: str = os.getenv("TOOL_IMAGE_PREFIX", "")
    TOOL_IMAGES_JSON: Optional[str] = os.getenv("TOOL_IMAGES_JSON") or None

    # Host data directory used by the "john" tool to read wordlists/hashes.
    # Either:
    # - an absolute host path accessible to the Docker daemon, OR
    # - a named volume reference in the form "volume:<name>"
    HOST_DATA_DIR: str = os.getenv("HOST_DATA_DIR", "./data")

    # Where the orchestrator container should look for john input files when validating
    # existence. Only used to locate files *before* launching the john container.
    JOHN_LOCAL_DATA_DIR: str = os.getenv("JOHN_LOCAL_DATA_DIR", "./data")
    CONTAINER_DATA_DIR: str = os.getenv("CONTAINER_DATA_DIR", "/data")
    JOHN_WORDLIST_MOUNT_MODE: str = os.getenv(
        "JOHN_WORDLIST_MOUNT_MODE", "host_path"
    )  # "host_path" or "container_path"

    # Docker / tool execution safety
    TOOL_EXECUTION_TIMEOUT_SECS: int = int(os.getenv("TOOL_EXECUTION_TIMEOUT_SECS", "900"))
    TOOL_OUTPUT_MAX_CHARS: int = int(os.getenv("TOOL_OUTPUT_MAX_CHARS", "200000"))

    # Logging
    LOG_DIR: str = os.getenv("LOG_DIR", "./logs")
    LOG_FILE: str = os.getenv("LOG_FILE", "./logs/orchestrator.log")

    @classmethod
    def tool_images(cls) -> Dict[str, str]:
        """
        Resolve tool name -> docker image tag.

        Env var `TOOL_IMAGES_JSON` can be set to something like:
          {"nmap":"myorg/nmap:latest","nikto":"myorg/nikto:v2"}
        """

        import json

        if not cls.TOOL_IMAGES_JSON:
            return {}

        try:
            raw = json.loads(cls.TOOL_IMAGES_JSON)
            if not isinstance(raw, dict):
                return {}
            return {str(k): str(v) for k, v in raw.items()}
        except Exception:
            return {}

    @classmethod
    def get_tool_image(cls, tool_name: str) -> str:
        override = cls.tool_images().get(tool_name)
        if override:
            return override
        return f"{cls.TOOL_IMAGE_PREFIX}{tool_name}"

