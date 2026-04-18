from __future__ import annotations

import json
import os
from typing import Dict, Optional


def env(key: str, default: str = "") -> str:
    return os.getenv(key, default)


class Settings:
    # FastAPI / container
    ORCHESTRATOR_HOST: str = env("ORCHESTRATOR_HOST", "0.0.0.0")
    ORCHESTRATOR_PORT: int = int(env("ORCHESTRATOR_PORT", "8000"))

    # BaronLLM
    BARONLLM_MODEL_PATH: str = env("BARONLLM_MODEL_PATH", "models/barronllm.gguf")
    BARONLLM_N_CTX: int = int(env("BARONLLM_N_CTX", "4096"))
    BARONLLM_N_GPU_LAYERS: int = int(env("BARONLLM_N_GPU_LAYERS", "35"))
    BARONLLM_TEMPERATURE: float = float(env("BARONLLM_TEMPERATURE", "0.1"))
    BARONLLM_CONFIDENCE_THRESHOLD: float = float(env("BARONLLM_CONFIDENCE_THRESHOLD", "0.7"))

    # Database
    DATABASE_URL: str = env("DATABASE_URL", "sqlite:///alphaweb.db")

    # Docker
    DOCKER_SOCKET: str = env("DOCKER_SOCKET", "unix:///var/run/docker.sock")

    # Tool images
    TOOL_IMAGE_PREFIX: str = env("TOOL_IMAGE_PREFIX", "")
    TOOL_IMAGES_JSON: Optional[str] = os.getenv("TOOL_IMAGES_JSON") or None

    # Host data directory for john tool
    HOST_DATA_DIR: str = env("HOST_DATA_DIR", "./data")
    JOHN_LOCAL_DATA_DIR: str = env("JOHN_LOCAL_DATA_DIR", "./data")
    CONTAINER_DATA_DIR: str = env("CONTAINER_DATA_DIR", "/data")
    JOHN_WORDLIST_MOUNT_MODE: str = env("JOHN_WORDLIST_MOUNT_MODE", "host_path")

    # Tool execution
    DEFAULT_TOOL_TIMEOUT: int = int(env("DEFAULT_TOOL_TIMEOUT", "300"))
    TOOL_EXECUTION_TIMEOUT_SECS: int = int(env("TOOL_EXECUTION_TIMEOUT_SECS", "900"))
    TOOL_OUTPUT_MAX_CHARS: int = int(env("TOOL_OUTPUT_MAX_CHARS", "200000"))

    # Rate limiting
    MAX_CONCURRENT_SCANS: int = int(env("MAX_CONCURRENT_SCANS", "5"))
    SCANS_PER_HOUR_LIMIT: int = int(env("SCANS_PER_HOUR_LIMIT", "10"))

    # Queue
    MAX_QUEUE_DEPTH: int = int(env("MAX_QUEUE_DEPTH", "50"))

    # Phase 2: Workflow / Orchestration
    WORKFLOW_MAX_DEPTH: int = int(env("WORKFLOW_MAX_DEPTH", "4"))
    WORKFLOW_MAX_TOOLS: int = int(env("WORKFLOW_MAX_TOOLS", "6"))
    ORCHESTRATION_CONFIDENCE_THRESHOLD: float = float(env("ORCHESTRATION_CONFIDENCE_THRESHOLD", "0.75"))

    # Docker resource limits
    DOCKER_MEMORY_LIMIT: str = env("DOCKER_MEMORY_LIMIT", "512m")
    DOCKER_CPU_LIMIT: str = env("DOCKER_CPU_LIMIT", "1.0")

    # Logging
    LOG_LEVEL: str = env("LOG_LEVEL", "INFO")
    LOG_DIR: str = env("LOG_DIR", "./logs")
    LOG_FILE: str = env("LOG_FILE", "./logs/orchestrator.log")

    @classmethod
    def tool_images(cls) -> Dict[str, str]:
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
