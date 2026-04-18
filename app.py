from __future__ import annotations

import json
import logging
import os
import time
from typing import Any

from fastapi import FastAPI, HTTPException

from config import Settings
from tool_runner import run_tool
from validators import ExecuteRequest, ExecuteResponse, parse_and_validate_execute_request


settings = Settings()

os.makedirs(settings.LOG_DIR, exist_ok=True)

logger = logging.getLogger("orchestrator")
logger.setLevel(logging.INFO)

_fmt = logging.Formatter("%(asctime)s %(levelname)s %(message)s")

_file_handler = logging.FileHandler(settings.LOG_FILE)
_file_handler.setFormatter(_fmt)
logger.addHandler(_file_handler)

_stream_handler = logging.StreamHandler()
_stream_handler.setFormatter(_fmt)
logger.addHandler(_stream_handler)


app = FastAPI(title="Cybersecurity Automation Orchestrator")


@app.post("/execute", response_model=ExecuteResponse)
async def execute(req: ExecuteRequest) -> Any:
    """
    Run a selected tool directly via Docker.
    """

    start = time.time()
    request_id = os.urandom(8).hex()

    try:
        validated = parse_and_validate_execute_request(req)

        run_result = await run_tool(
            tool_name=validated.tool,
            args=validated.args,
            target=validated.target,
            settings=settings,
        )

        elapsed_ms = int((time.time() - start) * 1000)
        logger.info(
            json.dumps(
                {
                    "request_id": request_id,
                    "tool_used": validated.tool,
                    "target": validated.target,
                    "elapsed_ms": elapsed_ms,
                },
                ensure_ascii=False,
            )
        )

        return ExecuteResponse(
            tool_used=validated.tool,
            raw_output=run_result.raw_output[: settings.TOOL_OUTPUT_MAX_CHARS],
        )

    except Exception as e:
        logger.exception("Execution failed")
        raise HTTPException(status_code=500, detail=str(e)) from e


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "app:app",
        host=settings.ORCHESTRATOR_HOST,
        port=settings.ORCHESTRATOR_PORT,
        reload=False,
    )

