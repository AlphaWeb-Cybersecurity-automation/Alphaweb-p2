from __future__ import annotations

import asyncio
import json
import logging
import os
import time
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, HTTPException, Query
from pydantic import BaseModel

from config import Settings
from database import Anomaly, ExecutionLog, ScanJob, SessionLocal, WorkflowStep, init_db
from llm_client import get_baron
from services.shannon_orchestrator import ShannonOrchestrator
from services.workflow_engine import WorkflowEngine
from tool_runner import run_tool
from validators import (
    ExecuteRequest,
    ExecuteResponse,
    ScanRequest,
    ValidateRequest,
    ValidationResult,
    check_rate_limit,
    parse_and_validate_execute_request,
    record_scan_end,
    record_scan_start,
    validate_parameters,
    validate_target_enhanced,
)

settings = Settings()

os.makedirs(settings.LOG_DIR, exist_ok=True)

logger = logging.getLogger("orchestrator")
logger.setLevel(getattr(logging, settings.LOG_LEVEL, logging.INFO))

_fmt = logging.Formatter("%(asctime)s %(levelname)s %(message)s")

_file_handler = logging.FileHandler(settings.LOG_FILE)
_file_handler.setFormatter(_fmt)
logger.addHandler(_file_handler)

_stream_handler = logging.StreamHandler()
_stream_handler.setFormatter(_fmt)
logger.addHandler(_stream_handler)


# --- Response models ---

class ScanCreateResponse(BaseModel):
    scan_id: str
    status: str
    tool_selected: Optional[str]
    target: str
    created_at: str


class Finding(BaseModel):
    port: Optional[int] = None
    state: Optional[str] = None
    service: Optional[str] = None
    version: Optional[str] = None


class WorkflowStepResponse(BaseModel):
    step_id: str
    parent_step_id: Optional[str] = None
    execution_order: int
    tool_name: str
    confidence: float = 0.0
    parameters: Dict[str, Any] = {}
    findings: Any = []
    execution_time: Optional[float] = None
    cpu_usage: Optional[float] = None
    memory_usage: Optional[float] = None
    exit_code: Optional[int] = None
    status: str = "pending"
    error_message: Optional[str] = None
    created_at: Optional[str] = None
    completed_at: Optional[str] = None


class AnomalyResponse(BaseModel):
    id: str
    step_id: Optional[str] = None
    type: str
    severity: str
    confidence: float = 0.0
    details: Dict[str, Any] = {}
    suggestion: Optional[str] = None


class ScanDetailResponse(BaseModel):
    scan_id: str
    status: str
    tool_used: Optional[str]
    target: str
    parameters: Dict[str, Any] = {}
    findings: Any = []
    execution_time: Optional[float] = None
    cpu_usage: Optional[float] = None
    memory_usage: Optional[float] = None
    exit_code: Optional[int] = None
    created_at: str
    completed_at: Optional[str] = None
    workflow: List[WorkflowStepResponse] = []
    anomalies: List[AnomalyResponse] = []
    execution_depth: int = 0


class WorkflowResponse(BaseModel):
    scan_id: str
    steps: List[WorkflowStepResponse] = []
    anomalies: List[AnomalyResponse] = []
    execution_depth: int = 0
    total_tools_run: int = 0


class AnalyzeCodeRequest(BaseModel):
    code: str
    language: Optional[str] = None
    filename: Optional[str] = None
    scan_type: Optional[str] = "full"


class CodeVulnerability(BaseModel):
    type: Optional[str] = None
    severity: str
    line: Optional[int] = None
    code_snippet: Optional[str] = None
    issue: str
    fix: Optional[str] = None
    file: Optional[str] = None


class AnalyzeCodeResponse(BaseModel):
    scan_id: str
    vulnerabilities: List[CodeVulnerability] = []
    total_vulnerabilities: int = 0
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    summary: str = ""


class ScanListItem(BaseModel):
    scan_id: str
    status: str
    tool_used: Optional[str]
    target: str
    created_at: str


class ScanListResponse(BaseModel):
    scans: List[ScanListItem]
    total: int
    page: int
    limit: int


class ValidateResponse(BaseModel):
    valid: bool
    tool_selected: Optional[str] = None
    confidence: Optional[float] = None
    rationale: Optional[str] = None
    warnings: List[str] = []


class HealthResponse(BaseModel):
    status: str
    timestamp: str
    components: Dict[str, bool]


# --- Job queue ---

scan_queue: asyncio.Queue = asyncio.Queue()
_worker_task: Optional[asyncio.Task] = None


def _log_to_db(scan_id: str, level: str, message: str) -> None:
    db = SessionLocal()
    try:
        db.add(ExecutionLog(scan_id=scan_id, log_level=level, message=message))
        db.commit()
    finally:
        db.close()


async def _process_scan(job_id: str) -> None:
    db = SessionLocal()
    try:
        scan = db.query(ScanJob).filter(ScanJob.id == job_id).first()
        if not scan:
            logger.error(f"Scan {job_id} not found in database")
            return

        scan.status = "running"
        scan.started_at = datetime.now(timezone.utc)
        db.commit()
        _log_to_db(job_id, "INFO", f"Starting scan with {scan.tool_name} against {scan.target}")

        record_scan_start(scan.user_id)

        try:
            params = json.loads(scan.parameters) if scan.parameters else {}
            start_time = time.time()

            # Use Shannon orchestrator for multi-step workflow
            orchestrator = ShannonOrchestrator(settings)
            try:
                summary = await orchestrator.run_workflow(
                    scan_id=job_id,
                    target=scan.target,
                    initial_tool=scan.tool_name,
                    initial_params=params,
                    initial_confidence=0.85,
                )
                elapsed = time.time() - start_time

                scan.execution_time = round(elapsed, 2)
                scan.findings = json.dumps(summary.get("all_findings", []))
                scan.status = "completed"
                scan.exit_code = 0
                scan.completed_at = datetime.now(timezone.utc)

                _log_to_db(
                    job_id, "INFO",
                    f"Workflow completed in {elapsed:.1f}s — "
                    f"{summary.get('total_tools_run', 1)} tools, "
                    f"depth {summary.get('execution_depth', 1)}"
                )

            except Exception as orch_err:
                # Fallback to single-tool execution if orchestration fails
                logger.warning(f"Orchestration failed, falling back to single tool: {orch_err}")
                _log_to_db(job_id, "WARNING", f"Orchestration failed: {orch_err} — running single tool")

                try:
                    result_single = await orchestrator.run_single_tool(
                        scan_id=job_id,
                        target=scan.target,
                        tool_name=scan.tool_name,
                        params=params,
                        confidence=0.85,
                    )
                    elapsed = time.time() - start_time

                    scan.raw_output = result_single.get("raw_output", "")[:settings.TOOL_OUTPUT_MAX_CHARS]
                    scan.execution_time = round(elapsed, 2)
                    scan.findings = json.dumps(result_single.get("findings", []))
                    scan.exit_code = result_single.get("exit_code", 0)
                    scan.status = "completed"
                    scan.completed_at = datetime.now(timezone.utc)

                    _log_to_db(job_id, "INFO", f"Single-tool scan completed in {elapsed:.1f}s")

                except Exception as single_err:
                    raise single_err

        except asyncio.TimeoutError:
            scan.status = "timeout"
            scan.error_message = "Scan exceeded maximum execution time"
            scan.completed_at = datetime.now(timezone.utc)
            _log_to_db(job_id, "ERROR", "Scan timed out")

        except Exception as e:
            scan.status = "failed"
            scan.error_message = str(e)
            scan.completed_at = datetime.now(timezone.utc)
            _log_to_db(job_id, "ERROR", f"Scan failed: {e}")
            logger.exception(f"Scan {job_id} failed")

        finally:
            record_scan_end(scan.user_id)
            db.commit()

    finally:
        db.close()


async def _worker() -> None:
    logger.info("Background scan worker started")
    while True:
        job_id = await scan_queue.get()
        try:
            await _process_scan(job_id)
        except Exception as e:
            logger.exception(f"Worker error processing {job_id}: {e}")
        finally:
            scan_queue.task_done()


# --- App lifecycle ---

@asynccontextmanager
async def lifespan(app: FastAPI):
    global _worker_task

    # Startup
    logger.info("Initializing AlphaWeb Phase 2...")
    init_db()
    logger.info("Database initialized")

    # Load BaronLLM
    baron = get_baron(settings)
    loaded = await asyncio.to_thread(baron.load)
    if loaded:
        logger.info("BaronLLM loaded successfully")
    else:
        logger.warning("BaronLLM failed to load - LLM features will be unavailable")

    # Start background worker
    _worker_task = asyncio.create_task(_worker())
    logger.info("Background worker started")

    yield

    # Shutdown
    if _worker_task:
        _worker_task.cancel()
        try:
            await _worker_task
        except asyncio.CancelledError:
            pass

    # Shutdown AlphaLLM server
    baron = get_baron(settings)
    baron.shutdown()

    logger.info("AlphaWeb shut down")


app = FastAPI(title="AlphaWeb - Cybersecurity Automation Platform", lifespan=lifespan)

# CORS for frontend dev server
from fastapi.middleware.cors import CORSMiddleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://localhost:3000", "http://127.0.0.1:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# --- Endpoints ---

@app.post("/api/scan", response_model=ScanCreateResponse, status_code=201)
async def create_scan(req: ScanRequest) -> Any:
    user_id = "default-user"

    # Rate limit check
    rate_check = check_rate_limit(user_id, settings.MAX_CONCURRENT_SCANS, settings.SCANS_PER_HOUR_LIMIT)
    if not rate_check.valid:
        raise HTTPException(status_code=429, detail=rate_check.errors)

    # Validate target
    target_check = validate_target_enhanced(req.target)
    if not target_check.valid:
        raise HTTPException(status_code=400, detail=target_check.errors)

    # Queue depth check
    if scan_queue.qsize() >= settings.MAX_QUEUE_DEPTH:
        raise HTTPException(status_code=503, detail="Scan queue is full, try again later")

    # BaronLLM analysis
    baron = get_baron(settings)
    if baron.is_loaded:
        analysis = await asyncio.to_thread(baron.analyze, req.request, req.target)
    else:
        analysis = _fallback_tool_selection(req.request)

    if not analysis.get("safety_checks_passed", False):
        raise HTTPException(status_code=400, detail={
            "error": "Safety checks failed",
            "rationale": analysis.get("rationale", ""),
            "warnings": analysis.get("warnings", []),
        })

    tool_selected = analysis.get("tool_selected")
    if not tool_selected:
        raise HTTPException(status_code=400, detail={
            "error": "Could not determine appropriate tool",
            "rationale": analysis.get("rationale", ""),
        })

    # Sanitize LLM-generated parameters before validation
    params = analysis.get("parameters", {})
    if "ports" in params:
        # Strip ports value if LLM returned something non-numeric (e.g. "common", "top100")
        ports_val = str(params["ports"]).strip()
        if not all(c in "0123456789,- " for c in ports_val) or not ports_val:
            del params["ports"]

    param_check = validate_parameters(tool_selected, params)
    if not param_check.valid:
        raise HTTPException(status_code=400, detail=param_check.errors)

    # Create scan job in DB
    scan_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc)

    db = SessionLocal()
    try:
        scan = ScanJob(
            id=scan_id,
            user_id=user_id,
            target=req.target,
            tool_name=tool_selected,
            status="pending",
            parameters=json.dumps(params),
            created_at=now,
        )
        db.add(scan)
        db.commit()
    finally:
        db.close()

    # Enqueue for background processing
    await scan_queue.put(scan_id)
    logger.info(f"Scan {scan_id} queued: {tool_selected} -> {req.target}")

    return ScanCreateResponse(
        scan_id=scan_id,
        status="pending",
        tool_selected=tool_selected,
        target=req.target,
        created_at=now.isoformat() + "Z",
    )


@app.get("/api/scan/{scan_id}", response_model=ScanDetailResponse)
async def get_scan(scan_id: str) -> Any:
    db = SessionLocal()
    try:
        scan = db.query(ScanJob).filter(ScanJob.id == scan_id).first()
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")

        params = {}
        if scan.parameters:
            try:
                params = json.loads(scan.parameters)
            except json.JSONDecodeError:
                pass

        findings = []
        if scan.findings:
            try:
                findings = json.loads(scan.findings)
            except json.JSONDecodeError:
                pass

        # Fetch workflow steps and anomalies
        workflow_engine = WorkflowEngine(scan_id)
        summary = workflow_engine.get_workflow_summary()

        workflow_steps = [
            WorkflowStepResponse(**step) for step in summary.get("steps", [])
        ]
        anomalies = [
            AnomalyResponse(**a) for a in summary.get("anomalies", [])
        ]

        return ScanDetailResponse(
            scan_id=scan.id,
            status=scan.status,
            tool_used=scan.tool_name,
            target=scan.target,
            parameters=params,
            findings=findings,
            execution_time=scan.execution_time,
            cpu_usage=scan.cpu_usage,
            memory_usage=scan.memory_usage,
            exit_code=scan.exit_code,
            created_at=scan.created_at.isoformat() + "Z" if scan.created_at else "",
            completed_at=scan.completed_at.isoformat() + "Z" if scan.completed_at else None,
            workflow=workflow_steps,
            anomalies=anomalies,
            execution_depth=summary.get("execution_depth", 0),
        )
    finally:
        db.close()


@app.get("/api/scans", response_model=ScanListResponse)
async def list_scans(
    page: int = Query(1, ge=1),
    limit: int = Query(10, ge=1, le=100),
) -> Any:
    db = SessionLocal()
    try:
        total = db.query(ScanJob).count()
        offset = (page - 1) * limit
        scans = (
            db.query(ScanJob)
            .order_by(ScanJob.created_at.desc())
            .offset(offset)
            .limit(limit)
            .all()
        )

        items = [
            ScanListItem(
                scan_id=s.id,
                status=s.status,
                tool_used=s.tool_name,
                target=s.target,
                created_at=s.created_at.isoformat() + "Z" if s.created_at else "",
            )
            for s in scans
        ]

        return ScanListResponse(scans=items, total=total, page=page, limit=limit)
    finally:
        db.close()


@app.get("/api/scan/{scan_id}/workflow", response_model=WorkflowResponse)
async def get_scan_workflow(scan_id: str) -> Any:
    db = SessionLocal()
    try:
        scan = db.query(ScanJob).filter(ScanJob.id == scan_id).first()
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")
    finally:
        db.close()

    workflow_engine = WorkflowEngine(scan_id)
    summary = workflow_engine.get_workflow_summary()

    return WorkflowResponse(
        scan_id=scan_id,
        steps=[WorkflowStepResponse(**s) for s in summary.get("steps", [])],
        anomalies=[AnomalyResponse(**a) for a in summary.get("anomalies", [])],
        execution_depth=summary.get("execution_depth", 0),
        total_tools_run=summary.get("total_tools_run", 0),
    )


@app.post("/api/analyze-code", response_model=AnalyzeCodeResponse)
async def analyze_code(req: AnalyzeCodeRequest) -> Any:
    """Analyze code for security vulnerabilities using BaronLLM."""
    scan_id = str(uuid.uuid4())
    baron = get_baron(settings)

    if baron.is_loaded:
        analysis = await asyncio.to_thread(
            baron.analyze_code, req.code, req.language or "unknown", req.filename
        )
        vulns = [
            CodeVulnerability(**v) for v in analysis.get("vulnerabilities", [])
        ]
    else:
        raw_vulns = _fallback_code_analysis(req.code, req.filename)
        vulns = [CodeVulnerability(**v) for v in raw_vulns]

    # Count severities
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for v in vulns:
        sev = v.severity.lower()
        if sev in counts:
            counts[sev] += 1

    return AnalyzeCodeResponse(
        scan_id=scan_id,
        vulnerabilities=vulns,
        total_vulnerabilities=len(vulns),
        critical=counts["critical"],
        high=counts["high"],
        medium=counts["medium"],
        low=counts["low"],
        summary=f"Found {len(vulns)} vulnerability(ies): "
                f"{counts['critical']} critical, {counts['high']} high, "
                f"{counts['medium']} medium, {counts['low']} low",
    )


@app.post("/api/validate", response_model=ValidateResponse)
async def validate_scan(req: ValidateRequest) -> Any:
    # Validate target
    target_check = validate_target_enhanced(req.target)
    if not target_check.valid:
        return ValidateResponse(
            valid=False,
            warnings=target_check.errors,
        )

    # BaronLLM analysis
    baron = get_baron(settings)
    if baron.is_loaded:
        analysis = await asyncio.to_thread(baron.analyze, req.request, req.target)
    else:
        analysis = _fallback_tool_selection(req.request)

    return ValidateResponse(
        valid=analysis.get("safety_checks_passed", False) and analysis.get("tool_selected") is not None,
        tool_selected=analysis.get("tool_selected"),
        confidence=analysis.get("confidence"),
        rationale=analysis.get("rationale"),
        warnings=analysis.get("warnings", []),
    )


@app.get("/health", response_model=HealthResponse)
async def health() -> Any:
    now = datetime.now(timezone.utc)

    # Check BaronLLM
    baron = get_baron(settings)
    baronllm_ok = baron.is_loaded

    # Check database
    db_ok = False
    try:
        db = SessionLocal()
        db.execute(__import__("sqlalchemy").text("SELECT 1"))
        db_ok = True
        db.close()
    except Exception:
        pass

    # Check Docker
    docker_ok = False
    try:
        import subprocess
        result = await asyncio.to_thread(
            subprocess.run,
            ["docker", "info"],
            capture_output=True,
            timeout=5,
        )
        docker_ok = result.returncode == 0
    except Exception:
        pass

    all_ok = baronllm_ok and db_ok and docker_ok
    return HealthResponse(
        status="healthy" if all_ok else "degraded",
        timestamp=now.isoformat() + "Z",
        components={
            "baronllm": baronllm_ok,
            "database": db_ok,
            "docker": docker_ok,
        },
    )


# --- Legacy endpoint ---

@app.post("/execute", response_model=ExecuteResponse)
async def execute(req: ExecuteRequest) -> Any:
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


# --- Fallback tool selection (when BaronLLM is not loaded) ---

KEYWORD_TOOL_MAP = {
    "port": "nmap",
    "scan port": "nmap",
    "service": "nmap",
    "nmap": "nmap",
    "mass scan": "masscan",
    "masscan": "masscan",
    "fast scan": "masscan",
    "vulnerability": "nikto",
    "vuln": "nikto",
    "web server": "nikto",
    "nikto": "nikto",
    "sql injection": "sqlmap",
    "sqli": "sqlmap",
    "sqlmap": "sqlmap",
    "database": "sqlmap",
    "fuzz": "ffuf",
    "endpoint": "ffuf",
    "ffuf": "ffuf",
    "directory": "gobuster",
    "dns": "gobuster",
    "gobuster": "gobuster",
    "brute": "hydra",
    "credential": "hydra",
    "password": "hydra",
    "hydra": "hydra",
    "hash": "john",
    "crack": "john",
    "john": "john",
    "curl": "curl",
    "http": "curl",
    "api": "curl",
    "request": "curl",
    "packet": "tcpdump",
    "capture": "tcpdump",
    "tcpdump": "tcpdump",
    "traffic": "tcpdump",
    "nuclei": "nuclei",
    "template": "nuclei",
    "cve": "nuclei",
    "hashcat": "hashcat",
    "gpu": "hashcat",
    "gitleaks": "gitleaks",
    "secret": "gitleaks",
    "leak": "gitleaks",
    "git": "gitleaks",
}


def _fallback_tool_selection(request_text: str) -> Dict[str, Any]:
    text = request_text.lower()
    selected = None
    for keyword, tool in KEYWORD_TOOL_MAP.items():
        if keyword in text:
            selected = tool
            break

    if selected:
        return {
            "tool_selected": selected,
            "confidence": 0.75,
            "parameters": {},
            "rationale": f"Keyword-based fallback selected {selected}",
            "safety_checks_passed": True,
            "warnings": ["BaronLLM unavailable - using keyword fallback"],
        }

    return {
        "tool_selected": None,
        "confidence": 0.3,
        "parameters": {},
        "rationale": "Could not determine appropriate tool from request",
        "safety_checks_passed": False,
        "warnings": ["BaronLLM unavailable", "No matching tool found"],
    }


def _fallback_code_analysis(code: str, filename: Optional[str] = None) -> List[Any]:
    """Basic pattern-based code vulnerability detection when BaronLLM is unavailable."""
    import re as _re
    vulns = []
    lines = code.splitlines()

    patterns = [
        (_re.compile(r"""(api[_-]?key|secret|password|token)\s*[=:]\s*["'][^"']+["']""", _re.IGNORECASE),
         "critical", "hardcoded_secret", "Hardcoded secret or credential detected",
         "Use environment variables or a secrets manager"),
        (_re.compile(r"eval\s*\(", _re.IGNORECASE),
         "high", "code_injection", "Use of eval() — potential code injection",
         "Replace eval() with safer alternatives like JSON.parse() or ast.literal_eval()"),
        (_re.compile(r"(exec|system|popen|subprocess\.call)\s*\(", _re.IGNORECASE),
         "high", "command_injection", "Command execution — potential injection risk",
         "Use subprocess with shell=False and parameterized arguments"),
        (_re.compile(r"(SELECT|INSERT|UPDATE|DELETE)\s+.*\+.*['\"]", _re.IGNORECASE),
         "high", "sql_injection", "Possible SQL injection via string concatenation",
         "Use parameterized queries or ORM"),
        (_re.compile(r"innerHTML\s*=", _re.IGNORECASE),
         "medium", "xss", "innerHTML assignment — potential XSS",
         "Use textContent or a sanitization library like DOMPurify"),
        (_re.compile(r"(MD5|SHA1)\s*\(", _re.IGNORECASE),
         "medium", "weak_crypto", "Weak hashing algorithm detected",
         "Use SHA-256 or bcrypt for hashing"),
        (_re.compile(r"verify\s*=\s*False", _re.IGNORECASE),
         "high", "ssl_bypass", "SSL verification disabled",
         "Enable SSL verification; use verify=True"),
        (_re.compile(r"chmod\s+777", _re.IGNORECASE),
         "medium", "insecure_permissions", "Overly permissive file permissions",
         "Use minimal permissions (e.g., chmod 644 or 755)"),
    ]

    for line_num, line in enumerate(lines, 1):
        for pattern, severity, vuln_type, issue, fix in patterns:
            if pattern.search(line):
                vulns.append({
                    "type": vuln_type,
                    "severity": severity,
                    "line": line_num,
                    "code_snippet": line.strip()[:120],
                    "issue": issue,
                    "fix": fix,
                    "file": filename,
                })

    return vulns


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "app:app",
        host=settings.ORCHESTRATOR_HOST,
        port=settings.ORCHESTRATOR_PORT,
        reload=False,
    )
