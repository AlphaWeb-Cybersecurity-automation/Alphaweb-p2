# AlphaWeb — AI-Powered Cybersecurity Automation Platform

## Overview

AlphaWeb is a web-based security automation platform combining:
- **AI-driven threat analysis** via BaronLLM (local LLM inference)
- **Code vulnerability detection** using Bandit (Python), ESLint (JavaScript), and pattern-based rules
- **Container-orchestrated security tools** — 25 tools across recon, exploitation, fuzzing, password cracking, and vulnerability scanning
- **Interactive UI** with real-time code analysis, file upload, and terminal output streaming

---

## Architecture

```
alphaweb/
├── frontend/              # React + Vite SPA
│   ├── components/        # UI modules
│   │   ├── ActivityBar/   # Left nav (Scanner, Reporting, Orchestration)
│   │   ├── SideBar/       # File upload & explorer
│   │   ├── Editor/        # Code viewer + live analysis
│   │   ├── AgentChat/     # Right panel: AI agent chat
│   │   ├── Terminal/      # Output console
│   │   ├── StatusBar/     # Footer info
│   │   └── QuickActions/  # Fast action buttons
│   ├── App.jsx            # Main component tree
│   ├── vite.config.js     # Vite build config (port 5173)
│   └── index.html         # Entry point
│
├── backend/               # Python FastAPI + SQLAlchemy
│   ├── app.py             # Main API routes (944 lines)
│   ├── config.py          # Environment config
│   ├── database.py        # SQLAlchemy models (ScanJob, ExecutionLog, Anomaly, WorkflowStep)
│   ├── llm_client.py      # BaronLLM inference client
│   ├── tool_runner.py     # Docker-based tool executor
│   ├── validators.py      # Input validation, rate limiting
│   ├── services/
│   │   ├── code_analyzer.py    # Multi-language code vulnerability analysis
│   │   ├── workflow_engine.py  # Tool orchestration & decision trees
│   │   ├── shannon_orchestrator.py # Advanced workflow orchestration
│   │   ├── anomaly_detector.py     # Output anomaly detection
│   │   ├── execution_graph.py      # Execution tracing
│   │   └── tool_decision_engine.py # AI-driven tool selection
│   ├── tools/             # Static analysis configs
│   │   └── js/            # ESLint + security plugins
│   ├── models/            # BaronLLM .gguf file location
│   ├── data/              # Wordlists, temp files
│   ├── logs/              # Execution logs
│   ├── alphaweb.db        # SQLite database
│   ├── requirements.txt    # Python dependencies
│   └── Dockerfile         # Container image
│
├── package.json           # Frontend deps
├── vite.config.js         # Frontend build config
└── README.md              # This file
```

---

## Key Features

### 1. Code Analysis Engine
- **Python**: Bandit security linter
- **JavaScript**: ESLint + eslint-plugin-security + eslint-plugin-no-unsanitized
- **Java, PHP, Go**: Pattern-based regex rules (XSS, SQLi, eval, hardcoded secrets, weak crypto)
- **Real-time UI**: Upload code → editor displays content → click "Analyze" → see vulnerability highlights + panel

### 2. Multi-Tool Orchestration
- **Docker containers** for isolated tool execution
- **Per-tool timeout map**: nmap 300s, sqlmap 900s, john 3600s, etc.
- **Resource limits**: configurable memory (512m), CPU (1.0)
- **Terminal streaming**: live output to browser console

### 3. BaronLLM Integration
- Local GGUF model inference (no external API calls)
- Context-aware code analysis fallback
- Chat interface for security queries

### 4. Database Persistence
- SQLite with SQLAlchemy ORM
- Tables: `ScanJob`, `ExecutionLog`, `Anomaly`, `WorkflowStep`
- Audit trail of all scans and workflow executions

### 5. UI Components
- **Activity Bar**: Project views (Scanner, Reporting, Orchestration)
- **SideBar**: File upload + explorer
- **Editor**: Code viewer + live line-by-line vulnerability highlighting
- **AgentChat**: AI-powered threat analysis (retro phosphor header)
- **Terminal**: Real-time tool output parsing

---

## Setup Instructions

### Prerequisites
- **Node.js** 20+ (frontend build)
- **Python** 3.9+ (backend)
- **Docker** (for security tool containers)
- **Java** 8+ (PMD integration when available)
- **npm** 9+ (frontend package manager)

---

### Backend Setup

#### 1. Install Python Dependencies
```bash
cd backend
pip install -r requirements.txt
```

**Dependencies:**
- `fastapi` — Web framework
- `uvicorn[standard]` — ASGI server
- `pydantic` — Data validation
- `sqlalchemy` — ORM
- `llama-cpp-python` — BaronLLM inference (local GGUF model)
- `bandit` — Python security linter
- `semgrep` — SAST scanner (Windows encoding issues; pattern fallback used)

#### 2. Configure Environment Variables
Create a `.env` file or export:
```bash
# FastAPI server
ORCHESTRATOR_HOST=0.0.0.0
ORCHESTRATOR_PORT=8000

# BaronLLM model
BARONLLM_MODEL_PATH=models/barronllm.gguf
BARONLLM_N_CTX=4096
BARONLLM_N_GPU_LAYERS=35
BARONLLM_TEMPERATURE=0.1
BARONLLM_CONFIDENCE_THRESHOLD=0.7

# Database
DATABASE_URL=sqlite:///alphaweb.db

# Docker
DOCKER_SOCKET=unix:///var/run/docker.sock
DOCKER_MEMORY_LIMIT=512m
DOCKER_CPU_LIMIT=1.0

# Tool timeouts (seconds)
DEFAULT_TOOL_TIMEOUT=300
TOOL_EXECUTION_TIMEOUT_SECS=900

# Logging
LOG_LEVEL=INFO
LOG_DIR=./logs
```

#### 3. Initialize Database
```bash
cd backend
python -c "from database import init_db; init_db()"
```

#### 4. Download BaronLLM Model (Optional)
Place your GGUF model at `backend/models/barronllm.gguf` (currently required but graceful fallback to regex patterns if unavailable).

#### 5. Start Backend
```bash
cd backend
python -m uvicorn app:app --host 0.0.0.0 --port 8000 --reload
```

Server runs on `http://localhost:8000`. Health check: `GET /health`

#### 6. Verify Services
```bash
# Check Bandit
bandit --version

# Check code analyzer
curl -X POST http://localhost:8000/analyze-code \
  -H "Content-Type: application/json" \
  -d '{"code":"eval(x)","filename":"test.py"}'
```

---

### Frontend Setup

#### 1. Install Dependencies
```bash
npm install
```

**Key Dependencies:**
- `react` 18.2.0
- `react-dom` 18.2.0
- `vite` 4.3.0 (build tool)

#### 2. Configure Vite Proxy
File: `vite.config.js`
- Frontend port: `5173`
- Backend proxy: `/api/*` → `http://localhost:8000`
- **Note**: Current proxy configuration requires backend routes WITHOUT `/api` prefix (e.g., `/analyze-code`, `/chat`, `/execute`)

#### 3. Start Dev Server
```bash
npm run dev
```

Frontend runs on `http://localhost:5173`. Vite auto-reloads on file changes.

#### 4. Build for Production
```bash
npm run build
```

Output: `dist/` directory (static SPA).

---

### Docker Setup (Security Tools)

#### 1. Verify Docker Installation
```bash
docker --version
docker ps
```

#### 2. Build Tool Images
```bash
cd backend
docker-compose -f docker-compose.tools.yml build
```

Builds images for: nmap, sqlmap, nikto, ffuf, gobuster, john, hydra, curl, tcpdump.

#### 3. Run Tool Execution
Tools are invoked dynamically from `tool_runner.py`:
```python
from tool_runner import run_tool_sync
result = run_tool_sync(
    tool_name="nmap",
    args="-p 80,443",
    target="example.com",
    settings=settings
)
print(result.raw_output, result.exit_code)
```

**Tool Timeout Map** (in `tool_runner.py`):
```python
TOOL_TIMEOUTS = {
    "curl": 60, "nmap": 300, "masscan": 120, "nikto": 600,
    "sqlmap": 900, "ffuf": 600, "gobuster": 600, "hydra": 1800,
    "john": 3600, "tcpdump": 60, "nuclei": 600, "hashcat": 3600,
    "gitleaks": 300,
}
```

---

## Running the Full Stack

### Terminal 1: Backend
```bash
cd backend
python -m uvicorn app:app --host 0.0.0.0 --port 8000 --reload
```

### Terminal 2: Frontend
```bash
npm run dev
```

### Terminal 3: Docker (if running tools)
```bash
cd backend
docker-compose -f docker-compose.tools.yml up
```

### Access
- **Frontend**: `http://localhost:5173`
- **Backend API**: `http://localhost:8000`
- **API Docs**: `http://localhost:8000/docs`

---

## API Endpoints

### Code Analysis
```bash
POST /analyze-code
Content-Type: application/json

{
  "code": "eval(userInput)",
  "language": "javascript",
  "filename": "app.js"
}

Response:
{
  "analysis_id": "uuid",
  "language": "javascript",
  "total_vulnerabilities": 2,
  "critical": 0, "high": 1, "medium": 1, "low": 0,
  "vulnerabilities": [
    {
      "type": "eval_injection",
      "severity": "high",
      "line": 1,
      "code_snippet": "eval(userInput)",
      "issue": "eval() executes arbitrary code...",
      "fix": "Use JSON.parse() for data or refactor...",
      "cwe": "CWE-95"
    }
  ]
}
```

### Scan Creation
```bash
POST /api/scan
{
  "target": "example.com",
  "tool": "nmap",
  "parameters": "-p 80,443,8000-9000"
}
```

### Chat (AI Analysis)
```bash
POST /api/chat
{
  "prompt": "scan for open ports",
  "domain": "example.com"
}
```

### Tool Execution
```bash
POST /execute
{
  "tool_name": "nmap",
  "args": "-sV -p 80,443",
  "target": "example.com"
}
```

### Health Check
```bash
GET /health
Response: {
  "status": "healthy",
  "components": {
    "baronllm": true,
    "database": true,
    "docker": true
  }
}
```

---

## Code Analysis Details

### Supported Languages
- **Python**: Bandit (SAST) + pattern rules (supplement)
- **JavaScript**: ESLint + security plugins (primary) + pattern rules (supplement)
- **Java**: Pattern rules (XSS, SQLi, eval, deserialization, hardcoded secrets, weak crypto)
- **PHP**: Pattern rules (eval, unvalidated input, SQLi, XSS, command injection, weak hash)
- **Go**: Pattern rules (command injection, SQLi, hardcoded secrets, TLS bypass, weak random)

### Analysis Chain
1. **Python**: Bandit JSON output → CWE mapping + fix text
2. **JavaScript**: ESLint (`eslint-plugin-security`) + rules deduplication
3. **Others**: Regex pattern matching with CWE/severity/fix metadata

### ESLint Configuration
Location: `backend/tools/js/.eslintrc.json`
```json
{
  "plugins": ["security", "no-unsanitized"],
  "rules": {
    "security/detect-eval-with-expression": "error",
    "security/detect-child-process": "error",
    "no-unsanitized/method": "error",
    "no-eval": "error",
    ...
  }
}
```

---

## Project Structure Reference

### Frontend Components

| Component | Purpose | Key State |
|-----------|---------|-----------|
| `ActivityBar` | Left nav tabs | activeView (scanner/reporting/orchestration) |
| `SideBar` | File explorer + upload | files[], dragging, domain input |
| `Editor` | Code viewer + analysis | activeFile, openFiles[], vulnLines |
| `AgentChat` | AI security chat | messages[], domain, input, loading |
| `Terminal` | Tool output console | logs[], clearKey, maximized |
| `StatusBar` | Footer metrics | activeFile, AI status, cursor pos |

### Backend Services

| Service | Purpose | Key Functions |
|---------|---------|---|
| `code_analyzer.py` | Multi-language SAST | analyze(), run_eslint(), run_bandit(), run_pattern_analysis() |
| `workflow_engine.py` | Tool orchestration | build execution DAG, multi-step workflows |
| `shannon_orchestrator.py` | Advanced workflow | confidence scoring, anomaly detection |
| `tool_decision_engine.py` | AI tool selection | LLM-guided tool picking |
| `anomaly_detector.py` | Output anomalies | Parse & flag suspicious results |

---

## Database Schema

### ScanJob
```
id (PK)
task_id (unique)
status (pending/running/completed/failed)
tool_selected (str)
target (str)
created_at (timestamp)
completed_at (timestamp)
result (JSON)
```

### ExecutionLog
```
id (PK)
scan_id (FK)
execution_order (int)
tool_name (str)
command_line (str)
raw_output (text)
exit_code (int)
execution_time (float)
timestamp (timestamp)
```

### Anomaly
```
id (PK)
scan_id (FK)
severity (critical/high/medium/low)
anomaly_type (str)
description (text)
detected_at (timestamp)
```

### WorkflowStep
```
id (PK)
scan_id (FK)
step_id (unique)
parent_step_id (FK)
execution_order (int)
tool_name (str)
parameters (JSON)
findings (JSON)
execution_time (float)
status (pending/completed/failed)
```

---

## Debugging & Troubleshooting

### Backend Won't Start
```bash
# Check Python version
python --version  # Must be 3.9+

# Check port in use
lsof -i :8000

# Rebuild dependencies
pip install --upgrade --force-reinstall -r requirements.txt
```

### Frontend Build Errors
```bash
# Clear node_modules and reinstall
rm -rf node_modules package-lock.json
npm install

# Check Node version
node --version  # Must be 20+
```

### Code Analysis Not Working
```bash
# Check Bandit installed
pip install bandit

# Check ESLint installed
cd backend/tools/js && npm install --legacy-peer-deps

# Test manually
python -c "from services.code_analyzer import analyze; print(analyze('eval(x)', None, 'test.py'))"
```

### Docker Tools Not Running
```bash
# Check Docker daemon
docker ps

# Build images
cd backend && docker-compose -f docker-compose.tools.yml build

# Run single tool test
docker run --rm <tool-image> --help
```

### Database Locked
```bash
# Remove old DB and recreate
rm backend/alphaweb.db
cd backend && python -c "from database import init_db; init_db()"
```

---

## Environment Variables Summary

| Variable | Default | Purpose |
|----------|---------|---------|
| `ORCHESTRATOR_HOST` | 0.0.0.0 | FastAPI bind address |
| `ORCHESTRATOR_PORT` | 8000 | FastAPI port |
| `BARONLLM_MODEL_PATH` | models/barronllm.gguf | Local LLM model file |
| `DATABASE_URL` | sqlite:///alphaweb.db | SQLAlchemy connection string |
| `DOCKER_SOCKET` | unix:///var/run/docker.sock | Docker daemon socket |
| `DOCKER_MEMORY_LIMIT` | 512m | Container memory limit |
| `DOCKER_CPU_LIMIT` | 1.0 | Container CPU limit |
| `TOOL_EXECUTION_TIMEOUT_SECS` | 900 | Global tool timeout override |
| `LOG_LEVEL` | INFO | Python logging level |

---

## Performance Tuning

### Code Analysis Optimization
- ESLint rule checks run in parallel for JS files
- Pattern analysis uses compiled regex (fast)
- Python Bandit runs in subprocess (isolated)

### Docker Tool Optimization
- Resource limits prevent runaway processes
- Per-tool timeout map prevents hanging
- No tool output retries (timeout = failed)

### Database Optimization
- SQLite suitable for <100k scans
- For production: migrate to PostgreSQL
- Add indexes on `scan_id`, `status` columns

---

## Development Workflow

### Adding a New Security Tool
1. Build/pull Docker image
2. Update `TOOL_TIMEOUTS` in `tool_runner.py`
3. Register in `SUPPORTED_TOOLS` list in `validators.py`
4. Test: `run_tool_sync(tool_name="...", args="...", target="...", settings=settings)`

### Adding a New Code Analysis Rule
1. Add regex pattern to `PATTERN_RULES[language]` in `services/code_analyzer.py`
2. Include: pattern, type, severity, issue, fix, CWE
3. Test: `run_pattern_analysis(code, language)`

### Adding UI Feature
1. Create component in `frontend/components/`
2. Import in `frontend/App.jsx`
3. Pass props & callbacks
4. Style with CSS (follow `--bg-*`, `--text-*` variables)

---

## Technologies

### Frontend
- **React** 18.2 — UI framework
- **Vite** 4.3 — Build tool & dev server
- **CSS3** — Styling (CSS variables, Grid, Flexbox)

### Backend
- **FastAPI** — Web framework (async)
- **SQLAlchemy** — ORM
- **Uvicorn** — ASGI server
- **Pydantic** — Data validation
- **llama-cpp-python** — Local LLM inference

### Security Analysis
- **Bandit** — Python SAST
- **ESLint** + plugins — JavaScript linter
- **Regex patterns** — Fallback for Java, PHP, Go
- **Docker** — Tool isolation

### Database
- **SQLite** — Dev/test (portable)
- **PostgreSQL** — Production (recommended)

---

## License & Contact

Project: AlphaWeb v0.1.0  
Author: flexsyyy  
Last Updated: 2026-04-19

---

## Quick Start (TL;DR)

```bash
# Backend
cd backend
pip install -r requirements.txt
pip install bandit
python -m uvicorn app:app --host 0.0.0.0 --port 8000

# Frontend (new terminal)
npm install
npm run dev

# Visit
# http://localhost:5173
```

Upload a Python/JS file → Click "Analyze" → See vulnerabilities with line numbers, CWE codes, and actionable fixes.
