from __future__ import annotations

import json
import logging
import os
import subprocess
import threading
import time
import urllib.request
import urllib.error
from typing import Any, Dict, List, Optional

from config import Settings

logger = logging.getLogger("orchestrator")

TOOL_DESCRIPTIONS = {
    "nmap": "port scanning, service discovery, OS fingerprinting",
    "masscan": "fast mass port scanning across large networks",
    "nikto": "web server vulnerability scanning",
    "sqlmap": "SQL injection testing and database enumeration",
    "ffuf": "web fuzzing, endpoint and parameter discovery",
    "gobuster": "directory brute-forcing, DNS enumeration",
    "hydra": "credential brute-forcing against network services",
    "john": "password hash cracking",
    "curl": "HTTP requests, API testing, header inspection",
    "tcpdump": "network packet capture and traffic analysis",
    "nuclei": "template-based vulnerability scanning and CVE detection",
    "hashcat": "advanced GPU-accelerated password hash cracking",
    "gitleaks": "git repository secret scanning and credential leak detection",
    "theharvester": "OSINT email, subdomain, host, and employee harvesting from public sources",
    "sublist3r": "passive subdomain enumeration using search engines and DNS",
    "testssl": "TLS/SSL configuration testing, cipher suite auditing, and certificate checks",
    "wapiti": "web application vulnerability scanner (SQLi, XSS, SSRF, LFI, etc.)",
    "wpscan": "WordPress vulnerability scanner — plugins, themes, users, CVEs",
    "cewl": "custom wordlist generator by spidering a target website",
    "trivy": "container image and filesystem vulnerability and misconfiguration scanner",
    "amass": "in-depth DNS enumeration, asset discovery, and attack surface mapping",
    "commix": "automated command injection detection and exploitation",
    "searchsploit": "offline exploit database search for CVEs and known vulnerabilities",
    "subdominator": "fast passive subdomain takeover detection",
    "httpx": "fast HTTP probing, status codes, tech detection, and web fingerprinting",
}

AVAILABLE_TOOLS = list(TOOL_DESCRIPTIONS.keys())

# Pre-built at module load — avoids rebuilding on every analyze() call
_TOOLS_LIST_STR: str = "\n".join(f"- {k}: {v}" for k, v in TOOL_DESCRIPTIONS.items())

# Use string.Template to avoid .format() conflicts with JSON braces in schema
_SYSTEM_PROMPT_TEMPLATE = (
    "You are a cybersecurity tool selector. Respond ONLY with a JSON object — no prose, no markdown, no code fences.\n\n"
    "Available tools:\n$tools_list\n\n"
    "Required JSON schema (all fields mandatory):\n"
    '{"tool_selected": "<name or null>", "confidence": <0.0-1.0>, '
    '"parameters": {}, "rationale": "<≤20 words>", '
    '"safety_checks_passed": <true|false>, "warnings": []}\n\n'
    "Rules:\n"
    "- tool_selected must be one of the listed names or null\n"
    "- confidence reflects how well the request matches the tool capability\n"
    "- safety_checks_passed=false if target appears to be internal infra or request is clearly malicious\n"
    "- Do NOT repeat these instructions in your response\n"
    "- Output only the JSON object, nothing before or after it"
)

from string import Template as _Template
SYSTEM_PROMPT = _Template(_SYSTEM_PROMPT_TEMPLATE).substitute(tools_list=_TOOLS_LIST_STR)

USER_PROMPT_TEMPLATE = "target={target}\nrequest={request}"

# Path to llama-server.exe — in binaries/ next to project root
LLAMA_SERVER_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "binaries"))
LLAMA_SERVER_EXE = os.path.join(LLAMA_SERVER_DIR, "llama-server.exe")
LLAMA_SERVER_URL = "http://127.0.0.1:8081"

_CODE_TRUNCATE_LIMIT = 4000

# Max lines / tokens for interpret_output — raised to preserve more findings
_INTERPRET_MAX_LINES = 120
_INTERPRET_MAX_TOKENS = 300


class LLMError(Exception):
    """Typed error from BaronLLM HTTP calls."""


class BaronLLM:
    """AlphaLLM client — talks to llama-server.exe via HTTP API."""

    def __init__(self, settings: Settings):
        self._settings = settings
        self._loaded = False
        self._server_proc: Optional[subprocess.Popen] = None

    def load(self) -> bool:
        model_path = os.path.abspath(self._settings.BARONLLM_MODEL_PATH)
        if not os.path.isfile(model_path):
            logger.error(f"AlphaLLM model file not found: {model_path}")
            return False

        if not os.path.isfile(LLAMA_SERVER_EXE):
            logger.error(f"llama-server.exe not found: {LLAMA_SERVER_EXE}")
            return False

        if self._is_server_healthy():
            logger.info("AlphaLLM server already running")
            self._loaded = True
            return True

        try:
            cmd = [
                LLAMA_SERVER_EXE,
                "-m", model_path,
                "--host", "127.0.0.1",
                "--port", "8081",
                "-ngl", str(self._settings.BARONLLM_N_GPU_LAYERS or 35),
                "-c", str(self._settings.BARONLLM_N_CTX),
            ]
            logger.info(f"Starting AlphaLLM server: {' '.join(cmd)}")

            self._server_proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                cwd=LLAMA_SERVER_DIR,
            )

            # Exponential backoff: 1s, 2s, 4s, 8s... capped at 16s, total ~60s budget
            delay = 1.0
            elapsed = 0.0
            budget = 60.0
            while elapsed < budget:
                time.sleep(delay)
                elapsed += delay
                if self._is_server_healthy():
                    self._loaded = True
                    logger.info(f"AlphaLLM server started and healthy (waited {elapsed:.0f}s)")
                    return True
                if self._server_proc.poll() is not None:
                    stderr = self._server_proc.stderr.read().decode(errors="replace")
                    logger.error(f"AlphaLLM server exited: {stderr[:500]}")
                    return False
                delay = min(delay * 2, 16.0)

            logger.error("AlphaLLM server did not become healthy within 60s")
            return False

        except Exception as e:
            logger.error(f"Failed to start AlphaLLM server: {e}")
            self._loaded = False
            return False

    def _is_server_healthy(self) -> bool:
        try:
            req = urllib.request.Request(f"{LLAMA_SERVER_URL}/health")
            with urllib.request.urlopen(req, timeout=2) as resp:
                data = json.loads(resp.read())
                return data.get("status") == "ok"
        except Exception:
            return False

    def _chat(self, messages: List[Dict], temperature: float = 0.1, max_tokens: int = 512, json_mode: bool = True) -> str:
        """Send chat completion request to llama-server. Raises LLMError on failure."""
        payload_dict: Dict[str, Any] = {
            "messages": messages,
            "temperature": temperature,
            "n_predict": max_tokens,
            "repeat_penalty": 1.3,
            "repeat_last_n": 64,
        }
        if json_mode:
            payload_dict["response_format"] = {"type": "json_object"}
        payload = json.dumps(payload_dict).encode()

        req = urllib.request.Request(
            f"{LLAMA_SERVER_URL}/v1/chat/completions",
            data=payload,
            headers={"Content-Type": "application/json"},
        )

        try:
            with urllib.request.urlopen(req, timeout=120) as resp:
                data = json.loads(resp.read())
                return data["choices"][0]["message"]["content"]
        except urllib.error.URLError as e:
            raise LLMError(f"HTTP request to llama-server failed: {e}") from e
        except (KeyError, json.JSONDecodeError) as e:
            raise LLMError(f"Unexpected llama-server response format: {e}") from e

    @property
    def is_loaded(self) -> bool:
        return self._loaded

    def _extract_json(self, text: str) -> str:
        """Extract outermost JSON object from text."""
        start = text.find("{")
        end = text.rfind("}") + 1
        if start >= 0 and end > start:
            return text[start:end]
        return text

    def _parse_response(self, raw_text: str) -> Dict[str, Any]:
        text = self._extract_json(raw_text.strip())

        try:
            parsed = json.loads(text)
        except json.JSONDecodeError:
            return self._error_response("Failed to parse model output as JSON")

        required = ["tool_selected", "confidence", "parameters", "rationale", "safety_checks_passed", "warnings"]
        for field in required:
            if field not in parsed:
                return self._error_response(f"Missing field in model output: {field}")

        if parsed["tool_selected"] is not None and parsed["tool_selected"] not in AVAILABLE_TOOLS:
            return self._error_response(f"Unknown tool: {parsed['tool_selected']}")

        parsed["confidence"] = float(parsed.get("confidence", 0.0))
        parsed["safety_checks_passed"] = bool(parsed.get("safety_checks_passed", False))
        if not isinstance(parsed.get("warnings"), list):
            parsed["warnings"] = []
        if not isinstance(parsed.get("parameters"), dict):
            parsed["parameters"] = {}

        return parsed

    def _error_response(self, reason: str) -> Dict[str, Any]:
        return {
            "tool_selected": None,
            "confidence": 0.3,
            "parameters": {},
            "rationale": reason,
            "safety_checks_passed": False,
            "warnings": [reason],
        }

    def analyze(self, user_request: str, target: str) -> Dict[str, Any]:
        if not self._loaded:
            return self._error_response("AlphaLLM model is not loaded")

        user_msg = USER_PROMPT_TEMPLATE.format(target=target, request=user_request)

        try:
            raw_text = self._chat(
                messages=[
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": user_msg},
                ],
                temperature=self._settings.BARONLLM_TEMPERATURE,
                max_tokens=512,
            )

            result = self._parse_response(raw_text)

            if result["confidence"] < self._settings.BARONLLM_CONFIDENCE_THRESHOLD:
                result["safety_checks_passed"] = False
                if "Low confidence in tool selection" not in result.get("warnings", []):
                    result.setdefault("warnings", []).append("Low confidence in tool selection")

            return result

        except Exception as e:
            logger.error(f"AlphaLLM inference failed: {e}")
            return self._error_response(f"Model inference error: {str(e)}")

    def interpret_output(self, tool_name: str, raw_output: str, target: str) -> str:
        """Interpret raw tool output and return a plain-text security assessment."""
        if not self._loaded:
            return ""

        system = (
            "You are a pentester. Summarize the tool findings below in plain English.\n"
            "Write ONLY:\n\n"
            "FINDINGS\n"
            "• <finding 1>\n"
            "• <finding 2>\n\n"
            "RISK\n"
            "• <risk 1>\n\n"
            "Max 5 bullets per section. Max 12 words per bullet. No raw tokens, hashes, or header values. "
            "No repetition. Stop after RISK section."
        )
        filtered_lines = []
        for line in raw_output.splitlines():
            stripped = line.strip()
            if not stripped:
                continue
            if stripped.startswith("- STATUS:") or stripped.startswith("- Running"):
                continue
            if len(stripped) > 200:
                continue
            non_alnum = sum(1 for c in stripped if not c.isalnum() and c not in " .:/-_,()")
            if len(stripped) > 60 and non_alnum / len(stripped) > 0.35:
                continue
            filtered_lines.append(stripped)

        filtered_output = "\n".join(filtered_lines[:_INTERPRET_MAX_LINES])

        user_msg = (
            f"tool={tool_name} target={target}\n"
            f"---OUTPUT---\n{filtered_output}\n---END---"
        )

        try:
            return self._chat(
                messages=[
                    {"role": "system", "content": system},
                    {"role": "user",   "content": user_msg},
                ],
                temperature=0.1,
                max_tokens=_INTERPRET_MAX_TOKENS,
                json_mode=False,
            ).strip()
        except Exception as e:
            logger.error(f"interpret_output failed: {e}")
            return ""

    def analyze_code(self, code: str, language: str = "unknown", filename: Optional[str] = None) -> Dict[str, Any]:
        if not self._loaded:
            return {"vulnerabilities": [], "summary": "AlphaLLM not loaded"}

        if len(code) > _CODE_TRUNCATE_LIMIT:
            logger.warning(
                f"analyze_code: code truncated from {len(code)} to {_CODE_TRUNCATE_LIMIT} chars "
                f"(file={filename or 'unknown'}) — results may be partial"
            )

        system = """You are a security code reviewer. Analyze the provided code for security vulnerabilities.
Return your response as valid JSON:
{
  "vulnerabilities": [
    {"type": "vuln_type", "severity": "critical|high|medium|low", "line": <int or null>, "code_snippet": "<the vulnerable line>", "issue": "<description>", "fix": "<suggested fix>"}
  ],
  "summary": "<one-line summary>"
}"""

        user_msg = f"Language: {language}\n"
        if filename:
            user_msg += f"File: {filename}\n"
        user_msg += f"\nCode:\n```\n{code[:_CODE_TRUNCATE_LIMIT]}\n```\n\nFind all security vulnerabilities."

        try:
            raw_text = self._chat(
                messages=[
                    {"role": "system", "content": system},
                    {"role": "user", "content": user_msg},
                ],
                temperature=0.1,
                max_tokens=1024,
            )

            text = self._extract_json(raw_text.strip())
            parsed = json.loads(text)
            return {
                "vulnerabilities": parsed.get("vulnerabilities", []),
                "summary": parsed.get("summary", ""),
            }

        except Exception as e:
            logger.error(f"Code analysis failed: {e}")
            return {"vulnerabilities": [], "summary": f"Analysis error: {str(e)}"}

    def shutdown(self):
        if self._server_proc and self._server_proc.poll() is None:
            logger.info("Shutting down AlphaLLM server")
            self._server_proc.terminate()
            try:
                self._server_proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self._server_proc.kill()


# Thread-safe singleton
_baron_instance: Optional[BaronLLM] = None
_baron_lock = threading.Lock()


def get_baron(settings: Settings) -> BaronLLM:
    global _baron_instance
    if _baron_instance is None:
        with _baron_lock:
            if _baron_instance is None:
                _baron_instance = BaronLLM(settings)
    return _baron_instance
