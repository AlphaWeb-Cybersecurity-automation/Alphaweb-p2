from __future__ import annotations

import json
import logging
import os
import subprocess
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
}

AVAILABLE_TOOLS = list(TOOL_DESCRIPTIONS.keys())

SYSTEM_PROMPT = """You are AlphaLLM, a cybersecurity tool selection AI. Given a user's security testing request, you must select the most appropriate tool and return your response as valid JSON.

Available tools:
{tools_list}

You MUST respond with ONLY valid JSON matching this exact schema:
{{
  "tool_selected": "<tool_name or null>",
  "confidence": <float 0.0-1.0>,
  "parameters": {{}},
  "rationale": "<explanation>",
  "safety_checks_passed": <true/false>,
  "warnings": []
}}

Rules:
- Select the single best tool for the request
- Set confidence based on how well the request matches the tool
- Include relevant parameters (target, ports, flags, etc.)
- Set safety_checks_passed to false if the request seems malicious or targets internal infrastructure
- Add warnings for any concerns
- If no tool matches or the request is unsafe, set tool_selected to null and confidence below 0.7
"""

USER_PROMPT_TEMPLATE = """Target: {target}
Request: {request}

Select the best tool and parameters for this security testing request."""

# Path to llama-server.exe — in binaries/ next to project root
LLAMA_SERVER_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "binaries"))
LLAMA_SERVER_EXE = os.path.join(LLAMA_SERVER_DIR, "llama-server.exe")
LLAMA_SERVER_URL = "http://127.0.0.1:8081"


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

        # Check if server is already running
        if self._is_server_healthy():
            logger.info("AlphaLLM server already running")
            self._loaded = True
            return True

        # Start llama-server.exe
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

            # Wait for server to become healthy
            for i in range(60):  # up to 60 seconds
                time.sleep(1)
                if self._is_server_healthy():
                    self._loaded = True
                    logger.info("AlphaLLM server started and healthy")
                    return True
                # Check if process died
                if self._server_proc.poll() is not None:
                    stderr = self._server_proc.stderr.read().decode(errors="replace")
                    logger.error(f"AlphaLLM server exited: {stderr[:500]}")
                    return False

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
        """Send chat completion request to llama-server."""
        payload_dict: Dict[str, Any] = {
            "messages": messages,
            "temperature": temperature,
            "n_predict": max_tokens,
        }
        if json_mode:
            payload_dict["response_format"] = {"type": "json_object"}
        payload = json.dumps(payload_dict).encode()

        req = urllib.request.Request(
            f"{LLAMA_SERVER_URL}/v1/chat/completions",
            data=payload,
            headers={"Content-Type": "application/json"},
        )

        with urllib.request.urlopen(req, timeout=120) as resp:
            data = json.loads(resp.read())
            return data["choices"][0]["message"]["content"]

    @property
    def is_loaded(self) -> bool:
        return self._loaded

    def _build_tools_list(self) -> str:
        lines = []
        for name, desc in TOOL_DESCRIPTIONS.items():
            lines.append(f"- {name}: {desc}")
        return "\n".join(lines)

    def _parse_response(self, raw_text: str) -> Dict[str, Any]:
        text = raw_text.strip()
        start = text.find("{")
        end = text.rfind("}") + 1
        if start >= 0 and end > start:
            text = text[start:end]

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

        tools_list = self._build_tools_list()
        system = SYSTEM_PROMPT.format(tools_list=tools_list)
        user_msg = USER_PROMPT_TEMPLATE.format(target=target, request=user_request)

        try:
            raw_text = self._chat(
                messages=[
                    {"role": "system", "content": system},
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
            "You are AlphaLLM, a cybersecurity analyst. "
            "Analyze tool output and respond ONLY in this exact two-section structure — no extra text before or after:\n\n"
            "FINDINGS\n"
            "• <one bullet per discovery — include port, protocol, service name, version if present, and state>\n"
            "• <host status, latency, OS hints, or banner info if available>\n\n"
            "RISK\n"
            "• <one bullet per security concern — be specific: service name + reason it matters>\n\n"
            "Rules: bullets only, no intro sentence, no recommendations, no 'Next Steps', technical precision."
        )
        user_msg = (
            f"Tool: {tool_name}  |  Target: {target}\n\n"
            f"{raw_output[:3000]}"
        )

        try:
            return self._chat(
                messages=[
                    {"role": "system", "content": system},
                    {"role": "user",   "content": user_msg},
                ],
                temperature=0.15,
                max_tokens=350,
                json_mode=False,
            ).strip()
        except Exception as e:
            logger.error(f"interpret_output failed: {e}")
            return ""

    def analyze_code(self, code: str, language: str = "unknown", filename: Optional[str] = None) -> Dict[str, Any]:
        if not self._loaded:
            return {"vulnerabilities": [], "summary": "AlphaLLM not loaded"}

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
        user_msg += f"\nCode:\n```\n{code[:4000]}\n```\n\nFind all security vulnerabilities."

        try:
            raw_text = self._chat(
                messages=[
                    {"role": "system", "content": system},
                    {"role": "user", "content": user_msg},
                ],
                temperature=0.1,
                max_tokens=1024,
            )

            text = raw_text.strip()
            start = text.find("{")
            end = text.rfind("}") + 1
            if start >= 0 and end > start:
                text = text[start:end]

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


# Singleton instance
_baron_instance: Optional[BaronLLM] = None


def get_baron(settings: Settings) -> BaronLLM:
    global _baron_instance
    if _baron_instance is None:
        _baron_instance = BaronLLM(settings)
    return _baron_instance
