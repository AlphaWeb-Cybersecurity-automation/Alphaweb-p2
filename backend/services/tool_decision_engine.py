"""Tool decision engine: determines follow-up tools based on findings.

Implements chain rules and confidence-gated decisions.
"""
from __future__ import annotations

import logging
import re
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("orchestrator")

# Chain rules: source_tool -> list of (condition_fn, next_tool, rationale)
# condition_fn receives (tool_name, findings, raw_output) and returns bool.

ChainRule = Tuple[
    str,                                           # next tool
    str,                                           # rationale
]


def _has_open_ports(findings: List[Dict], raw_output: str) -> bool:
    """Check if nmap/masscan found open ports."""
    for f in findings:
        if f.get("state") == "open":
            return True
    return bool(re.search(r"\d+/(tcp|udp)\s+open", raw_output))


def _has_web_service(findings: List[Dict], raw_output: str) -> bool:
    """Check if findings include HTTP/HTTPS services."""
    web_keywords = {"http", "https", "apache", "nginx", "httpd", "iis", "tomcat", "lighttpd"}
    for f in findings:
        svc = (f.get("service") or "").lower()
        ver = (f.get("version") or "").lower()
        if any(kw in svc or kw in ver for kw in web_keywords):
            return True
    return bool(re.search(r"(http|https|apache|nginx|httpd)", raw_output, re.IGNORECASE))


def _has_directories(findings: List[Dict], raw_output: str) -> bool:
    """Check if gobuster/ffuf found directories or paths."""
    if findings:
        return True
    return bool(re.search(r"Status:\s*(200|301|302|403)", raw_output))


def _has_web_vulns(findings: List[Dict], raw_output: str) -> bool:
    """Check if nikto found web vulnerabilities."""
    vuln_keywords = ["vulnerability", "vuln", "injection", "xss", "sql", "osvdb", "cve"]
    for f in findings:
        detail = (f.get("detail") or "").lower()
        if any(kw in detail for kw in vuln_keywords):
            return True
    return bool(re.search(r"(OSVDB|CVE-|vulnerability|injection)", raw_output, re.IGNORECASE))


def _has_forms_or_params(findings: List[Dict], raw_output: str) -> bool:
    """Check if findings suggest injectable forms/parameters."""
    form_keywords = ["form", "parameter", "input", "login", "search", "query"]
    for f in findings:
        detail = (f.get("detail") or "").lower()
        if any(kw in detail for kw in form_keywords):
            return True
    return bool(re.search(r"(form|parameter|login|input)", raw_output, re.IGNORECASE))


def _has_auth_endpoints(findings: List[Dict], raw_output: str) -> bool:
    """Check if findings suggest authentication endpoints."""
    auth_keywords = ["login", "auth", "signin", "password", "credential", "admin"]
    for f in findings:
        detail = (f.get("detail") or "").lower()
        if any(kw in detail for kw in auth_keywords):
            return True
    return bool(re.search(r"(login|auth|signin|admin)", raw_output, re.IGNORECASE))


def _always(_findings: List[Dict], _raw: str) -> bool:
    return True


# Tool chain definitions
TOOL_CHAINS: Dict[str, List[Tuple[Any, str, str]]] = {
    "masscan": [
        (_has_open_ports, "nmap", "Masscan found open ports — running nmap for service detection"),
    ],
    "nmap": [
        (_has_web_service, "nikto", "Open web service detected — scanning for vulnerabilities"),
        (_has_open_ports, "gobuster", "Open ports found — enumerating directories"),
    ],
    "gobuster": [
        (_has_directories, "ffuf", "Directories found — fuzzing for hidden endpoints"),
        (_has_directories, "curl", "Directories found — inspecting responses"),
        (_has_directories, "gitleaks", "Directories found — scanning for exposed secrets"),
    ],
    "nikto": [
        (_has_web_vulns, "sqlmap", "Web vulnerabilities found — testing for SQL injection"),
        (_has_auth_endpoints, "hydra", "Auth endpoints found — testing credentials"),
        (_has_web_vulns, "nuclei", "Vulnerabilities found — running template-based scan"),
    ],
    "john": [
        (_always, "hashcat", "John completed — running hashcat for additional cracking"),
    ],
}


def decide_next_tools(
    tool_name: str,
    findings: List[Dict],
    raw_output: str,
    confidence: float,
    confidence_threshold: float = 0.75,
) -> List[Dict[str, Any]]:
    """Decide which follow-up tools to run based on current tool's results.

    Returns a list of dicts: [{"tool": str, "rationale": str, "parameters": {}}]
    Only returns the FIRST matching chain rule (to avoid over-branching).
    """
    if confidence < confidence_threshold:
        logger.info(f"Confidence {confidence:.2f} below threshold {confidence_threshold} — stopping chain")
        return []

    chains = TOOL_CHAINS.get(tool_name, [])
    if not chains:
        return []

    for condition_fn, next_tool, rationale in chains:
        try:
            if condition_fn(findings, raw_output):
                logger.info(f"Chain decision: {tool_name} -> {next_tool} ({rationale})")
                return [{
                    "tool": next_tool,
                    "rationale": rationale,
                    "parameters": _build_follow_up_params(tool_name, next_tool, findings, raw_output),
                }]
        except Exception as e:
            logger.warning(f"Chain condition check failed for {tool_name}->{next_tool}: {e}")

    return []


def _build_follow_up_params(
    source_tool: str,
    next_tool: str,
    findings: List[Dict],
    raw_output: str,
) -> Dict[str, Any]:
    """Build parameters for the follow-up tool based on source findings."""
    params: Dict[str, Any] = {}

    if source_tool in ("nmap", "masscan") and next_tool == "nikto":
        # Pass web ports to nikto
        web_ports = []
        for f in findings:
            if f.get("state") == "open":
                svc = (f.get("service") or "").lower()
                if any(kw in svc for kw in ("http", "https", "web")):
                    web_ports.append(f["port"])
        if web_ports:
            params["port"] = web_ports[0]

    elif source_tool == "nmap" and next_tool == "gobuster":
        web_ports = []
        for f in findings:
            if f.get("state") == "open":
                svc = (f.get("service") or "").lower()
                if "http" in svc:
                    web_ports.append(f["port"])
        if web_ports:
            params["port"] = web_ports[0]

    return params
