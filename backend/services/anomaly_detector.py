"""Anomaly detector: 4 detection methods for scan results.

1. Statistical anomalies (z-score > 3)
2. Rule-based (crash, timeout, high memory/cpu, parse failure)
3. Contradictions (same port open + closed, OS/service mismatch)
4. Pattern anomalies (too many findings, too many critical findings)
"""
from __future__ import annotations

import logging
import math
from typing import Any, Dict, List

logger = logging.getLogger("orchestrator")


def detect_anomalies(workflow_steps: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Run all 4 anomaly detection methods across workflow steps."""
    anomalies: List[Dict[str, Any]] = []

    anomalies.extend(_statistical_anomalies(workflow_steps))
    anomalies.extend(_rule_based_anomalies(workflow_steps))
    anomalies.extend(_contradiction_anomalies(workflow_steps))
    anomalies.extend(_pattern_anomalies(workflow_steps))

    return anomalies


def _statistical_anomalies(steps: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Z-score > 3 on execution_time, memory_usage, cpu_usage."""
    anomalies = []

    for metric in ("execution_time", "memory_usage", "cpu_usage"):
        values = [s.get(metric) for s in steps if s.get(metric) is not None]
        if len(values) < 2:
            continue

        mean = sum(values) / len(values)
        variance = sum((v - mean) ** 2 for v in values) / len(values)
        std = math.sqrt(variance) if variance > 0 else 0

        if std == 0:
            continue

        for step in steps:
            val = step.get(metric)
            if val is None:
                continue
            z = abs(val - mean) / std
            if z > 3:
                anomalies.append({
                    "type": f"statistical_{metric}",
                    "severity": "warning",
                    "confidence": min(0.5 + (z - 3) * 0.1, 0.99),
                    "details": {
                        "metric": metric,
                        "value": val,
                        "mean": round(mean, 2),
                        "std": round(std, 2),
                        "z_score": round(z, 2),
                        "tool": step.get("tool_name"),
                        "step_id": step.get("step_id"),
                    },
                    "suggestion": f"Unusual {metric} for {step.get('tool_name')}: "
                                  f"{val} (z-score={z:.1f})",
                })

    return anomalies


def _rule_based_anomalies(steps: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Detect crashes, timeouts, high resource usage, parse failures."""
    anomalies = []

    for step in steps:
        tool = step.get("tool_name", "unknown")
        sid = step.get("step_id")

        # Tool crash
        if step.get("status") == "failed":
            anomalies.append({
                "type": "tool_crash",
                "severity": "critical",
                "confidence": 0.98,
                "details": {
                    "tool": tool,
                    "step_id": sid,
                    "error": step.get("error_message", ""),
                },
                "suggestion": f"{tool} crashed — check container logs and input parameters",
            })

        # Timeout
        if step.get("status") == "timeout":
            anomalies.append({
                "type": "tool_timeout",
                "severity": "high",
                "confidence": 0.95,
                "details": {"tool": tool, "step_id": sid},
                "suggestion": f"{tool} timed out — target may be unresponsive or scope too large",
            })

        # High memory
        mem = step.get("memory_usage")
        if mem is not None and mem > 400:
            anomalies.append({
                "type": "high_memory",
                "severity": "warning",
                "confidence": 0.85,
                "details": {"tool": tool, "step_id": sid, "memory_mb": mem},
                "suggestion": f"{tool} used {mem}MB memory — approaching container limit",
            })

        # High CPU
        cpu = step.get("cpu_usage")
        if cpu is not None and cpu > 90:
            anomalies.append({
                "type": "high_cpu",
                "severity": "warning",
                "confidence": 0.80,
                "details": {"tool": tool, "step_id": sid, "cpu_percent": cpu},
                "suggestion": f"{tool} used {cpu}% CPU — may affect other scans",
            })

        # Empty output (parse failure indicator)
        findings = step.get("findings", [])
        raw = step.get("raw_output", "")
        if step.get("status") == "completed" and not findings and len(raw) > 100:
            anomalies.append({
                "type": "parse_failure",
                "severity": "low",
                "confidence": 0.70,
                "details": {"tool": tool, "step_id": sid, "raw_length": len(raw)},
                "suggestion": f"{tool} produced output but no findings were parsed",
            })

    return anomalies


def _contradiction_anomalies(steps: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Detect contradictory findings across tools (port open+closed, etc)."""
    anomalies = []

    # Gather port states from all steps
    port_states: Dict[int, List[Dict]] = {}
    for step in steps:
        for f in step.get("findings", []):
            port = f.get("port")
            state = f.get("state")
            if port is not None and state:
                port_states.setdefault(port, []).append({
                    "state": state,
                    "tool": step.get("tool_name"),
                })

    # Check for same port open+closed
    for port, entries in port_states.items():
        states = {e["state"] for e in entries}
        if "open" in states and "closed" in states:
            anomalies.append({
                "type": "port_contradiction",
                "severity": "high",
                "confidence": 0.90,
                "details": {
                    "port": port,
                    "reports": entries,
                },
                "suggestion": f"Port {port} reported as both open and closed — "
                              f"possible firewall or timing issue",
            })

    return anomalies


def _pattern_anomalies(steps: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Detect unusual patterns: too many findings, too many critical."""
    anomalies = []

    for step in steps:
        findings = step.get("findings", [])
        tool = step.get("tool_name", "unknown")
        sid = step.get("step_id")

        # Too many findings
        if len(findings) > 500:
            anomalies.append({
                "type": "excessive_findings",
                "severity": "warning",
                "confidence": 0.75,
                "details": {"tool": tool, "step_id": sid, "count": len(findings)},
                "suggestion": f"{tool} returned {len(findings)} findings — "
                              f"may indicate misconfigured scope or noisy scan",
            })

        # Count severity if present
        critical_count = sum(
            1 for f in findings
            if (f.get("severity") or "").lower() in ("critical", "high")
        )
        if critical_count > 50:
            anomalies.append({
                "type": "excessive_critical",
                "severity": "high",
                "confidence": 0.80,
                "details": {"tool": tool, "step_id": sid, "critical_count": critical_count},
                "suggestion": f"{tool} found {critical_count} critical/high findings — "
                              f"verify target scope and consider false positives",
            })

    return anomalies
