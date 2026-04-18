"""Shannon-inspired orchestrator: multi-step tool chaining.

Flow:
  User Request → BaronLLM picks first tool → run tool_runner
  → tool_decision_engine selects next tool → repeat
  → anomaly_detector runs after workflow
  → DB stores workflow + anomalies
"""
from __future__ import annotations

import json
import logging
import re
from typing import Any, Dict, List, Optional

from config import Settings
from tool_runner import ToolRunResult, run_tool

from services.anomaly_detector import detect_anomalies
from services.execution_graph import ExecutionGraph
from services.tool_decision_engine import decide_next_tools
from services.workflow_engine import WorkflowEngine

logger = logging.getLogger("orchestrator")


class ShannonOrchestrator:
    """Orchestrates multi-step tool execution for a scan."""

    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    async def run_workflow(
        self,
        scan_id: str,
        target: str,
        initial_tool: str,
        initial_params: Dict[str, Any],
        initial_confidence: float,
    ) -> Dict[str, Any]:
        """Execute the full orchestration workflow.

        Returns a summary dict with all findings, workflow steps, and anomalies.
        """
        graph = ExecutionGraph(
            max_depth=self.settings.WORKFLOW_MAX_DEPTH,
            max_tools=self.settings.WORKFLOW_MAX_TOOLS,
        )
        workflow = WorkflowEngine(scan_id)

        all_findings: List[Dict] = []
        all_raw_outputs: List[str] = []

        # Execute the chain starting with the initial tool
        await self._execute_chain(
            graph=graph,
            workflow=workflow,
            target=target,
            tool_name=initial_tool,
            parameters=initial_params,
            confidence=initial_confidence,
            parent_step_id=None,
            all_findings=all_findings,
            all_raw_outputs=all_raw_outputs,
        )

        # Run anomaly detection across all steps
        summary = workflow.get_workflow_summary()
        anomalies = detect_anomalies(summary["steps"])
        workflow.save_anomalies(anomalies)

        # Refresh summary to include anomalies
        summary = workflow.get_workflow_summary()
        summary["all_findings"] = all_findings

        return summary

    async def _execute_chain(
        self,
        graph: ExecutionGraph,
        workflow: WorkflowEngine,
        target: str,
        tool_name: str,
        parameters: Dict[str, Any],
        confidence: float,
        parent_step_id: Optional[str],
        all_findings: List[Dict],
        all_raw_outputs: List[str],
    ) -> None:
        """Recursively execute tools following chain decisions."""
        # Check if we can add this tool
        can_add, reason = graph.can_add(tool_name, parameters, parent_step_id)
        if not can_add:
            logger.info(f"Chain stopped: {reason}")
            return

        # Create workflow step
        step_id = workflow.create_step(
            tool_name=tool_name,
            confidence=confidence,
            parameters=parameters,
            parent_step_id=parent_step_id,
        )

        # Register in execution graph
        graph.add_node(
            step_id=step_id,
            tool_name=tool_name,
            parameters=parameters,
            parent_id=parent_step_id,
        )

        logger.info(
            f"[Workflow {workflow.scan_id}] Step {graph.total_tools_run}: "
            f"{tool_name} (confidence={confidence:.2f})"
        )

        # Build args string from parameters
        args_str = _params_to_args(tool_name, parameters)

        # Execute the tool
        try:
            result: ToolRunResult = await run_tool(
                tool_name=tool_name,
                args=args_str,
                target=target,
                settings=self.settings,
            )

            # Parse findings
            findings = parse_findings(tool_name, result.raw_output)

            workflow.complete_step(
                step_id=step_id,
                findings=findings,
                raw_output=result.raw_output,
                execution_time=result.execution_time,
                exit_code=result.exit_code,
                cpu_usage=result.cpu_usage,
                memory_usage=result.memory_usage,
                status=result.status,
                error_message=result.errors[0] if result.errors else None,
            )

            all_findings.extend(findings)
            all_raw_outputs.append(result.raw_output)

            if not result.success:
                logger.warning(f"Tool {tool_name} failed: {result.errors}")
                return

        except Exception as e:
            logger.exception(f"Tool execution failed: {tool_name}")
            workflow.fail_step(step_id, str(e))
            return

        # Decide follow-up tools
        next_tools = decide_next_tools(
            tool_name=tool_name,
            findings=findings,
            raw_output=result.raw_output,
            confidence=confidence,
            confidence_threshold=self.settings.ORCHESTRATION_CONFIDENCE_THRESHOLD,
        )

        for next_tool_info in next_tools:
            await self._execute_chain(
                graph=graph,
                workflow=workflow,
                target=target,
                tool_name=next_tool_info["tool"],
                parameters=next_tool_info.get("parameters", {}),
                confidence=confidence * 0.95,  # slight decay per chain depth
                parent_step_id=step_id,
                all_findings=all_findings,
                all_raw_outputs=all_raw_outputs,
            )

    async def run_single_tool(
        self,
        scan_id: str,
        target: str,
        tool_name: str,
        params: Dict[str, Any],
        confidence: float,
    ) -> Dict[str, Any]:
        """Fallback: run a single tool without chaining (Phase 1 behavior)."""
        workflow = WorkflowEngine(scan_id)
        step_id = workflow.create_step(
            tool_name=tool_name,
            confidence=confidence,
            parameters=params,
        )

        args_str = _params_to_args(tool_name, params)

        try:
            result = await run_tool(
                tool_name=tool_name,
                args=args_str,
                target=target,
                settings=self.settings,
            )

            findings = parse_findings(tool_name, result.raw_output)
            workflow.complete_step(
                step_id=step_id,
                findings=findings,
                raw_output=result.raw_output,
                execution_time=result.execution_time,
                exit_code=result.exit_code,
                status=result.status,
                error_message=result.errors[0] if result.errors else None,
            )

            return {
                "findings": findings,
                "raw_output": result.raw_output,
                "execution_time": result.execution_time,
                "exit_code": result.exit_code,
                "status": result.status,
            }

        except Exception as e:
            workflow.fail_step(step_id, str(e))
            raise


def _params_to_args(tool_name: str, parameters: Dict[str, Any]) -> str:
    """Convert parameter dict to CLI args string."""
    parts = []

    if tool_name == "nmap":
        # Use fast scan (-F) by default to avoid timeouts on full 65k port scans
        if not parameters.get("ports"):
            parts.append("-F")
        # Service version detection
        parts.append("-sV")

    if parameters.get("ports"):
        parts.append(f"-p {parameters['ports']}")
    if parameters.get("port") and tool_name in ("nikto",):
        parts.append(f"-p {parameters['port']}")
    return " ".join(parts)


def parse_findings(tool_name: str, raw_output: str) -> List[Dict[str, Any]]:
    """Parse tool-specific output into structured findings."""
    if tool_name == "nmap":
        return _parse_nmap(raw_output)
    elif tool_name == "masscan":
        return _parse_masscan(raw_output)
    elif tool_name in ("nikto", "nuclei"):
        return _parse_line_findings(raw_output)
    elif tool_name in ("gobuster", "ffuf"):
        return _parse_directory_findings(raw_output)
    elif tool_name == "sqlmap":
        return _parse_line_findings(raw_output)
    elif tool_name == "gitleaks":
        return _parse_gitleaks(raw_output)
    else:
        return _parse_generic(raw_output)


def _parse_nmap(raw: str) -> List[Dict]:
    findings = []
    for line in raw.splitlines():
        match = re.match(
            r"(\d+)/(tcp|udp)\s+(open|closed|filtered)\s+(\S+)\s*(.*)", line
        )
        if match:
            findings.append({
                "port": int(match.group(1)),
                "protocol": match.group(2),
                "state": match.group(3),
                "service": match.group(4),
                "version": match.group(5).strip() or None,
            })
    return findings


def _parse_masscan(raw: str) -> List[Dict]:
    findings = []
    for line in raw.splitlines():
        match = re.match(r"Discovered open port (\d+)/(tcp|udp) on (.+)", line)
        if match:
            findings.append({
                "port": int(match.group(1)),
                "protocol": match.group(2),
                "state": "open",
                "host": match.group(3).strip(),
            })
    return findings


def _parse_directory_findings(raw: str) -> List[Dict]:
    findings = []
    for line in raw.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        # gobuster/ffuf output: /path (Status: 200) [Size: 1234]
        match = re.match(r"(/\S+)\s+.*Status:\s*(\d+)", line)
        if match:
            findings.append({
                "path": match.group(1),
                "status_code": int(match.group(2)),
                "detail": line,
            })
        elif line.startswith("/"):
            findings.append({"path": line.split()[0], "detail": line})
    return findings


def _parse_gitleaks(raw: str) -> List[Dict]:
    findings = []
    try:
        data = json.loads(raw)
        if isinstance(data, list):
            for item in data:
                findings.append({
                    "type": "secret",
                    "rule": item.get("RuleID", ""),
                    "file": item.get("File", ""),
                    "line": item.get("StartLine", 0),
                    "detail": item.get("Match", ""),
                })
    except (json.JSONDecodeError, TypeError):
        return _parse_generic(raw)
    return findings


def _parse_line_findings(raw: str) -> List[Dict]:
    findings = []
    for line in raw.splitlines():
        line = line.strip()
        if line and not line.startswith("#") and not line.startswith("-"):
            findings.append({"detail": line})
    return findings


def _parse_generic(raw: str) -> List[Dict]:
    findings = []
    for line in raw.splitlines():
        line = line.strip()
        if line and not line.startswith("#") and not line.startswith("-"):
            findings.append({"detail": line})
    return findings
