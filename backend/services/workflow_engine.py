"""Workflow engine: manages ordered workflow steps and persistence."""
from __future__ import annotations

import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from database import Anomaly, SessionLocal, WorkflowStep

logger = logging.getLogger("orchestrator")


class WorkflowEngine:
    """Manages workflow steps for a scan and persists them to the database."""

    def __init__(self, scan_id: str) -> None:
        self.scan_id = scan_id
        self._steps: List[Dict[str, Any]] = []
        self._step_count = 0

    def create_step(
        self,
        tool_name: str,
        confidence: float,
        parameters: Dict,
        parent_step_id: Optional[str] = None,
    ) -> str:
        """Create and persist a new workflow step. Returns step_id."""
        step_id = str(uuid.uuid4())
        self._step_count += 1

        db = SessionLocal()
        try:
            step = WorkflowStep(
                id=step_id,
                scan_id=self.scan_id,
                parent_step_id=parent_step_id,
                execution_order=self._step_count,
                tool_name=tool_name,
                confidence=confidence,
                parameters=json.dumps(parameters),
                status="running",
                created_at=datetime.now(timezone.utc),
            )
            db.add(step)
            db.commit()
        finally:
            db.close()

        self._steps.append({
            "step_id": step_id,
            "tool_name": tool_name,
            "execution_order": self._step_count,
        })

        return step_id

    def complete_step(
        self,
        step_id: str,
        findings: List[Dict],
        raw_output: str,
        execution_time: float,
        exit_code: int,
        cpu_usage: float = 0.0,
        memory_usage: float = 0.0,
        status: str = "completed",
        error_message: Optional[str] = None,
    ) -> None:
        """Mark a workflow step as completed with its results."""
        db = SessionLocal()
        try:
            step = db.query(WorkflowStep).filter(WorkflowStep.id == step_id).first()
            if step:
                step.findings = json.dumps(findings)
                step.raw_output = raw_output
                step.execution_time = execution_time
                step.exit_code = exit_code
                step.cpu_usage = cpu_usage
                step.memory_usage = memory_usage
                step.status = status
                step.error_message = error_message
                step.completed_at = datetime.now(timezone.utc)
                db.commit()
        finally:
            db.close()

    def fail_step(self, step_id: str, error_message: str) -> None:
        self.complete_step(
            step_id=step_id,
            findings=[],
            raw_output="",
            execution_time=0.0,
            exit_code=-1,
            status="failed",
            error_message=error_message,
        )

    def save_anomalies(self, anomalies: List[Dict[str, Any]], step_id: Optional[str] = None) -> None:
        """Persist detected anomalies to the database."""
        if not anomalies:
            return

        db = SessionLocal()
        try:
            for a in anomalies:
                db.add(Anomaly(
                    scan_id=self.scan_id,
                    step_id=step_id,
                    anomaly_type=a.get("type", "unknown"),
                    severity=a.get("severity", "info"),
                    confidence=a.get("confidence", 0.0),
                    details=json.dumps(a.get("details", {})),
                    suggestion=a.get("suggestion", ""),
                ))
            db.commit()
        finally:
            db.close()

    def get_workflow_summary(self) -> Dict[str, Any]:
        """Get all workflow steps and anomalies for this scan."""
        db = SessionLocal()
        try:
            steps = (
                db.query(WorkflowStep)
                .filter(WorkflowStep.scan_id == self.scan_id)
                .order_by(WorkflowStep.execution_order)
                .all()
            )
            anomalies = (
                db.query(Anomaly)
                .filter(Anomaly.scan_id == self.scan_id)
                .all()
            )

            return {
                "steps": [
                    {
                        "step_id": s.id,
                        "parent_step_id": s.parent_step_id,
                        "execution_order": s.execution_order,
                        "tool_name": s.tool_name,
                        "confidence": s.confidence,
                        "parameters": _safe_json(s.parameters),
                        "findings": _safe_json(s.findings),
                        "execution_time": s.execution_time,
                        "cpu_usage": s.cpu_usage,
                        "memory_usage": s.memory_usage,
                        "exit_code": s.exit_code,
                        "status": s.status,
                        "error_message": s.error_message,
                        "created_at": s.created_at.isoformat() + "Z" if s.created_at else None,
                        "completed_at": s.completed_at.isoformat() + "Z" if s.completed_at else None,
                    }
                    for s in steps
                ],
                "anomalies": [
                    {
                        "id": a.id,
                        "step_id": a.step_id,
                        "type": a.anomaly_type,
                        "severity": a.severity,
                        "confidence": a.confidence,
                        "details": _safe_json(a.details),
                        "suggestion": a.suggestion,
                    }
                    for a in anomalies
                ],
                "execution_depth": max((s.execution_order for s in steps), default=0),
                "total_tools_run": len(steps),
            }
        finally:
            db.close()


def _safe_json(val):
    if not val:
        return val
    if isinstance(val, str):
        try:
            return json.loads(val)
        except json.JSONDecodeError:
            return val
    return val
