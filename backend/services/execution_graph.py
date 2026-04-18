"""Execution graph: tracks tool execution history within a workflow.

Prevents loops/duplicates and maintains parent→child relationships.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple


@dataclass
class GraphNode:
    step_id: str
    tool_name: str
    parameters: Dict
    parent_id: Optional[str] = None
    depth: int = 0
    children: List[str] = field(default_factory=list)


class ExecutionGraph:
    """DAG of tool executions for a single scan workflow."""

    def __init__(self, max_depth: int = 4, max_tools: int = 6) -> None:
        self._nodes: Dict[str, GraphNode] = {}
        self._execution_order: List[str] = []
        self._tool_param_set: Set[Tuple[str, str]] = set()
        self.max_depth = max_depth
        self.max_tools = max_tools

    @property
    def total_tools_run(self) -> int:
        return len(self._execution_order)

    @property
    def current_depth(self) -> int:
        if not self._execution_order:
            return 0
        last = self._nodes[self._execution_order[-1]]
        return last.depth

    def can_add(self, tool_name: str, parameters: Dict, parent_id: Optional[str] = None) -> Tuple[bool, str]:
        """Check whether a new tool execution is allowed."""
        if self.total_tools_run >= self.max_tools:
            return False, f"Maximum tool count ({self.max_tools}) reached"

        depth = 0
        if parent_id and parent_id in self._nodes:
            depth = self._nodes[parent_id].depth + 1

        if depth >= self.max_depth:
            return False, f"Maximum depth ({self.max_depth}) reached"

        # Prevent duplicate tool+params
        param_key = _param_key(tool_name, parameters)
        if param_key in self._tool_param_set:
            return False, f"Duplicate execution: {tool_name} with same parameters"

        return True, ""

    def add_node(
        self,
        step_id: str,
        tool_name: str,
        parameters: Dict,
        parent_id: Optional[str] = None,
    ) -> GraphNode:
        depth = 0
        if parent_id and parent_id in self._nodes:
            depth = self._nodes[parent_id].depth + 1
            self._nodes[parent_id].children.append(step_id)

        node = GraphNode(
            step_id=step_id,
            tool_name=tool_name,
            parameters=parameters,
            parent_id=parent_id,
            depth=depth,
        )
        self._nodes[step_id] = node
        self._execution_order.append(step_id)
        self._tool_param_set.add(_param_key(tool_name, parameters))
        return node

    def get_node(self, step_id: str) -> Optional[GraphNode]:
        return self._nodes.get(step_id)

    def get_execution_order(self) -> List[str]:
        return list(self._execution_order)

    def get_all_nodes(self) -> List[GraphNode]:
        return [self._nodes[sid] for sid in self._execution_order]


def _param_key(tool_name: str, parameters: Dict) -> Tuple[str, str]:
    import json
    return (tool_name, json.dumps(parameters, sort_keys=True))
