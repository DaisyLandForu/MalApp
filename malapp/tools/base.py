"""Deterministic tool protocol contracts."""

from __future__ import annotations

import copy
import hashlib
import json
from collections.abc import Callable
from dataclasses import asdict, dataclass, field
from typing import Any, Protocol


def digest_value(value: Any) -> str:
    payload = json.dumps(value, ensure_ascii=False, sort_keys=True, default=str)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]


def clone_facts(value: Any) -> Any:
    return copy.deepcopy(value)


def snapshot_fields(sample: dict[str, Any], keys: frozenset[str] | tuple[str, ...]) -> dict[str, Any]:
    observed: dict[str, Any] = {}
    for key in keys:
        if key in sample and sample[key] not in ("", None, [], {}, ()):
            observed[key] = copy.deepcopy(sample[key])
    return observed


def merge_observed_fields(facts: dict[str, dict[str, Any]]) -> dict[str, Any]:
    merged: dict[str, Any] = {}
    for payload in facts.values():
        if not isinstance(payload, dict):
            continue
        fields = payload.get("observed_fields")
        if isinstance(fields, dict):
            merged.update(clone_facts(fields))
    return merged


def merge_observed_iocs(facts: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    merged: list[dict[str, Any]] = []
    for payload in facts.values():
        if not isinstance(payload, dict):
            continue
        for item in payload.get("observed_iocs") or []:
            if isinstance(item, dict) and item not in merged:
                merged.append(clone_facts(item))
    return merged


@dataclass(frozen=True)
class ToolSpec:
    name: str
    agent: str
    description: str = ""


def validate_tool_arguments(tool_name: str, agent: str, arguments: Any) -> tuple[bool, list[str]]:
    """Validate the ToolCall argument object. Denial/timeout is a separate status."""
    errors: list[str] = []
    if not str(tool_name or "").strip():
        errors.append("missing_tool_name")
    if not str(agent or "").strip():
        errors.append("missing_agent")
    if not isinstance(arguments, dict):
        errors.append("arguments_not_object")
        return False, errors
    if not isinstance(arguments.get("sample"), dict):
        errors.append("sample_not_object")
    if "iocs" not in arguments:
        errors.append("missing_iocs")
    elif not isinstance(arguments.get("iocs"), list):
        errors.append("iocs_not_list")
    return not errors, errors


@dataclass
class ToolCall:
    tool_name: str
    agent: str
    arguments: dict[str, Any] = field(default_factory=dict)


TOOL_PHASE_BY_STATUS = {
    "completed": "tool_call_finished",
    "failed": "tool_call_failed",
    "timeout": "tool_call_timeout",
    "denied": "tool_call_denied",
}


@dataclass
class ToolObservation:
    tool_name: str
    agent: str
    status: str
    input_digest: str
    output_digest: str
    latency_ms: float
    facts: dict[str, Any] = field(default_factory=dict)
    error_type: str = ""
    error: str = ""
    plan_id: str = ""
    run_id: str = ""
    phase: str = ""
    arguments_valid: bool = True
    argument_errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["facts"] = clone_facts(self.facts)
        payload["phase"] = self.phase or TOOL_PHASE_BY_STATUS.get(self.status, self.status)
        return payload


@dataclass
class ToolExecutionResult:
    observations: list[ToolObservation] = field(default_factory=list)
    denied: list[str] = field(default_factory=list)
    facts: dict[str, Any] = field(default_factory=dict)
    events: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "observations": [item.to_dict() for item in self.observations],
            "denied": list(self.denied),
            "facts": {name: clone_facts(value) for name, value in self.facts.items()},
            "events": [dict(item) for item in self.events],
        }


class Tool(Protocol):
    spec: ToolSpec

    def run(self, sample: dict[str, Any], *, iocs: list[dict[str, Any]] | None = None) -> dict[str, Any]:
        ...


ToolFn = Callable[[dict[str, Any]], dict[str, Any]]
