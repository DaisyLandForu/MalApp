"""Deterministic tool protocol contracts."""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from typing import Any, Callable, Protocol


def digest_value(value: Any) -> str:
    payload = json.dumps(value, ensure_ascii=False, sort_keys=True, default=str)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]


@dataclass(frozen=True)
class ToolSpec:
    name: str
    agent: str
    description: str = ""


@dataclass
class ToolCall:
    tool_name: str
    agent: str
    arguments: dict[str, Any] = field(default_factory=dict)


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

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ToolExecutionResult:
    observations: list[ToolObservation] = field(default_factory=list)
    denied: list[str] = field(default_factory=list)
    facts: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "observations": [item.to_dict() for item in self.observations],
            "denied": list(self.denied),
            "facts": dict(self.facts),
        }


class Tool(Protocol):
    spec: ToolSpec

    def run(self, sample: dict[str, Any], *, iocs: list[dict[str, Any]] | None = None) -> dict[str, Any]:
        ...


ToolFn = Callable[[dict[str, Any]], dict[str, Any]]
